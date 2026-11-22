# Apache Reqsign Koofr

Koofr credential exchange and request signing for
[Apache Reqsign](https://github.com/apache/reqsign).

The crate exchanges an account email and an application-specific password for a
Koofr access token, then adds the sensitive
`Authorization: Token token=<token>` header. It does not select mounts, build
file paths, or send business requests.

## Endpoint and token exchange

The official Koofr API endpoint is `https://app.koofr.net`, the endpoint used
by Koofr's first-party SDKs. The `/token` JSON exchange follows the first-party
Go SDK; OpenDAL's Koofr backend uses the same exchange. Koofr's API Swagger
documents Bearer and app-password Basic schemes separately; it does not describe
this exchange.

`LoginCredentialProvider` posts JSON to `{endpoint}/token`:

```json
{"email":"me@example.com","password":"application-specific-password"}
```

A successful response is `{"token":"..."}`. Use an application-specific
password generated at
<https://app.koofr.net/app/admin/preferences/password>, not the account login
password.

Call `with_endpoint` for Koofr-compatible APIs. The endpoint must be an
absolute HTTP(S) URI with a host, optional port, and optional path prefix.
Userinfo, query strings, fragments, dot segments, backslashes, whitespace, and
control characters are rejected. An explicit `http://` endpoint sends the email
and application password in cleartext. Reqsign sends the exchange to the
configured destination; redirect policy belongs to the configured `HttpSend`
adapter.

The exchange does not return an expiry. The token stays cached until the caller
replaces the `Signer` or installs a provider/context that starts a new cache.
Koofr rejecting the token does not invalidate the cache automatically; the
caller must replace the signer or its credential cache.

## No ambient discovery

Koofr's first-party SDK repositories use `KOOFR_*` variables only in their own
test suites. They do not define a production environment-variable credential
convention, so this crate does not read ambient credentials. Configure
`LoginCredentialProvider` or `StaticCredentialProvider` explicitly.

## Example

```rust,no_run
use reqsign_core::{Context, Signer};
use reqsign_koofr::{LoginCredentialProvider, RequestSigner};

# async fn example() -> reqsign_core::Result<()> {
let ctx = Context::new(); // configure HttpSend and any other components
let signer = Signer::new(
    ctx,
    LoginCredentialProvider::new("me@example.com", "application-password"),
    RequestSigner,
);

let mut request = http::Request::get(
    "https://app.koofr.net/api/v2/mounts/primary/files/list?path=%2F",
)
.body(())
.unwrap()
.into_parts()
.0;

signer.sign(&mut request, None).await?;
# Ok(())
# }
```

## License

Apache-2.0
