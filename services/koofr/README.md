# Apache Reqsign Koofr

Koofr credential exchange and request signing for
[Apache Reqsign](https://github.com/apache/reqsign).

The crate exchanges an account email and an application-specific password for a
Koofr access token, then adds the sensitive
`Authorization: Token token=<token>` header. It does not select mounts, build
file paths, or send business requests.

## Endpoint and token exchange

The official Koofr API endpoint is `https://app.koofr.net`, the endpoint used
by Koofr's first-party SDKs. `LoginCredentialProvider` posts JSON to
`{endpoint}/token`:

```json
{"email":"me@example.com","password":"application-specific-password"}
```

A successful response is `{"token":"..."}`. Use an application-specific
password generated at
<https://app.koofr.net/app/admin/preferences/password>, not the account login
password. Call `with_endpoint` for Koofr-compatible APIs.

The documented exchange does not return an expiry. Reqsign caches the token
until the provider is replaced or Koofr rejects it.

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
