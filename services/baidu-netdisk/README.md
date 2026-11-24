# reqsign-baidu-netdisk

Baidu Netdisk Open Platform access-token credentials and request signing for
Reqsign.

Baidu Netdisk's xpan APIs authenticate requests with an `access_token` query
parameter. This crate holds the token, supplies it through a static provider,
and signs request heads by appending the form-encoded query parameter.

## Usage

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_baidu_netdisk::{RequestSigner, StaticCredentialProvider};

# async fn example() -> Result<()> {
let signer = Signer::new(
    Context::new(),
    StaticCredentialProvider::new("baidu-netdisk-access-token"),
    RequestSigner,
);

let mut req = http::Request::get(
    "https://pan.baidu.com/rest/2.0/xpan/file?method=list&dir=%2Fapps%2FMyApp",
)
.body(())
.unwrap()
.into_parts()
.0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

The resulting request URI contains
`...&access_token=<form-encoded-token>`. The token is a secret; treat signed
URLs and any logs that include the URI as secret-bearing material.

## Credentials

`StaticCredentialProvider` accepts a token that the caller already obtained
through Baidu's Open Platform authorization flow. This crate does not read an
environment variable, a well-known credential file, or an OAuth token endpoint.
It also does not implement OAuth refresh, single-use refresh-token rotation, or
token persistence; those stay with the caller.

An empty token is rejected before it enters the signer's credential cache. The
token has no tracked expiry in this crate, so it is reused for the lifetime of
the `Signer`. Replace the credential provider or create a new signer to use a
different token.

## Request ownership

The caller owns the API host, method, path, other query parameters, headers
(including `User-Agent`), and body. Signing removes any existing `access_token`
query parameter and appends one encoded parameter. Existing percent escapes,
parameter order, duplicate keys, empty values, empty segments, literal `+`
characters, and all headers are preserved. This makes re-signing safe without
leaving stale authentication parameters.

Query authentication has no separate presign lifetime here, so signing rejects
`expires_in`. Do not forward a signed request to an unrelated host.

`Debug` output for credentials and the static provider never contains the
token. On `wasm32-unknown-unknown`, static credentials and query signing need no
JavaScript clock.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
