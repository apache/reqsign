# reqsign-seafile

Seafile token authentication and request signing for Reqsign.

The crate loads an account or repository API token, either from an explicit
value or by exchanging a username and password with a configured Seafile
server, and signs API requests with Seafile's token header.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Result, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_seafile::{DefaultCredentialProvider, RequestSigner};

# async fn main() -> Result<()> {
let context = Context::new()
    .with_file_read(TokioFileRead)
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);

let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner,
);

let mut request = http::Request::get("https://files.example.com/api2/repos/")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut request, None).await?;
# Ok(())
# }
```

The default provider reads the `token` value from the `[account]` section of
`~/.seafile.conf`, the user configuration file read by Seafile's first-party
`seaf-cli`. Seafile does not document a standard credential environment
variable or login command, so the default chain does not invent one. Use
`StaticCredentialProvider` when a token is managed explicitly, or
`AccountTokenCredentialProvider` to perform the account exchange with supplied
credentials.

## Account Token Exchange

`AccountTokenCredentialProvider` posts form-encoded `username` and `password`
fields to `{server}/api2/auth-token/` and reads the `token` field from the
JSON response. The current OpenAPI document describes a JSON request body, but
Seafile's server-side example, `seaf-cli`, and the Python SDK post form fields;
this crate follows those executable clients. The server value may include the
base path of a self-hosted reverse proxy:

```rust,no_run
use reqsign_core::{Context, Signer};
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_seafile::{AccountTokenCredentialProvider, RequestSigner};

let context = Context::new().with_http_send(ReqwestHttpSend::default());
let signer = Signer::new(
    context,
    AccountTokenCredentialProvider::new(
        "https://files.example.com/seafile",
        "user@example.com",
        "password",
    ),
    RequestSigner,
);
```

The username and password are sent only to the configured server. Use HTTPS in
production. An explicit `http://` server is accepted because self-hosted Seafile
deployments may run over HTTP on a private network, but it sends the login
secret in cleartext. Two-factor authentication is not part of this exchange;
obtain a token separately and use `StaticCredentialProvider` when the server
requires it.

## Request Signing

`RequestSigner` inserts a sensitive `Authorization: Token <token>` header and
leaves the URI and all other headers unchanged. Seafile 11 and newer also accept
`Bearer`, but `Token` works with older self-hosted servers and matches existing
OpenDAL behavior. Seafile has no query authentication, so `expires_in` is
rejected.

Seafile account and repository API tokens have no documented expiration. The
credential carries no expiration, and `Signer` caches it until the signer is
recreated or its credential provider is replaced. Recreate the signer after the
token is revoked or rotated. The signer does not restrict the request host, so
do not forward a signed `Authorization` header to a different server.

## Scope

Repository id discovery, repository-scoped upload and download links, and all
business request construction stay with the caller. This crate authenticates
the request; it does not list repositories or call Seafile's storage APIs.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
