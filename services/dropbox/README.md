# reqsign-dropbox

Dropbox authentication and request signing for Reqsign.

The default credential provider reads the access token documented by the
official [`dbxcli`](https://github.com/dropbox/dbxcli) tool from
`DBXCLI_ACCESS_TOKEN` through `Context`. Reqsign does not parse `dbxcli`
account or team configuration files. Explicit access tokens and OAuth 2.0
refresh-token credentials are available through `StaticCredentialProvider` and
`RefreshCredentialProvider`.

`RequestSigner` adds only a sensitive `Authorization: Bearer` header. Dropbox
does not support query authentication, so signing rejects `expires_in` and never
changes the URI or other headers.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_dropbox::{DefaultCredentialProvider, RequestSigner};

# async fn example() -> reqsign_core::Result<()> {
let context = Context::new().with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner,
);

let mut req = http::Request::get("https://api.dropboxapi.com/2/users/get_current_account")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

For long-lived access, construct an explicit refresh provider:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_dropbox::{RefreshCredentialProvider, RequestSigner};

# fn example(context: Context) -> Result<()> {
let provider = RefreshCredentialProvider::new(
    "client-id",
    "client-secret",
    "refresh-token",
)?;
let signer = Signer::new(context, provider, RequestSigner);
# let _ = signer;
# Ok(())
# }
```

The refresh provider sends the client ID and secret as an RFC 6749 form body.
It expects Dropbox to return `expires_in`; a response without an expiration is
rejected instead of being cached as a token with an unknown lifetime.
Refresh-token rotation is serialized per shared provider, and access-token
caching belongs to `reqsign_core::Signer`.

On `wasm32-unknown-unknown`, this crate enables Jiff's `js` feature. Runtime
signing or refresh requires a wasm-bindgen JavaScript host such as a browser or
Node; a bare WASM runtime without a JavaScript clock can compile the crate but
is not a supported runtime. CI exercises the public default signer path under
`wasm-bindgen-test` in Node.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
