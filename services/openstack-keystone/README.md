# reqsign-openstack-keystone

OpenStack Keystone authentication implementation for reqsign.

The crate authenticates against the Keystone v3 identity API with password
credentials or accepts a pre-issued token, signs OpenStack service requests with
the resulting token, and keeps the service catalog that Keystone returns for a
scoped token. The catalog lets callers resolve the endpoint of a service, such
as Swift, without another request.

## Credential Sources

The default chain uses the environment provider. A non-empty `OS_AUTH_TOKEN` is
used directly as a pre-issued `X-Auth-Token` and takes priority over password
authentication; it makes no Keystone request. When it is set, `OS_AUTH_URL`,
`OS_USERNAME`, and `OS_PASSWORD` are not required. An empty `OS_AUTH_TOKEN` is
ignored, so password authentication still works.

Without `OS_AUTH_TOKEN`, the default chain reads `OS_AUTH_URL`, `OS_USERNAME`,
and `OS_PASSWORD`, plus the optional `OS_USER_DOMAIN_NAME`, `OS_PROJECT_NAME`,
and `OS_PROJECT_DOMAIN_NAME`.

A pre-issued token has no service catalog. When `OS_STORAGE_URL` is also set,
the provider exposes it as the public `object-store` endpoint; otherwise the
service endpoint remains caller configuration, as it does for the OpenDAL Swift
backend. Use `DefaultCredentialProvider::builder().no_env()` to remove both
environment sources together.

For explicit configuration, use `KeystoneCredentialProvider` with password
credentials, or `StaticCredentialProvider` with a pre-issued token and optional
catalog metadata. Install either with `Signer::new`, or prepend it to the default
chain with `DefaultCredentialProvider::push_front` so it takes priority over the
environment. `Credential::endpoint_in_region` resolves a service endpoint from
the returned catalog.

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_openstack_keystone::{RequestSigner, StaticCredentialProvider};

# async fn main() -> Result<()> {
let signer = Signer::new(
    Context::new(),
    StaticCredentialProvider::new("pre-issued-token"),
    RequestSigner,
);
# Ok(())
# }
```

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Result, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_openstack_keystone::{DefaultCredentialProvider, RequestSigner};

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

let mut req = http::Request::get("https://swift.example.com/v1/AUTH_test/container/object")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

The default chain reads `OS_AUTH_TOKEN` first, or `OS_AUTH_URL`, `OS_USERNAME`,
and `OS_PASSWORD` for password authentication, plus the optional
`OS_USER_DOMAIN_NAME`, `OS_PROJECT_NAME`, and `OS_PROJECT_DOMAIN_NAME`. Use
`KeystoneCredentialProvider` or `StaticCredentialProvider` directly with
`Signer`, or prepend one with `DefaultCredentialProvider::push_front`, for
explicit credentials. `Credential::endpoint_in_region` looks up a service
endpoint from the returned catalog.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
