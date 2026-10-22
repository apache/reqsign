# reqsign-openstack-keystone

OpenStack Keystone authentication implementation for reqsign.

The crate authenticates against the Keystone v3 identity API with password
credentials, signs OpenStack service requests with the resulting token, and
keeps the service catalog that Keystone returns for a scoped token. The catalog
lets callers resolve the endpoint of a service, such as Swift, without another
request.

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

The default chain reads `OS_AUTH_URL`, `OS_USERNAME`, and `OS_PASSWORD`, plus
the optional `OS_USER_DOMAIN_NAME`, `OS_PROJECT_NAME`, and
`OS_PROJECT_DOMAIN_NAME`. Use `KeystoneCredentialProvider` with
`DefaultCredentialProvider::builder()` for explicit credentials, and
`Credential::endpoint_in_region` to look up a service endpoint from the
returned catalog.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
