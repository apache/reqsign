# reqsign-tencent-cos

Tencent Cloud Object Storage request signing implementation for reqsign.

The default credential provider checks Tencent Cloud environment variables and
then web identity configuration. It supports both header authentication and
presigned query authentication.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_tencent_cos::{DefaultCredentialProvider, RequestSigner};

let context = Context::new().with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new(),
);
```

Environment credentials use `TENCENTCLOUD_SECRET_ID` and
`TENCENTCLOUD_SECRET_KEY`, with an optional token in
`TENCENTCLOUD_TOKEN` or `TENCENTCLOUD_SECURITY_TOKEN`. TKE aliases are also
supported.

Web identity credentials use `TENCENTCLOUD_ROLE_ARN`, `TENCENTCLOUD_PROVIDER_ID`,
`TENCENTCLOUD_REGION`, and a file holding an OIDC token referenced by
`TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE`. The provider exchanges that token at
`sts.tencentcloudapi.com` for temporary credentials and returns no credential
until all four values are configured.

See [tests/README.md](./tests/README.md) for the live web identity test setup and
its CI trust boundary.

## Examples

- [Credential-chain logging](examples/tencent_chain_logging.rs)

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
