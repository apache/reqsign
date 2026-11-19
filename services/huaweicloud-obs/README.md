# reqsign-huaweicloud-obs

Huawei Cloud Object Storage Service signing implementation for reqsign.

The default credential provider reads `HUAWEI_CLOUD_ACCESS_KEY_ID` and
`HUAWEI_CLOUD_SECRET_ACCESS_KEY`, with an optional
`HUAWEI_CLOUD_SECURITY_TOKEN`.

## Changelog: credential expiry

`Credential` now has an absolute `expires_at: Option<Timestamp>` field.
`Credential::new` keeps its original three-argument, no-expiry behavior; use
`Credential::with_expires_at` when the expiration is known. The added public
field means existing struct-literal construction no longer compiles, so
struct-literal callers must switch to `Credential::new` (and
`with_expires_at` where needed).

`AgencyGrant` and `AgencyGranter` issue Huawei Cloud IAM agency temporary
credentials through `Granter<Credential>`. The result carries the exact IAM
`expires_at` and can be passed directly to `RequestSigner`. Known-expiry
credentials are rejected by header signing or presigning when they do not cover
the requested operation deadline.

> Signing requires a process-wide `CryptoProvider`. Install one at startup
> before constructing signers; see
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_huaweicloud_obs::{DefaultCredentialProvider, RequestSigner};

let context = Context::new().with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new("bucket"),
);
```

Use `StaticCredentialProvider` for credentials supplied directly by an
application, or `DefaultCredentialProvider::builder()` to replace or remove
the environment credential slot.

## Examples

- [Credential-chain logging](examples/chain_logging.rs)
- [Custom credential chain](examples/custom_chain.rs)

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
