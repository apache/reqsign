# reqsign-aws-core

Shared AWS credential and request canonicalization foundation for `reqsign`
signing implementations.

This crate contains the AWS credential type, algorithm-independent credential
providers, and canonical request primitives shared by SigV4 and SigV4a. Most
users should depend on `reqsign-aws-v4` or `reqsign-aws-v4a`, which re-export
the relevant public types.

## Shared configuration and region discovery

`SharedConfig` reads the selected AWS profile without acquiring credentials,
executing `credential_process`, or contacting metadata or SSO services. It is
also re-exported by both signing crates and `reqsign::aws`.

```no_run
use reqsign_aws_core::{IMDSv2RegionProvider, SharedConfig};
use reqsign_core::{Context, OsEnv};

# async fn example(ctx: Context) -> reqsign_core::Result<()> {
// Supply FileRead and HttpSend adapters through Context as needed.
let ctx = ctx.with_env(OsEnv);
let config = SharedConfig::new().with_profile("example");
let profile = config.load(&ctx).await?;
let endpoint = profile.endpoint_url();
let configured_region = profile.region();

// Metadata fallback is opt-in and independent of authentication.
let region = config
    .with_imds(IMDSv2RegionProvider::new())
    .resolve_region(&ctx)
    .await?;
# Ok(())
# }
```

See [`SharedConfig`] for profile/file selection, merge rules, and region/endpoint
precedence. Missing values remain `None`; applications choose their own defaults.
[`IMDSv2RegionProvider`] documents the opt-in metadata fallback and its deadline.

[`SharedConfig`]: https://docs.rs/reqsign-aws-core/latest/reqsign_aws_core/struct.SharedConfig.html
[`IMDSv2RegionProvider`]: https://docs.rs/reqsign-aws-core/latest/reqsign_aws_core/struct.IMDSv2RegionProvider.html
