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

Profile and file selection use explicit options first, then `AWS_PROFILE`,
`AWS_CONFIG_FILE`, and `AWS_SHARED_CREDENTIALS_FILE`, then `default`,
`~/.aws/config`, and `~/.aws/credentials`. The Context supplies the home directory,
file reader, and environment. Config files use `[default]` and `[profile name]`;
credentials files use `[default]` and `[name]`. Named profiles do not inherit
`default`. During shared configuration loading, credentials-file properties
replace config-file properties with the same name, preserving other properties.
The static credential provider retains its existing complete-credentials-file
precedence and config-file fallback.

Region precedence is `with_region`, `AWS_REGION`, `AWS_DEFAULT_REGION`, then the
merged profile's `region`. Global endpoint precedence is `with_endpoint_url`,
`AWS_ENDPOINT_URL`, then the merged profile's `endpoint_url`. `Profile::get`
returns the raw merged file property, before these overrides. Service-specific
endpoint variables, `[services ...]` sections, endpoint rules, and
`AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` are not interpreted. The endpoint is a
setting for the caller to use, not an automatically selected signing endpoint.

Unreadable files and unavailable home directories are treated as absent.
Malformed readable files return an error without including their contents.
Missing values remain `None`; applications choose their own fallback regions.
Calling `load` never queries metadata, even after `with_imds`. `resolve_region`
skips file reads when an explicit or environment region is available, and only
queries metadata when no configured region is found and discovery is enabled.

`IMDSv2RegionProvider` performs a token request and an authenticated
`/latest/meta-data/placement/region` request, without requiring an IAM role. It
honors `AWS_EC2_METADATA_DISABLED`, `AWS_EC2_METADATA_SERVICE_ENDPOINT`, and
`AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE=IPv6`. An explicit endpoint takes
precedence. The whole lookup has a configurable two-second deadline and no
retries or IMDSv1 fallback. Disabled discovery returns `None`; transport,
protocol, and timeout failures return errors. The Context HTTP adapter must
cooperate with future cancellation. The timer works independently of the
application's async runtime (using browser timers on wasm32).

See the AWS documentation for [shared configuration file format](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html)
and [EC2 metadata categories](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html).
