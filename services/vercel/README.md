# reqsign-vercel

Vercel Blob and Vercel Artifacts token discovery and request signing for
Reqsign.

The two APIs share `Authorization: Bearer <token>` but use different tokens,
scopes, and endpoints. This crate keeps them as separate credential types,
providers, and signers so a Blob credential cannot authenticate an Artifacts
request, or the reverse.

## Vercel Blob

`BlobRequestSigner` signs Blob API requests with a read-write token. The default
provider reads `BLOB_READ_WRITE_TOKEN`, the long-lived static token documented
for `@vercel/blob` when code runs outside Vercel.

The caller owns the endpoint, pathname, method, access level, upload options,
and Blob API headers. Vercel's current SDK uses
`https://vercel.com/api/blob` for control-plane calls; blob content is served
from `*.blob.vercel-storage.com`. The signer preserves the endpoint and URI
the caller builds.

Vercel's OIDC (`VERCEL_OIDC_TOKEN` plus `BLOB_STORE_ID`) and client-token flows
need store or operation context in the request, so this crate does not discover
or refresh them. Pass a caller-managed token through
`BlobStaticCredentialProvider` when needed.

## Vercel Artifacts

`ArtifactsRequestSigner` signs the Vercel Artifacts API used by the Turborepo
Remote Cache at `https://api.vercel.com/v8/artifacts/{hash}`.

The default chain reads:

1. `TURBO_TOKEN`, the bearer token documented by Turborepo for Remote Cache
   access.
2. `VERCEL_ARTIFACTS_TOKEN`, which Vercel injects into its build environments.

When both are present, `TURBO_TOKEN` is tried first. `TURBO_TEAM`,
`TURBO_TEAMID`, and `VERCEL_ARTIFACTS_OWNER` select the cache scope in the
request query and stay with the caller. So do the cache key and headers such as
`x-artifact-duration`. Reqsign neither reads nor stores the team or cache
identity.

Vercel documents an OIDC token exchange for CI and a personal access token for
non-OIDC setups. Reqsign accepts the resulting bearer token but does not perform
the exchange or refresh it.

## Failure behavior

The configured sources fail closed. A present but unusable token, or an invalid
prepended or static provider, fails signing instead of silently selecting a
different identity. An absent token yields no credential, and signing then
reports `CredentialInvalid`.

Signing inserts a sensitive `Authorization` header and leaves the URI and every
other header unchanged. Neither API has query authentication, so signing rejects
`expires_in`. Neither token has a readable expiry, and signing writes no protocol
time, so signing has no clock dependency. On `wasm32-unknown-unknown`,
environment and static credentials plus header signing need no JavaScript clock.

The caller owns the HTTP client and its redirect policy. Do not forward a signed
`Authorization` header to a different host.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Result, Signer};
use reqsign_vercel::{
    ArtifactsDefaultCredentialProvider, ArtifactsRequestSigner,
    BlobDefaultCredentialProvider, BlobRequestSigner,
};

# async fn example() -> Result<()> {
let ctx = Context::new().with_env(OsEnv);

let blob = Signer::new(
    ctx.clone(),
    BlobDefaultCredentialProvider::new(),
    BlobRequestSigner,
);

let artifacts = Signer::new(
    ctx,
    ArtifactsDefaultCredentialProvider::new(),
    ArtifactsRequestSigner,
);

// The caller owns the endpoint, pathname, cache key, and scope query.
let mut blob_req = http::Request::put(
    "https://vercel.com/api/blob/reports/2026%20Q1.csv?addRandomSuffix=0",
)
.body(())
.unwrap()
.into_parts()
.0;
blob.sign(&mut blob_req, None).await?;

let mut artifact_req = http::Request::put(
    "https://api.vercel.com/v8/artifacts/example-hash?teamId=team_example",
)
.body(())
.unwrap()
.into_parts()
.0;
artifacts.sign(&mut artifact_req, None).await?;
# Ok(())
# }
```

For explicit tokens, replace the providers:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_vercel::{
    ArtifactsRequestSigner, ArtifactsStaticCredentialProvider, BlobRequestSigner,
    BlobStaticCredentialProvider,
};

# fn example(context: Context) -> Result<()> {
let blob = Signer::new(
    context.clone(),
    BlobStaticCredentialProvider::new("vercel-blob-read-write-token"),
    BlobRequestSigner,
);
let artifacts = Signer::new(
    context,
    ArtifactsStaticCredentialProvider::new("vercel-artifacts-token"),
    ArtifactsRequestSigner,
);
# let _ = (blob, artifacts);
# Ok(())
# }
```

The builders expose one positive method and one removal method per slot. Removed
slots are not re-enabled during `build()`, and an error from a prepended provider
is returned instead of falling through to the default chain.

```rust,no_run
use reqsign_vercel::{
    ArtifactsDefaultCredentialProvider, ArtifactsEnvCredentialProvider,
    ArtifactsVercelEnvCredentialProvider, BlobDefaultCredentialProvider,
    BlobEnvCredentialProvider,
};

let blob = BlobDefaultCredentialProvider::builder()
    .no_env()
    .env(BlobEnvCredentialProvider::new())
    .build();

let artifacts = ArtifactsDefaultCredentialProvider::builder()
    .no_vercel_env()
    .env(ArtifactsEnvCredentialProvider::new())
    .vercel_env(ArtifactsVercelEnvCredentialProvider::new())
    .build();
# let _ = (blob, artifacts);
```

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
