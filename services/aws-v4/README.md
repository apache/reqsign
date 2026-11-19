# reqsign-aws-v4

AWS SigV4 signing implementation for `reqsign`.

## Quick Start

```rust,no_run
use reqsign_aws_v4::{DefaultCredentialProvider, EMPTY_STRING_SHA256, RequestSigner};
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);

    let signer = Signer::new(
        ctx,
        DefaultCredentialProvider::new(),
        RequestSigner::new("s3", "us-east-1"),
    );

    let mut req = http::Request::get("https://s3.amazonaws.com/mybucket/mykey")
        .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;
    Ok(())
}
```

## Payload Signing

`RequestSigner` signs the request head (`http::request::Parts`) and never reads
the body. If `x-amz-content-sha256` is present, the signer preserves it and uses
it as the SigV4 payload hash. Otherwise, header authentication adds
`x-amz-content-sha256: UNSIGNED-PAYLOAD`, including for an empty body. Query
authentication (presigning) does not add the header, but uses
`UNSIGNED-PAYLOAD` in the canonical request.

`UNSIGNED-PAYLOAD` is an Amazon S3 payload mode. The signer uses the same
default for every service name, while other AWS services define their own
payload requirements. Check the endpoint's [SigV4 requirements] when that mode
is not accepted.

For an S3 request that must sign the actual payload, hash the exact bytes that
will be sent and set `x-amz-content-sha256` before signing. Use
`EMPTY_STRING_SHA256` for an empty body and `reqsign_core::hash::hex_sha256` for
non-empty bytes:

```rust,no_run
use reqsign_aws_v4::EMPTY_STRING_SHA256;
use reqsign_core::hash::hex_sha256;

let body: &[u8] = b"Hello, World!";
let payload_hash = if body.is_empty() {
    EMPTY_STRING_SHA256.to_string()
} else {
    hex_sha256(body)
};

let request = http::Request::put("https://s3.amazonaws.com/mybucket/hello.txt")
    .header("x-amz-content-sha256", payload_hash)
    .body(body)
    .expect("request must be valid");
```

Setting `EMPTY_STRING_SHA256` is only required when the endpoint requires a
signed empty payload; otherwise the default `UNSIGNED-PAYLOAD` remains in
effect. If the header is set before presigning, it becomes part of
`X-Amz-SignedHeaders`, and the same header must be sent with the presigned
request. Leave it unset when the URL should use `UNSIGNED-PAYLOAD` without a
payload header.

Hash the bytes after content encoding or compression, and do not change the
payload after signing. `RequestSigner` does not implement chunked or streaming
payload signatures.

[SigV4 requirements]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html

## Default Credential Chain

`DefaultCredentialProvider::new()` builds the documented AWS default chain:

1. `env`
2. `profile`
3. `sso`
4. `web_identity`
5. `process`
6. `ecs`
7. `imds`

On `wasm32`, the non-portable `sso` and `process` slots are not available.

## S3 Express Authentication

`RequestSigner::new("s3express", region)` uses the S3 Express CreateSession
token representation by default. Use `with_standard_session_token()` for
operations that require IAM credentials, including `CopyObject`, `HeadBucket`,
and `UploadPartCopy`. The same selection applies to header and query
authentication.

```rust
use reqsign_aws_v4::RequestSigner;

let _session_signer = RequestSigner::new("s3express", "us-west-2");
let _iam_signer = RequestSigner::new("s3express", "us-west-2")
    .with_standard_session_token();
```

## Select a Profile

Use `with_profile(...)` to select one profile consistently for the shared
profile, SSO, and process credential sources. The explicit selection takes
precedence over `AWS_PROFILE`.

```rust,no_run
use reqsign_aws_v4::DefaultCredentialProvider;

let provider = DefaultCredentialProvider::builder()
    .with_profile("production")
    .build();
```

## Customize Slots

Use `DefaultCredentialProvider::builder()` to replace or remove individual slots.
Each slot is represented by `Option<T>` internally: `slot(provider)` enables it,
`no_slot()` removes it, and `build()` only pushes `Some(...)` slots into the
chain.

```rust,no_run
use reqsign_aws_v4::{DefaultCredentialProvider, ProfileCredentialProvider};

let provider = DefaultCredentialProvider::builder()
    .no_env()
    .profile(ProfileCredentialProvider::new().with_profile("production"))
    .no_imds()
    .build();
```

For advanced composition, use `DefaultCredentialProvider::with_chain(...)` or
prepend a higher-priority source with `DefaultCredentialProvider::push_front(...)`.

## S3 Access Grants

Use `S3AccessGrantsGranter` to authorize one typed `GetDataAccess` request with
an existing AWS credential and return the temporary credential issued by S3
Access Grants. The result can be passed directly to the existing AWS signer.

```rust,no_run
use std::time::Duration;

use reqsign_aws_v4::{
    DefaultCredentialProvider, S3AccessGrantsConfig, S3AccessGrantsGrant,
    S3AccessGrantsGranter, S3AccessGrantsPermission, S3AccessGrantsPrivilege,
    S3AccessGrantsTarget,
};
use reqsign_core::{Context, Granter};
use reqsign_http_send_reqwest::ReqwestHttpSend;

# async fn example() -> reqsign_core::Result<()> {
let grant = S3AccessGrantsGrant::new(
    S3AccessGrantsTarget::for_prefix("example-bucket", "customer-a/"),
    S3AccessGrantsPermission::Read,
    S3AccessGrantsPrivilege::Minimal,
);
let granter = Granter::new(
    Context::new().with_http_send(ReqwestHttpSend::default()),
    DefaultCredentialProvider::new(),
    S3AccessGrantsGranter::new(
        S3AccessGrantsConfig::new("111122223333", "us-east-2"),
        grant,
    ),
);
let credential = granter.grant(Some(Duration::from_secs(900))).await?;
# let _ = credential;
# Ok(())
# }
```

## Examples

- [S3 signing example](examples/s3_sign.rs)
- [DynamoDB signing example](examples/dynamodb_sign.rs)
- [S3 Express signing example](examples/s3_express_sign.rs)
