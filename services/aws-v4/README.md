# reqsign-aws-v4

AWS SigV4 signing implementation for `reqsign`.

> Signing needs a `CryptoProvider` resolved through the `Context`: bind one with
> `Context::with_crypto`, install a process-wide default, or use a facade
> `default_context()` (which binds RustCrypto when the global slot is empty). A
> bare `Context::new()` starts unbound. See
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

## Quick Start

```rust,no_run
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_aws_v4::{DefaultCredentialProvider, EMPTY_STRING_SHA256, RequestSigner};
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = Context::new().with_crypto(RustCryptoProvider::new())
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

## Canonical URI Encoding

The signer uses `PercentEncodingMode::Single` by default for every signing
service. This keeps Reqsign's existing canonical URI bytes and signatures stable
across upgrades. Call `with_percent_encoding_mode` to opt in to
`PercentEncodingMode::Double` when a service requires one additional encoding
pass:

```rust
use reqsign_aws_v4::{PercentEncodingMode, RequestSigner};

let signer = RequestSigner::new("execute-api", "us-east-1")
    .with_percent_encoding_mode(PercentEncodingMode::Double);
```

Both header signing and presigning use this setting. Supply the final wire-ready
URI: a path of `/a%20b` is signed as `/a%2520b` in Double mode, while the outgoing
path remains `/a%20b`. Double encodes the original path without decoding it; a
literal `@` becomes `%40`, while an existing `%40` becomes `%2540`. It preserves
literal `/` separators and does not normalize paths or change payload hashing.

Single retains Reqsign's existing per-segment decode/re-encode behavior, including
normalizing escape spelling and rejecting percent-encoded invalid UTF-8. It is
not a raw-path pass-through for noncanonical wire paths.

## Payload Signing

### Why `UNSIGNED-PAYLOAD` is the default

`RequestSigner` receives `http::request::Parts` and never reads the request
body. The caller owns the body and may stream it, retry it, or hand it directly
to the HTTP client; hashing it inside the signer would require buffering the
whole body or implementing a streaming signature. Reqsign therefore defaults
to the S3 payload mode and leaves the signed-payload decision to the caller.

When `x-amz-content-sha256` is absent, header authentication adds
`x-amz-content-sha256: UNSIGNED-PAYLOAD`, including for an empty body, and uses
that value in the canonical request. Query authentication (presigning) does not
add the header but canonicalizes the missing value as `UNSIGNED-PAYLOAD`.

`UNSIGNED-PAYLOAD` is an Amazon S3 payload mode. The signer uses the same
default for every service name; other AWS services define their own SigV4
payload requirements, and some require the actual payload hash. Do not assume a
non-S3 endpoint accepts `UNSIGNED-PAYLOAD`. Check the endpoint's
[SigV4 requirements] and API reference when the service requires a signed
payload.

### Signing the exact bytes

For an operation that requires a signed payload, set `x-amz-content-sha256`
before signing to the lowercase hex SHA-256 of the exact bytes that will be
transmitted. For an empty body, use `EMPTY_STRING_SHA256`, whose value is the
SHA-256 of the empty string:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Use `reqsign_core::hash::hex_sha256` for non-empty bytes. Hash after any content
encoding or compression, and do not change the payload after signing. Chunked
or streaming payload signatures are not implemented.

```rust,no_run
use reqsign_aws_v4::EMPTY_STRING_SHA256;
use reqsign_core::hash::hex_sha256;

let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
let body: &[u8] = b"Hello, World!";
let payload_hash = if body.is_empty() {
    EMPTY_STRING_SHA256.to_string()
} else {
    hex_sha256(&provider, body).expect("SHA-256 must succeed")
};

let request = http::Request::put("https://s3.amazonaws.com/mybucket/hello.txt")
    .header("x-amz-content-sha256", payload_hash)
    .body(body)
    .expect("request must be valid");

let empty_request = http::Request::put("https://s3.amazonaws.com/mybucket/empty.txt")
    .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
    .body(())
    .expect("request must be valid");
```

Setting `EMPTY_STRING_SHA256` is only required when the endpoint requires a
signed empty payload; otherwise the default `UNSIGNED-PAYLOAD` remains in
effect. If the header is set before presigning, it becomes part of
`X-Amz-SignedHeaders`, and the same header must be sent with the presigned
request. Leave it unset when the URL should use `UNSIGNED-PAYLOAD` without a
payload header.

### Signature hash, TLS, and S3 checksums

The SigV4 signature covers the request method, URI, signed headers, and the
declared payload hash; it does not encrypt the body. When set to a payload
digest, the hash binds the signature to those exact bytes; `UNSIGNED-PAYLOAD`
explicitly does not cover the body. The signature does not replace TLS: the HTTP
client owns transport security, and Reqsign does not verify responses or S3
checksums.

S3's upload checksum headers are a separate integrity mechanism. `RequestSigner`
does not add them to general requests; callers supply them when required or
useful. Their values and support rules differ from the SigV4 payload hash:

| Header | Value | Role |
| --- | --- | --- |
| `x-amz-content-sha256` | Lowercase hex SHA-256, or `UNSIGNED-PAYLOAD` | SigV4 payload hash |
| `x-amz-checksum-*` (for example, `x-amz-checksum-sha256`) | Base64-encoded checksum | S3 additional checksum; support varies by algorithm, operation, bucket, and transfer mode |
| `Content-MD5` | Base64 MD5 | Legacy S3 integrity header; availability depends on operation, bucket, and transfer mode |

Checksum support is not universal. For example, [`PutObject`] does not support
`Content-MD5` for directory buckets, while [`DeleteObjects`] requires
`Content-MD5` for general purpose buckets and accepts `Content-MD5` or one of
the supported `x-amz-checksum-*` headers for directory buckets. Multipart
uploads and `aws-chunked` trailing checksums have their own per-operation rules.
Use the operation's API reference and the [S3 upload integrity guide]; do not
substitute a checksum header for `x-amz-content-sha256`.

For the REST API, use the algorithm-specific `x-amz-checksum-*` header rather
than the SDK-only `x-amz-sdk-checksum-algorithm` selector.

[SigV4 requirements]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
[S3 upload integrity guide]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
[`PutObject`]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
[`DeleteObjects`]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html

## Default Credential Chain

`DefaultCredentialProvider::new()` builds the documented AWS default chain:

1. `env`
2. `profile`
3. `sso`
4. `web_identity`
5. `process`
6. `ecs`
7. `imds`

The `profile` stage resolves `source_profile` chains backed by static
credentials, SSO, or `credential_process`. A role can instead name
`Environment`, `Ec2InstanceMetadata`, or `EcsContainer` in `credential_source`.
Each STS call uses the previous hop's credential. The graph uses the configured
slots, and removing a required slot returns an error for the selected role.

Providers added with `push_front` run first. Environment credentials take
precedence over profiles selected by `AWS_PROFILE` or the default name. For an
explicitly named role chain, the provider checks the graph before choosing
credentials. An invalid graph fails even when environment credentials are
available. A valid chain with `credential_source = Environment` uses the
`env` slot as its STS source and returns the final role credentials. Other valid
chains retain the environment-first order.

A profile can set `role_arn` and `web_identity_token_file` to use the
`web_identity` slot. Web identity profile settings and role-chain process
commands use the merged config and credentials files. The web identity slot can
discover its profile even with `.no_profile()`. The role chain and the `sso` and
`process` slots are available on targets other than `wasm32`.

## S3 Express Authentication

`RequestSigner::new("s3express", region)` uses the S3 Express CreateSession
token representation by default for every request authority. Use
`with_standard_session_token()` for operations that require IAM credentials,
including `CopyObject`, `HeadBucket`, and `UploadPartCopy`. The same selection
applies to header and query authentication.

```rust
use reqsign_aws_v4::RequestSigner;

let _session_signer = RequestSigner::new("s3express", "us-west-2");
let _iam_signer = RequestSigner::new("s3express", "us-west-2")
    .with_standard_session_token();
```

## Select a Profile

Use `with_profile(...)` to select one profile for the shared profile, SSO,
process, and web identity credential sources. The explicit selection takes
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

## IMDSv1 Fallback

The default IMDS provider requires IMDSv2. Instances that cannot use IMDSv2 can
opt in to an IMDSv1 fallback on the IMDS slot:

```rust,no_run
use reqsign_aws_v4::{DefaultCredentialProvider, IMDSv2CredentialProvider};

let provider = DefaultCredentialProvider::builder()
    .imds(IMDSv2CredentialProvider::new().with_imdsv1_fallback())
    .build();
```

Fallback is attempted only when the IMDSv2 token request returns HTTP 403, 404,
or 405. Transport, server, metadata, role, and credential errors are returned
and never downgraded. IMDSv2 remains the default.

## S3 Access Grants

Use `S3AccessGrantsGranter` to authorize one typed `GetDataAccess` request with
an existing AWS credential and return the temporary credential issued by S3
Access Grants. The result can be passed directly to the existing AWS signer.

```rust,no_run
use reqsign_crypto_rustcrypto::RustCryptoProvider;
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
    Context::new().with_crypto(RustCryptoProvider::new()).with_http_send(ReqwestHttpSend::default()),
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
