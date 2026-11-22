# Apache Reqsign

Signing HTTP requests for AWS, Azure, Cloudflare, Dropbox, GitHub, Google, Huawei, Aliyun, Tencent and Oracle services.

## Features

This crate provides a unified interface for signing HTTP requests across multiple cloud providers:

- **AWS**: Signature V4 for AWS services
- **Azure**: Azure Storage services
- **Cloudflare**: Cloudflare API v4 requests with an API token, including KV and D1
- **Dropbox**: OAuth 2.0 bearer authentication
- **GitHub**: GitHub.com bearer tokens and anonymous public access
- **Google**: Google Cloud services
- **Aliyun**: Aliyun Object Storage Service (OSS) and Aliyun Drive Open Platform
- **Huawei Cloud**: Object Storage Service (OBS)
- **Tencent Cloud**: Cloud Object Storage (COS)
- **Oracle**: Oracle Cloud services

## Request URI Contract

Requests passed to the built-in signers must already contain a valid, wire-ready URI
with an authority. Construct the intended path and query structure before signing and
percent-encode data components exactly once. Structural delimiters such as path `/`
and query `&` remain literal; delimiter bytes that belong to data must be encoded, such
as `%2F` for a slash inside one path segment.

Reqsign does not perform general-purpose URI encoding for callers. Existing percent
escapes, query order, duplicate keys, empty values, and literal `+` characters are part
of the caller-owned wire representation. Header authentication preserves that URI.
Query authentication preserves it as a prefix and appends only protocol-encoded
authentication fields.

`Signer::sign` is atomic with respect to the caller's request head. On error, the
method, URI, version, headers, and extensions remain unchanged. On success, only the
URI and headers may change. The `expires_in` argument is a service-specific validity
input, not a universal switch between header and query authentication.

## Quick Start

Add `reqsign` to your `Cargo.toml`:

```toml
[dependencies]
reqsign = "0.20"
```

By default, this includes `default-context` (a ready-to-use context using
`reqwest` and `tokio`) and `default-crypto` (the RustCrypto provider).
`default-crypto` makes `default_context()` bind RustCrypto when the process-wide
slot is empty, so default signers work without startup boilerplate. It never
writes the global slot. To choose a global provider, install it before
constructing facade contexts; contexts already bound to RustCrypto keep that
binding, and an explicit `Context::with_crypto` binding always wins.

To use specific services only:

```toml
[dependencies]
reqsign = { version = "0.20", default-features = false, features = ["aws", "default-context"] }
```

## Examples

### Option 1: Using Default Signers (Recommended)

The easiest way to get started is using the default signers provided for each service:

```rust,ignore
use anyhow::Result;
use reqsign::{aws, default_context};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a default runtime context (HTTP client, file reader, OS env, command execution).
    // It binds RustCrypto when no process-wide provider is installed.
    let ctx = default_context();
    // Create a default signer for AWS S3 in us-east-1 using the supplied context
    let signer = aws::default_signer(ctx, "s3", "us-east-1");

    // Build and sign a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;

    println!("Request signed successfully!");
    Ok(())
}
```

### Option 2: Custom Assembly

For more control, you can manually assemble the signer components:

```rust,ignore
use anyhow::Result;
use reqsign::{Context, RustCryptoProvider, Signer, default_context};
use reqsign::aws::{DefaultCredentialProvider, RequestSigner};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a context with default implementations
    // (including a RustCrypto binding when default-crypto is enabled).
    let ctx = default_context();

    // Or build your own context with specific implementations.
    // A bare Context starts unbound, so bind the provider explicitly.
    let ctx = Context::new()
        .with_crypto(RustCryptoProvider::new())
        .with_file_read(reqsign_file_read_tokio::TokioFileRead)
        .with_http_send(reqsign_http_send_reqwest::ReqwestHttpSend::default())
        .with_env(reqsign::OsEnv);

    // Configure credential provider and request signer
    let credential_provider = DefaultCredentialProvider::new();
    let request_signer = RequestSigner::new("s3", "us-east-1");

    // Assemble the signer
    let signer = Signer::new(ctx, credential_provider, request_signer);

    // Build and sign a request
    let mut req = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://s3.amazonaws.com/my-bucket/my-object")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut req, None).await?;

    println!("Request signed successfully!");
    Ok(())
}
```

### Customizing Default Signers

You can customize the default signers using the `with_*` methods:

```rust,ignore
use reqsign::aws;
use reqsign::aws::StaticCredentialProvider;

// Pass a custom context directly and customize components as needed
let signer = aws::default_signer(my_custom_context, "s3", "us-east-1")
    .with_credential_provider(StaticCredentialProvider::new(
        "my-access-key",
        "my-secret-key",
    ));
```

For server applications that already hold an OIDC assertion, see
[Caller-provided subject tokens](../docs/caller-provided-subject-tokens.md).

### Examples for Other Services

```rust,ignore
let ctx = reqsign::default_context();

// Azure Storage
use reqsign::azure;
let signer = azure::default_signer(ctx.clone());

// Cloudflare (KV and D1)
use reqsign::cloudflare;
let signer = cloudflare::default_signer(ctx.clone());

// Backblaze B2
use reqsign::b2;
let signer = b2::default_signer(ctx.clone());

// GitHub
use reqsign::github;
let signer = github::default_signer(ctx.clone());

// Google Cloud
use reqsign::google;
let signer = google::default_signer(ctx.clone(), "storage.googleapis.com");

// Aliyun OSS
use reqsign::aliyun;
let signer = aliyun::default_signer(ctx.clone(), "mybucket");

// Aliyun Drive (supply an explicit provider; there is no ambient source)
use reqsign::aliyun_drive;
let signer = aliyun_drive::default_signer(ctx.clone())
    .with_credential_provider(aliyun_drive::StaticCredentialProvider::new("access-token"));

// Huawei Cloud OBS
use reqsign::huaweicloud;
let signer = huaweicloud::default_signer(ctx.clone(), "mybucket");

// OpenStack Keystone
use reqsign::openstack;
let signer = openstack::default_signer(ctx.clone());

// Tencent COS
use reqsign::tencent;
let signer = tencent::default_signer(ctx.clone());

// Oracle Cloud
use reqsign::oracle;
let signer = oracle::default_signer(ctx);
```

## Feature Flags

- `default`: Enables `default-context` and `default-crypto`
- `default-context`: Provides a default context implementation using `reqwest` and `tokio`
- `default-crypto`: Re-exports `RustCryptoProvider`; `default_context()` binds it when no process-wide provider is installed
- `aliyun`: Enable Aliyun OSS support
- `aliyun-drive`: Enable Aliyun Drive Open Platform support
- `aws`: Enable AWS services support
- `azure`: Enable Azure Storage support
- `b2`: Enable Backblaze B2 Native API support
- `cloudflare`: Enable Cloudflare API support (KV and D1)
- `dropbox`: Enable Dropbox OAuth 2.0 support
- `github`: Enable GitHub.com support
- `google`: Enable Google Cloud support
- `google-credential-access-boundary-client-side`: Enable client-side Google Credential Access Boundary token generation; implies `google` (server-side CAB is included by `google`)
- `http-message-signatures`: Enable HTTP Message Signatures (RFC 9421) support
- `huaweicloud`: Enable Huawei Cloud OBS support
- `oauth2`: Enable the shared OAuth 2.0 refresh-token support
- `openstack`: Enable OpenStack Keystone support
- `oracle`: Enable Oracle Cloud support
- `tencent`: Enable Tencent COS support

## WASM Support

This crate supports WebAssembly (WASM) targets. However, the `default-context` feature is not available on WASM due to platform limitations. When targeting WASM, you should:

1. Disable default features
2. Use the existing context implementations from `reqsign-file-read-tokio` and `reqsign-http-send-reqwest` crates
3. Or implement your own WASM-compatible context

Example for WASM:
```toml
[dependencies]
reqsign = { version = "0.20", default-features = false, features = ["aws"] }
reqsign-http-send-reqwest = "4"
```
