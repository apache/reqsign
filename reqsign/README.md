# Apache Reqsign

Signing HTTP requests for AWS, Azure, Cloudflare, Dropbox, GitHub, Google, Huawei, Aliyun, Baidu Netdisk, Tencent, Upyun, Oracle, Vercel and Seafile services.

## Features

This crate provides a unified interface for signing HTTP requests across multiple cloud providers:

- **AWS**: Signature V4 for AWS services
- **Azure**: Azure Storage services
- **Baidu Netdisk**: Static access-token query signing
- **Cloudflare**: Cloudflare API v4 requests with an API token, including KV and D1
- **Dropbox**: OAuth 2.0 bearer authentication
- **GitHub**: GitHub.com bearer tokens and anonymous public access
- **OneDrive**: Microsoft Graph OAuth 2.0 bearer authentication
- **Google**: Google Cloud services
- **Aliyun**: Aliyun Object Storage Service (OSS) and Aliyun Drive Open Platform
- **Huawei Cloud**: Object Storage Service (OBS)
- **Koofr**: Koofr access-token exchange and request signing
- **Tencent Cloud**: Cloud Object Storage (COS)
- **Upyun**: UPYUN header signing for Upyun Storage
- **Oracle**: Oracle Cloud services
- **Vercel**: Vercel Blob and Artifacts (Turborepo Remote Cache) bearer tokens
- **Seafile**: Seafile Web API services

## Upgrading

0.21 moves the core and the established service crates to `4.0.0` and makes
cryptography and the runtime `Context` explicit. The migration steps, including
`default_signer(ctx, ...)` and the `CryptoProvider` binding, are in
[Upgrading to Reqsign 0.21](https://github.com/apache/reqsign/blob/main/website/docs/guides/upgrading-to-0.21.md).

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

Add `reqsign` to your `Cargo.toml`. The example also needs `anyhow`, `http`,
and `tokio`:

```toml
[dependencies]
reqsign = { version = "0.21", features = ["aws"] }
anyhow = "1"
http = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
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
reqsign = { version = "0.21", default-features = false, features = ["aws", "default-context", "default-crypto"] }
anyhow = "1"
http = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
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

For more control, you can manually assemble the signer components. This
example also uses the native context adapters directly:

```toml
[dependencies]
reqsign = { version = "0.21", features = ["aws"] }
reqsign-file-read-tokio = "4"
reqsign-http-send-reqwest = "5"
anyhow = "1"
http = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

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

// Baidu Netdisk (supply the access token explicitly; there is no ambient source)
use reqsign::baidu_netdisk;
let signer = baidu_netdisk::default_signer(ctx.clone(), "access-token");

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

// OneDrive (supply an explicit static or refresh provider; there is no ambient source)
use reqsign::onedrive;
let signer = onedrive::default_signer(ctx.clone()).with_credential_provider(
    onedrive::DefaultCredentialProvider::new()
        .push_front(onedrive::StaticCredentialProvider::new("graph-access-token")),
);

// Huawei Cloud OBS
use reqsign::huaweicloud;
let signer = huaweicloud::default_signer(ctx.clone(), "mybucket");

// OpenStack Keystone
use reqsign::openstack;
let signer = openstack::default_signer(ctx.clone());

// Tencent COS
use reqsign::tencent;
let signer = tencent::default_signer(ctx.clone());

// Upyun
use reqsign::upyun;
let signer = upyun::default_signer(ctx.clone(), "mybucket");

// Vercel Blob
use reqsign::vercel;
let blob_signer = vercel::default_blob_signer(ctx.clone());

// Vercel Artifacts
let artifacts_signer = vercel::default_artifacts_signer(ctx.clone());

// Oracle Cloud
use reqsign::oracle;
let signer = oracle::default_signer(ctx.clone());

// Seafile
use reqsign::seafile;
let signer = seafile::default_signer(ctx.clone());
```

## Feature Flags

- `default`: Enables `default-context` and `default-crypto`
- `default-context`: Provides a default context implementation: `ReqwestHttpSend` and `OsEnv` on every target, plus `TokioFileRead` and `TokioCommandExecute` on native targets
- `default-crypto`: Re-exports `RustCryptoProvider`; `default_context()` binds it when no process-wide provider is installed
- `aliyun`: Enable Aliyun OSS support
- `aliyun-drive`: Enable Aliyun Drive Open Platform support
- `aws`: Enable AWS services support (alias of `aws-v4`)
- `aws-v4`: Enable AWS Signature V4 signing support
- `aws-v4a`: Enable AWS Signature V4a multi-region signing support
- `azure`: Enable Azure Storage support
- `b2`: Enable Backblaze B2 Native API support
- `baidu-netdisk`: Enable Baidu Netdisk support
- `cloudflare`: Enable Cloudflare API support (KV and D1)
- `dropbox`: Enable Dropbox OAuth 2.0 support
- `github`: Enable GitHub.com support
- `google`: Enable Google Cloud support
- `google-credential-access-boundary-client-side`: Enable client-side Google Credential Access Boundary token generation; implies `google` (server-side CAB is included by `google`)
- `http-message-signatures`: Enable HTTP Message Signatures (RFC 9421) support
- `huaweicloud`: Enable Huawei Cloud OBS support
- `koofr`: Enable Koofr support
- `oauth2`: Enable the shared OAuth 2.0 refresh-token support
- `onedrive`: Enable OneDrive support (implies `oauth2`)
- `openstack`: Enable OpenStack Keystone support
- `oracle`: Enable Oracle Cloud support
- `seafile`: Enable Seafile support
- `tencent`: Enable Tencent COS support
- `upyun`: Enable Upyun support
- `vercel`: Enable Vercel Blob and Artifacts support
- `volcengine`: Enable Volcengine TOS support
- `yandex-disk`: Enable Yandex Disk support
- `full`: Enable all service features

## WASM Support

Reqsign supports `wasm32-unknown-unknown` for a defined subset of services;
see the
[Custom runtimes & WASM guide](https://github.com/apache/reqsign/blob/main/website/docs/guides/custom-runtimes.md)
for the provider list and clock requirements.

`default-context` and `default-crypto` are supported on WASM.
`default_context()` wires `ReqwestHttpSend` and `OsEnv` and, with
`default-crypto`, binds RustCrypto. File reading and command execution have no
browser equivalent and fail when a credential source needs them; `OsEnv` reads
no variables on WASM because there is no process environment, so prefer static
or externally injected credentials.

AWS signing stamps each request with `Timestamp::now()`. A WASM build must
enable Jiff's JavaScript clock in the application for that to work:

```toml
[dependencies]
reqsign = { version = "0.21", features = ["aws"] }

[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]
jiff = { version = "1.0.1", features = ["js"] }
```

The default features enabled above include `default-context` and
`default-crypto`. Jiff's `js` clock reads `js_sys::Date` through wasm-bindgen
JS host imports, so this recipe needs a wasm-bindgen JavaScript host, such as
a browser or Node, that provides the clock imports.
