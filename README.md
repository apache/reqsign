# Apache Reqsign

[![Build Status]][actions] [![Latest Version]][crates.io] [![Crate Downloads]][crates.io]

[Build Status]: https://img.shields.io/github/actions/workflow/status/apache/reqsign/ci.yml?branch=main
[actions]: https://github.com/apache/reqsign/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/reqsign.svg
[crates.io]: https://crates.io/crates/reqsign
[Crate Downloads]: https://img.shields.io/crates/d/reqsign.svg

Signing API requests without effort.

---

Most APIs are simple, but they can become complicated when hidden behind complex abstractions. `reqsign` brings the simple API back: build, sign, send.

## Quick Start

### Option 1: Use Default Signer (Recommended)

The simplest way to use `reqsign` is with the default signers provided by each service:

```rust
use anyhow::Result;
use reqsign::{aws, default_context};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a default runtime context (HTTP client, file reader, OS env, command execution).
    // It binds RustCrypto when no process-wide provider is installed.
    let ctx = default_context();
    // Create a default signer for S3 in us-east-1 using the supplied context
    let signer = aws::default_signer(ctx, "s3", "us-east-1");
    
    // Build your request
    let mut req = http::Request::builder()
        .method("GET")
        .uri("https://s3.amazonaws.com/testbucket")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    
    // Sign the request
    signer.sign(&mut req, None).await?;
    
    // Send the request with your preferred HTTP client
    println!("Request has been signed!");
    Ok(())
}
```

### Option 2: Custom Assembly

For more control over the components, you can manually assemble the signer:

```rust
use anyhow::Result;
use reqsign::{Context, RustCryptoProvider, Signer};
use reqsign_aws_v4::{DefaultCredentialProvider, RequestSigner};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;

#[tokio::main]
async fn main() -> Result<()> {
    // Build your own context with specific implementations.
    // A bare Context starts unbound, so bind the provider explicitly.
    let ctx = Context::new()
        .with_crypto(RustCryptoProvider::new())
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(reqsign::OsEnv);
    
    // Configure credential provider
    let credential_provider = DefaultCredentialProvider::new();
    
    // Configure request signer for S3
    let request_signer = RequestSigner::new("s3", "us-east-1");
    
    // Assemble the signer
    let signer = Signer::new(ctx, credential_provider, request_signer);
    
    // Build and sign the request
    let mut req = http::Request::builder()
        .method("GET")
        .uri("https://s3.amazonaws.com/testbucket")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    
    // Sign the request
    signer.sign(&mut req, None).await?;
    
    println!("Request has been signed!");
    Ok(())
}
```

### Customizing Default Signers

You can also customize the default signers using the `with_*` methods:

```rust
use reqsign::{aws, default_context};
use reqsign_aws_v4::StaticCredentialProvider;

// Start with default signer and customize specific components
let ctx = default_context();
let signer = aws::default_signer(ctx, "s3", "us-east-1")
    .with_credential_provider(StaticCredentialProvider::new(
        "my-access-key",
        "my-secret-key",
    ));
```

For server applications that already hold an OIDC assertion, see
[Caller-provided subject tokens](docs/caller-provided-subject-tokens.md).

### More Services Examples

#### AWS SigV4a

```rust
use reqsign::aws::v4a::{SigningRegionSet, default_signer};
use reqsign::default_context;

let ctx = default_context();
let region_set = SigningRegionSet::new("us-east-1,us-west-2")?;
let signer = default_signer(ctx, "s3", region_set);
# Ok::<(), reqsign_core::Error>(())
```

#### Azure Storage

```rust
use reqsign::{azure, default_context};

let ctx = default_context();

// Default signer for Azure Storage
let signer = azure::default_signer(ctx.clone());

// With custom credentials
use reqsign_azure_storage::StaticCredentialProvider;
let signer = azure::default_signer(ctx)
    .with_credential_provider(StaticCredentialProvider::new_shared_key(
        "account-name",
        "account-key",
    ));
```

#### Vercel Blob and Artifacts

```rust
use reqsign::{default_context, vercel};

let ctx = default_context();

// Reads BLOB_READ_WRITE_TOKEN.
let blob_signer = vercel::default_blob_signer(ctx.clone());

// Reads TURBO_TOKEN, then VERCEL_ARTIFACTS_TOKEN.
let artifacts_signer = vercel::default_artifacts_signer(ctx);
```

#### Google Cloud

```rust
use reqsign::{default_context, google};

// Default signer for Google Cloud Storage
let ctx = default_context();
let signer = google::default_signer(ctx, "storage.googleapis.com");
```

#### Aliyun OSS

```rust
use reqsign::{aliyun, default_context};

// Default signer for Aliyun OSS
let ctx = default_context();
let signer = aliyun::default_signer(ctx, "mybucket");
```

## Features

- Pure Rust with minimal dependencies.
- Tested against official SDKs and services.
- Supported services
  - Aliyun OSS: `reqsign-aliyun-oss`
  - AWS shared credentials and canonicalization: `reqsign-aws-core`
  - AWS services (SigV4): `reqsign-aws-v4`
  - AWS multi-region services (SigV4a): `reqsign-aws-v4a`
  - Azure Storage services: `reqsign-azure-storage`
  - Dropbox: `reqsign-dropbox`
  - Google services: `reqsign-google`
  - Huawei Cloud OBS: `reqsign-huaweicloud-obs`
  - OpenStack Keystone: `reqsign-openstack-keystone`
  - Oracle Cloud: `reqsign-oracle`
  - OAuth 2.0 refresh-token support: `reqsign-oauth2`
  - Tencent COS: `reqsign-tencent-cos`
  - Vercel Blob and Artifacts: `reqsign-vercel`
  - Volcengine TOS: `reqsign-volcengine-tos`

## Contributing

Check out the [CONTRIBUTING.md](CONTRIBUTING.md) guide for more details on getting started with contributing to this project.

## Getting help

Submit [issues](https://github.com/apache/reqsign/issues/new/choose) for bug report or asking questions in [discussion](https://github.com/apache/reqsign/discussions/new?category=q-a).

Join the [development mailing list](mailto:dev@reqsign.apache.org) for project discussions and release votes. [Subscribe](mailto:dev-subscribe@reqsign.apache.org) before posting, or browse the [archives](https://lists.apache.org/list.html?dev@reqsign.apache.org).

## Acknowledgments

Inspired by:

- [aws-sigv4](https://crates.io/crates/aws-sigv4) for AWS SigV4 support.
- [azure_storage_blobs](https://crates.io/crates/azure_storage_blobs) for Azure Storage support.

## License

Licensed under [Apache License, Version 2.0](LICENSE).
