# reqsign-core

Core components for signing API requests.

---

This crate provides the foundational types and traits for the reqsign ecosystem. It defines the core abstractions that enable flexible and extensible request signing.

## Quick Start

```rust
use reqsign_core::{Context, Signer, ProvideCredential, SignRequest};

// Create a context with your implementations
let ctx = Context::default();

// Create a signer with credential loader and request builder
let signer = Signer::new(ctx, credential_loader, request_builder);

// Sign your requests
let mut parts = /* your request parts */;
signer.sign(&mut parts, None).await?;
```

## Features

- **Flexible Architecture**: Define your own credential types and signing logic
- **Async Support**: Built with async/await for modern Rust applications
- **Environment Integration**: Access environment variables through the Context
- **Type Safety**: Strong typing ensures compile-time correctness

## Changelog: 4.0.0

- Cryptography moved behind `reqsign_core::crypto::CryptoProvider`, resolved
  through the `Context`: an explicit `Context::with_crypto` binding, then the
  process-wide `install_default`, otherwise `ConfigInvalid` at the point of use.
  `Context::new()` starts unbound and the crate links no cryptographic
  implementation. Use `reqsign-crypto-rustcrypto` (or another backend) to bind
  one.
- The `jwt` module and `jwt` feature are removed. Hash and MAC helpers take
  `&dyn CryptoProvider` and return `Result`; services format their own RS256
  JWS through the selected provider.
- `Signer::with_context` isolates the credential cache instead of reusing the
  previous context's cached credential. `with_request_signer` and
  `with_credential_granter` keep the cache.
- The minimum supported Rust version is 1.87.0.

## Core Concepts

### Context

The `Context` struct serves as a container for runtime dependencies:
- File system access via `FileRead` trait
- HTTP client via `HttpSend` trait  
- Environment variables via `Env` trait

### Traits

- **`ProvideCredential`**: Load credentials from various sources
- **`SignRequest`**: Build service-specific signing requests
- **`SigningCredential`**: Validate credential validity
- **`FileRead`**: Async file reading operations
- **`HttpSend`**: HTTP request execution
- **`Env`**: Environment variable access

### Signer

The `Signer` orchestrates the signing process by:
1. Loading credentials using the provided loader
2. Building signing requests with the builder
3. Applying signatures to HTTP requests

## Examples

Check out the [custom_signer example](examples/custom_signer.rs) to see how to implement your own signing logic.

```bash
cargo run --example custom_signer
```

## Integration

This crate is typically used with service-specific implementations:
- `reqsign-aws-v4` for AWS services
- `reqsign-aws-v4a` for multi-region AWS services
- `reqsign-aliyun-oss` for Aliyun OSS
- `reqsign-aliyun-drive` for Aliyun Drive Open Platform
- `reqsign-azure-storage` for Azure Storage
- `reqsign-vercel` for Vercel Blob and Artifacts
- And more...

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
