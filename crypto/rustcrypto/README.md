# reqsign-crypto-rustcrypto

Pure Rust [`CryptoProvider`][provider] for Reqsign, built on the RustCrypto
crates.

The provider implements MD5, SHA-1, SHA-256, HMAC-SHA-1, HMAC-SHA-256,
HMAC-SHA-512, and ECDSA P-256 on every target. RSA PKCS#1 v1.5 signing, AES-GCM,
and secure random generation are available on native targets. On
`wasm32-unknown-unknown`, those operations return `ConfigInvalid`.

## Quick Start

Bind the provider to one context:

```rust
use reqsign_core::Context;
use reqsign_crypto_rustcrypto::RustCryptoProvider;

let ctx = Context::new().with_crypto(RustCryptoProvider::new());
```

Or install it process-wide before constructing contexts:

```rust
use reqsign_crypto_rustcrypto::RustCryptoProvider;

if RustCryptoProvider::install_default().is_err() {
    eprintln!("a process-wide crypto provider is already installed");
}
```

The facade's `default_context()` binds this provider when the `default-crypto`
feature is enabled and no process-wide provider is installed. A context that
already binds a provider keeps that binding.

See [CryptoProvider][contract] for the provider contract, resolution order, and
error semantics.

[provider]: https://docs.rs/reqsign-core/latest/reqsign_core/crypto/trait.CryptoProvider.html
[contract]: https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md

## License

Licensed under the Apache License, Version 2.0.
