# reqsign-crypto-rustcrypto

Pure Rust [`CryptoProvider`][provider] for Reqsign, built on the RustCrypto
crates.

MD5, SHA-1, SHA-256, HMAC-SHA-1, HMAC-SHA-256, and HMAC-SHA-512 are always
available. Three optional features add the remaining operations:

| Feature | Default | Enables |
| --- | --- | --- |
| `rsa` | yes | RSA PKCS#1 v1.5 signing on native targets |
| `p256` | yes | ECDSA P-256 signing on every target |
| `aes-gcm` | yes | AES-128/256-GCM and secure random generation on native targets |

An operation whose feature is disabled returns `ConfigInvalid` and names the
missing feature. On `wasm32-unknown-unknown`, RSA, AES-GCM, and secure random
generation remain unavailable even when their feature is enabled; they return
`ConfigInvalid` with a target-specific message.

## Quick Start

`RustCryptoProvider` enables all three algorithm features by default:

```rust
use reqsign_core::Context;
use reqsign_crypto_rustcrypto::RustCryptoProvider;

let ctx = Context::new().with_crypto(RustCryptoProvider::new());
```

For a hash/HMAC-only build, disable default features:

```toml
[dependencies]
reqsign-crypto-rustcrypto = { version = "1", default-features = false }
```

Select only the algorithms a caller needs:

```toml
[dependencies]
reqsign-crypto-rustcrypto = { version = "1", default-features = false, features = ["p256"] }
```

Or install it process-wide before constructing contexts:

```rust
use reqsign_crypto_rustcrypto::RustCryptoProvider;

if RustCryptoProvider::install_default().is_err() {
    eprintln!("a process-wide crypto provider is already installed");
}
```

The facade's `default_context()` binds this provider when the `default-crypto`
feature is enabled and no process-wide provider is installed. The facade has no
algorithm features: it keeps the unconditional hash and HMAC operations and
weakly enables `p256` for `aws-v4a` and `rsa` for `azure`, `google`, `oracle`,
and `http-message-signatures`. A service feature without `default-crypto` does
not pull this backend.

See [CryptoProvider][contract] for the provider contract, resolution order, and
error semantics.

[provider]: https://docs.rs/reqsign-core/latest/reqsign_core/crypto/trait.CryptoProvider.html
[contract]: https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md

## License

Licensed under the Apache License, Version 2.0.
