# reqsign-crypto-boring

BoringSSL [`CryptoProvider`][provider] for Reqsign.

The provider implements every Reqsign crypto operation with BoringSSL's safe,
one-shot APIs. MD5 is available only when BoringSSL is not running in FIPS mode;
a FIPS build returns `ConfigInvalid` for MD5 instead of computing a digest that
the security policy excludes.

This crate is native-only and excluded from the Reqsign workspace, so the main
workspace stays pure Rust. Building it requires a C/C++ compiler and CMake.

## Quick Start

Bind the provider to one context:

```rust
use reqsign_core::Context;
use reqsign_crypto_boring::BoringCryptoProvider;

let ctx = Context::new().with_crypto(BoringCryptoProvider::new());
```

Or install it process-wide:

```rust
use reqsign_crypto_boring::BoringCryptoProvider;

if BoringCryptoProvider::install_default().is_err() {
    eprintln!("a process-wide crypto provider is already installed");
}
```

Enable the `fips` feature to forward to BoringSSL's FIPS build.

See [CryptoProvider][contract] for the provider contract, resolution order, and
error semantics.

[provider]: https://docs.rs/reqsign-core/latest/reqsign_core/crypto/trait.CryptoProvider.html
[contract]: https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md

## License

Licensed under the Apache License, Version 2.0.
