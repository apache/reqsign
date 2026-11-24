# reqsign-http-message-signatures

RFC 9421 HTTP Message Signatures for Reqsign request heads.

This crate implements the signing side of
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html). It emits
`Signature-Input` and `Signature` dictionary members with a caller-selected
label and ordered component list. Verification, response signing, multiple
signatures in one call, component parameters, `@request-target`, and body I/O
are outside this first version.

Algorithms come from the [`CryptoProvider`][provider] selected through the
`Context`: HMAC-SHA256 with raw key bytes, and RSASSA-PKCS1-v1_5 with SHA-256
using an unencrypted PKCS#1 or PKCS#8 PEM private key. The RustCrypto provider
supports RSA on native targets and returns `ConfigInvalid` for it on
`wasm32-unknown-unknown`.

## Quick Start

```rust
use http::header::HeaderName;
use reqsign_core::{Context, Result, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_http_message_signatures::{
    Component, Credential, RequestSigner, StaticCredentialProvider,
};

async fn sign_request() -> Result<()> {
    let credential = Credential::hmac_sha256("my-key", b"shared secret")?;
    let request_signer = RequestSigner::new(
        "sig1",
        [
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::Header(HeaderName::from_static("content-digest")),
        ],
    )?;

    let ctx = Context::new().with_crypto(RustCryptoProvider::new());
    let signer = Signer::new(
        ctx,
        StaticCredentialProvider::new(credential),
        request_signer,
    );

    let mut parts = http::Request::builder()
        .method("POST")
        .uri("https://example.com/upload?part=1")
        .header("content-digest", "sha-256=:...:")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut parts, None).await?;
    Ok(())
}
```

The URI must be absolute and use HTTP or HTTPS. Existing percent escapes, query
order, and repeated query parameters are preserved. A present `Host` header
must be unique and byte-identical to the URI authority.

## WASM

The crate compiles for `wasm32-unknown-unknown` and runs when hosted by a
JavaScript runtime through wasm-bindgen, such as a browser or Node. Jiff reads
the clock from that host; a bare WASM runtime without a JavaScript clock is not
supported. HMAC signing works on WASM; RSA signing requires a provider that
implements it there.

[provider]: https://docs.rs/reqsign-core/latest/reqsign_core/crypto/trait.CryptoProvider.html

## License

Licensed under the Apache License, Version 2.0.
