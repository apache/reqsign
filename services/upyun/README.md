# reqsign-upyun

Upyun REST API request signing implementation for reqsign.

The signer adds the Upyun `Date` and `Authorization` headers. The signature
covers the request method, wire path, `Date`, and the `Content-MD5` header when
the caller already set it. Request construction, bucket selection, endpoint
selection, and transport remain with the caller.

> Signing needs a `CryptoProvider` resolved through the `Context`: bind one with
> `Context::with_crypto`, install a process-wide default, or use a facade
> `default_context()` (which binds RustCrypto when the global slot is empty). A
> bare `Context::new()` starts unbound. Upyun signing needs the provider's
> optional MD5 operation and its HMAC-SHA1 operation. A provider that does not
> support MD5, such as a FIPS-restricted backend, fails with `ConfigInvalid`
> instead of falling back. See
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

## Quick Start

```rust,no_run
use reqsign_core::{Context, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_upyun::{RequestSigner, StaticCredentialProvider};

# async fn example() -> reqsign_core::Result<()> {
let ctx = Context::new().with_crypto(RustCryptoProvider::new());
let signer = Signer::new(
    ctx,
    StaticCredentialProvider::new("operator", "password"),
    RequestSigner::new(),
);

let mut req = http::Request::put("https://v0.api.upyun.com/bucket/object.txt")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

Set `Content-MD5` on the request before signing when the request body should be
covered by the signature:

```rust,no_run
# use http::Request;
let mut req = Request::put("https://v0.api.upyun.com/bucket/object.txt")
    .header("content-md5", "7ac66c0f148de9519b8bd264312c4d64")
    .body(())
    .unwrap()
    .into_parts()
    .0;
```

## Credential Sources

`StaticCredentialProvider` uses an operator name and password supplied by the
caller.

`UpxConfigCredentialProvider` reads the active session from the Upyun CLI
(`upx`) configuration file at `~/.upx.cfg`. The provider uses the session
selected by `user_idx`; a missing file, an unset or invalid index, or an
incomplete session returns no credential. Use `with_config_file` to isolate a
different configuration file.

`DefaultCredentialProvider` uses the Upyun CLI configuration by default. Use
`push_front` to install explicit credentials or another source:

```rust,no_run
use reqsign_upyun::{DefaultCredentialProvider, StaticCredentialProvider};

let provider = DefaultCredentialProvider::new()
    .push_front(StaticCredentialProvider::new("operator", "password"));
```

## Contract

- Only header authentication is implemented. `expires_in` is ignored.
- The signer signs the wire path without decoding or rebuilding it.
- The signer does not calculate the body MD5 or construct requests.
- Signing is atomic: on error, the request URI and headers remain unchanged.
- `Debug` output redacts the credential secret.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
