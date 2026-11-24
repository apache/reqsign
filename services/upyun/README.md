# reqsign-upyun

Upyun REST API request signing implementation for reqsign.

The signer adds the Upyun `Date` and `Authorization` headers. The signature
covers the request method, wire URI, `Date`, and the `Content-MD5` header when
the caller already set it. The wire URI is the request path plus the raw query
string when one is present. The signed URI is the wire path and raw query
exactly as supplied: the signer does not decode, normalize, reorder, or rebuild
them, and makes no claim about path rewriting by a proxy or server. Request
construction, bucket selection, endpoint selection, and transport remain with
the caller.

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

`StaticCredentialProvider` uses a operator name and password supplied by the
caller.

`UpxConfigCredentialProvider` reads the Upyun CLI (`upx`) configuration file
at `~/.upx.cfg`. The file has one session per bucket and operator pair. Without
extra configuration, the provider returns the session selected by `user_idx`,
which is the CLI's current bucket session. Use `with_bucket` to select the
session for a specific bucket: a matching current session is preferred, then
the first session for that bucket is used. The file has no account or endpoint
scope beyond the bucket. A missing file, no matching session, or an incomplete
session returns no credential. The discovered credential carries the selected
session's bucket. For every signature, the first segment of the request's wire
path must exactly equal that CLI session bucket; otherwise signing fails,
including when a cached credential is reused. This is a local check of the
request target and does not assume server-side path rewriting. Use
`with_config_file` to isolate a different configuration file.

`DefaultCredentialProvider` uses the Upyun CLI configuration by default. The
facade `default_signer(ctx, bucket)` therefore selects the CLI session for the
request's bucket. Use `push_front` to install explicit credentials or another
source:

```rust,no_run
use reqsign_upyun::{DefaultCredentialProvider, StaticCredentialProvider};

let provider = DefaultCredentialProvider::new()
    .push_front(StaticCredentialProvider::new("operator", "password"));
```

The default source and prepended providers fail closed: a provider error is
returned instead of falling through to a lower-priority source.

## Contract

- Only header authentication is implemented. `expires_in` is ignored.
- Discovered CLI credentials are scoped to their session bucket. The first
  segment of the request's wire path must exactly equal that bucket on every
  signature, including cache hits.
- Explicit static credentials are unscoped and keep the caller's chosen scope.
- The signed URI is the wire path and raw query exactly as supplied; the signer
  does not decode, reorder, or rebuild them and does not assume server-side path
  rewriting. Endpoints whose request target carries a query, such as `?usage`
  and `?metadata=...`, are signed over that query.
- The signer does not calculate the body MD5 or construct requests.
- Signing is atomic: on error, the request URI and headers remain unchanged.
- `Debug` output redacts the credential secret, and the generated
  `Authorization` header is marked sensitive.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
