# reqsign-volcengine-tos

Volcengine Object Storage request signing implementation for reqsign.

This crate supports both header authentication and presigned query
authentication. Its default credential provider reads credentials from the
environment.

## STS AssumeRole

`AssumeRoleGrant` and `AssumeRoleGranter` consume an existing Volcengine
credential and issue a temporary TOS credential with the exact STS
`ExpiredTime`. Install the granter explicitly through `reqsign_core::Granter`;
the default credential chain is unchanged.

## Changelog

- `Credential` now has an `expires_at` field for the absolute expiration
  returned by STS. `Credential::new` and `Credential::with_session_token` keep
  their previous behavior and leave expiration unset; use
  `Credential::with_expires_at` for temporary credentials constructed by hand.
- Adding `expires_at` breaks struct-literal construction. Callers that build
  `Credential` with a struct literal must switch to the constructors. The
  existing constructors remain available and keep their previous behavior.
- `RequestSigner` now enforces the credential's absolute expiration through the
  full presigned URL lifetime. Header signing continues to check the signing
  time.

> Signing needs a `CryptoProvider` resolved through the `Context`: bind one with
> `Context::with_crypto`, install a process-wide default, or use a facade
> `default_context()` (which binds RustCrypto when the global slot is empty). A
> bare `Context::new()` starts unbound. See
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

## Quick Start

```rust,no_run
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_volcengine_tos::{DefaultCredentialProvider, RequestSigner};

let context = Context::new().with_crypto(RustCryptoProvider::new()).with_env(OsEnv);
let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new("cn-beijing"),
);
```

Set `VOLCENGINE_ACCESS_KEY_ID` and `VOLCENGINE_SECRET_ACCESS_KEY`, and
optionally `VOLCENGINE_SESSION_TOKEN`. Use `StaticCredentialProvider` when the
credentials are supplied directly by an application.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
