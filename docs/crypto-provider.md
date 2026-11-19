# CryptoProvider API Design

This document defines the repository's authoritative public contract for
request-signing cryptography in reqsign 4.x. Implementations that do not match
this document are legacy debt; new work and reviews must follow it.

## Summary

Reqsign no longer links a cryptographic implementation into `reqsign-core` or
any `services/*` crate. Hashing, MACs, asymmetric signing, AES-GCM encryption,
and secure random generation are provided by one process-wide
`reqsign_core::crypto::CryptoProvider` installed by the application at startup.

The change is deliberately breaking: a missing provider, or a provider that
does not implement a requested operation, returns
`ErrorKind::ConfigInvalid` instead of falling back to a bundled implementation.

Two provider crates ship with this design:

- `reqsign-crypto-rustcrypto`, a pure-Rust workspace member with
  `wasm32-unknown-unknown` support for its supported subset.
- `reqsign-crypto-boring`, an independent, native-only crate built on
  BoringSSL and excluded from the main workspace.

## Provider Contract

```rust
pub trait CryptoProvider: Debug + Send + Sync + 'static {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]>;
    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]>;
    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]>;
    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]>;

    fn rsa_pkcs1v15_sha256_sign(
        &self,
        private_key_pem: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>>;

    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>>;

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>>;

    fn fill_random(&self, dest: &mut [u8]) -> Result<()>;
}
```

The four hash/MAC methods are mandatory. The remaining four have default
implementations that return `ConfigInvalid`, so a minimal provider remains
useful for services that only need hashing.

### Operation Semantics

- `sha1` and `sha256` return the digest as a fixed-width byte array.
- `hmac_sha1` and `hmac_sha256` return the MAC as a fixed-width byte array.
  HMAC accepts keys of any length, including empty and longer-than-block keys.
- `rsa_pkcs1v15_sha256_sign` implements RSASSA-PKCS1-v1_5 with SHA-256. The key
  is an unencrypted PKCS#8 (`PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) PEM
  document. The result is the big-endian signature with the modulus width.
- `ecdsa_p256_sha256_sign` implements ECDSA over NIST P-256 with SHA-256. The
  scalar is the big-endian 32-byte private key in `1 <= d < n`. The result is an
  ASN.1 DER signature.
- `aes_gcm_encrypt` implements AES-128-GCM for a 16-byte key and AES-256-GCM for
  a 32-byte key. The nonce is exactly 12 bytes. AAD is authenticated and not
  encrypted. The result is `ciphertext || 16-byte authentication tag`.
- `fill_random` fills the complete destination with bytes from a
  cryptographically secure random source.

Implementations must allow concurrent calls and must not share mutable
per-call state between invocations. A provider may keep immutable configuration,
but it must not be required to serialize signing operations for correctness.

## Registration

```rust
pub fn install_default(
    provider: impl CryptoProvider,
) -> std::result::Result<(), Arc<dyn CryptoProvider>>;

pub fn get_default() -> Option<&'static Arc<dyn CryptoProvider>>;
```

Installation is backed by `OnceLock<Arc<dyn CryptoProvider>>` and succeeds at
most once per process.

- The first successful call installs the provider.
- A later call leaves the first provider installed and returns the rejected
  provider inside `Err`.
- Concurrent calls are safe: exactly one caller wins and every other caller
  receives `Err`.
- Installation is not idempotent: a repeated call is rejected rather than
  succeeding as a no-op.
- `get_default()` only reads the current value. Calling it before installation
  returns `None` and does not freeze the unset state; a later
  `install_default()` still succeeds.
- Reqsign never installs a provider implicitly and never falls back to a
  bundled implementation.

Applications own the choice of provider. Top-level binaries and services call
`install_default` once during startup. Integrating middleware, such as OpenDAL,
must not install a provider on behalf of its users: doing so would take away the
application's choice and can race with the application's own initialization.
Middleware should document the requirement and let the application fail with a
clear `ConfigInvalid` error if it has not installed one.

## Failure Semantics

| Condition | Error kind | Retryable |
| --- | --- | --- |
| No provider installed | `ConfigInvalid` | no |
| Installed provider does not support the operation | `ConfigInvalid` | no |
| Unencrypted-key material is malformed, not RSA, out of range, or has an invalid AES key length | `CredentialInvalid` | no |
| Backend, FFI, allocator, or random-source failure | `Unexpected` | no |

`ConfigInvalid` is a configuration/ownership error, not a transient failure. A
caller that retries it without installing or changing a provider cannot
succeed. `CredentialInvalid` identifies key material supplied by the caller or
loaded from a credential source.

Reqsign must not panic when a provider is missing, an operation is unsupported,
or key material is malformed. Backends must use their fallible APIs rather than
unwrap backend errors.

## Core Helpers

`reqsign_core::hash` keeps its pure encoding helpers unchanged:

```rust
pub fn base64_encode(content: &[u8]) -> String;
pub fn base64_decode(content: &str) -> Result<Vec<u8>>;
```

The digest, MAC, and encoded digest/MAC helpers now return `Result` and delegate
to the installed provider:

```rust
pub fn sha1(content: &[u8]) -> Result<[u8; 20]>;
pub fn sha256(content: &[u8]) -> Result<[u8; 32]>;
pub fn hmac_sha1(key: &[u8], content: &[u8]) -> Result<[u8; 20]>;
pub fn hmac_sha256(key: &[u8], content: &[u8]) -> Result<[u8; 32]>;
pub fn hex_sha1(content: &[u8]) -> Result<String>;
pub fn hex_sha256(content: &[u8]) -> Result<String>;
pub fn hex_hmac_sha1(key: &[u8], content: &[u8]) -> Result<String>;
pub fn hex_hmac_sha256(key: &[u8], content: &[u8]) -> Result<String>;
pub fn base64_hmac_sha1(key: &[u8], content: &[u8]) -> Result<String>;
pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> Result<String>;
```

`reqsign_core::jwt` no longer exposes an `rsa` type. The typed
`encode_rs256(&H, &C, &RsaPrivateKey)` entry point is removed. The byte-based
entry point remains and delegates RSA signing to the provider:

```rust
pub fn encode_rs256_pem<H, C>(
    header: &H,
    claims: &C,
    private_key_pem: &[u8],
) -> Result<String>;
```

Enabling the `jwt` feature adds `serde` and `serde_json`; it does not add `rsa`
or any other cryptographic implementation.

## Official Providers

### `reqsign-crypto-rustcrypto`

Location: `crypto/rustcrypto`. Workspace member. Version follows the core
crate's lockstep line.

`RustCryptoProvider::new()`, `Default`, and
`RustCryptoProvider::install_default()` are the public entry points.

| Operation | Native | `wasm32-unknown-unknown` |
| --- | --- | --- |
| SHA-1, SHA-256, HMAC-SHA-1/256 | yes | yes |
| ECDSA P-256 with SHA-256 | yes | yes |
| RSA PKCS#1 v1.5 with SHA-256 | yes | unsupported (`ConfigInvalid`) |
| AES-128/256-GCM | yes | unsupported (`ConfigInvalid`) |
| Secure random bytes | yes | unsupported (`ConfigInvalid`) |

The native RSA path accepts PKCS#8 and PKCS#1 PEM and uses OS randomness for
blinding. The WASM subset matches the services reqsign supports on
`wasm32-unknown-unknown` and avoids requiring a JavaScript random source.

### `reqsign-crypto-boring`

Location: `crypto/boring`. Excluded from the root workspace so the main
workspace, `--all-features`, Windows/macOS builds, WASM builds, and release
planning never require CMake or a C/C++ toolchain.

`BoringCryptoProvider::new()`, `Default`, and
`BoringCryptoProvider::install_default()` are the public entry points. The
provider implements all eight operations through safe, stateless BoringSSL
calls and contains no `unsafe` code. The optional `fips` feature forwards to
`boring/fips`.

The crate has an independent version cadence (`0.1.0` initially), is verified by
`.github/workflows/crypto_boring.yml`, and is not published by
`cargo publish --workspace`.

## Facade and Features

The `reqsign` facade adds:

```toml
default = ["default-context", "default-crypto"]
default-crypto = ["dep:reqsign-crypto-rustcrypto"]
```

`default-crypto` re-exports `RustCryptoProvider`. It does not install it.
`default_context()` remains limited to runtime components (`FileRead`,
`HttpSend`, `Env`, `CommandExecute`) and never registers a crypto provider.

Applications that select a different backend disable `default-crypto` and take
the backend crate directly. Applications that use only hashing can provide
their own minimal `CryptoProvider`.

## Migration

### Applications

Install one provider once during startup, before constructing signers and before
any credential loading that may use cryptography. For example, AWS SSO computes
its cache key with SHA-1, Google service-account exchange signs a JWT, and Azure
client certificate authentication signs a client assertion while loading a
credential. Installing later can change a configuration error into credential
absence.

```rust
use reqsign::RustCryptoProvider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    RustCryptoProvider::install_default()
        .map_err(|_| "a CryptoProvider is already installed")?;

    // Build contexts, signers, granters, and clients here.
    Ok(())
}
```

A failure from `install_default` means another component already installed a
provider. Applications that intentionally compose several libraries should
install their chosen provider before any of them are initialized.

The generic credential chain continues past provider errors and returns
`Ok(None)` when every source is exhausted; services that select an identity
before loading, such as AWS SSO, propagate that identity's errors instead. A
missing provider found through the generic chain can therefore surface as
credential absence, and `Signer::sign` reports `CredentialInvalid` ("failed to
load signing credential") with the request unchanged. This preserves the
existing chain and `Ok(None)` contract; installing before credential loading is
what makes the missing-provider `ConfigInvalid` visible.

### Core and Service Crates

`reqsign-core` and every `services/*` crate have no production dependency on
`sha1`, `sha2`, `hmac`, `rsa`, `p256`, or `aes-gcm`. Those crates remain
permitted as `dev-dependencies` for verification. Encoding (`base64`, `hex`) and
secret zeroization (`zeroize`) remain ordinary dependencies where needed.

All former hash and MAC call sites propagate `?`. Public signing, granting, and
credential entry points already return `Result`, so this changes error
propagation but not their success contracts. On-wire formats are unchanged:
AWS SigV4/SigV4a, Azure Storage SAS/shared key/client certificate, Google
signed URLs and CAB tokens, Oracle, Aliyun OSS, Huawei Cloud OBS, Tencent COS,
and Volcengine TOS keep their existing canonicalization and encodings.

Notable service-specific details:

- AWS SigV4a derives the P-256 scalar in pure Rust, keeps the scalar in
  `Zeroizing<[u8; 32]>`, and performs the fixed-width range check against
  `n - 2` before incrementing. The signature is still DER-encoded hex.
- Azure client certificate authentication keeps the certificate/key PEM
  splitting in `azure-storage`; the thumbprint uses the provider's SHA-1 and the
  client assertion uses `jwt::encode_rs256_pem`.
- Google service-account signing encodes the provider's RSA signature as hex;
  client-side credential access boundary encryption uses AES-GCM through the
  provider and gets its nonce from `fill_random`. Malformed service-account key
  material returns `CredentialInvalid` while signing the exchange JWT.

### Removed APIs

- `reqsign_core::jwt::encode_rs256(&H, &C, &RsaPrivateKey)` is removed.
  Use `encode_rs256_pem` with PEM bytes.
- Hash and MAC helpers return `Result`.
- `reqsign-core` no longer provides crypto implementations, so a process that
  signs or hashes without installing a provider fails with `ConfigInvalid`.

## Verification

The repository verifies this contract with:

- Separate `reqsign-core` integration test binaries for the unset provider,
  early lookup, rejected second installation, and concurrent installation.
- RustCrypto provider tests for published hash/HMAC vectors, block-size key
  boundaries, both RSA PEM formats, AES-128/256-GCM with and without AAD,
  ECDSA verification, invalid scalars, invalid AES key lengths, random output,
  and unsupported-operation defaults.
- BoringSSL parity tests against `reqsign-crypto-rustcrypto` for byte-identical
  hashes, HMACs, RSA signatures, and AES-GCM output; cross-backend ECDSA
  verification; error-kind checks; and an AWS SigV4 end-to-end signing test.
- A per-root `cargo tree --all-features --target all --edges normal` check
  confirms that no core or service production graph contains a cryptographic
  implementation crate, without workspace feature unification hiding optional
  paths.
- `cargo check -p reqsign-crypto-rustcrypto --target wasm32-unknown-unknown`,
  the workspace test suite, doc tests, formatting, clippy with `-D warnings`,
  license headers, and the standalone BoringSSL workflow.
