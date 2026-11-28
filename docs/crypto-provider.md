<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# CryptoProvider API Design

This document defines the repository's authoritative public contract for
request-signing cryptography in reqsign 4.x. Implementations that do not match
this document are legacy debt; new work and reviews must follow it.

## Summary

Reqsign no longer links a cryptographic implementation into `reqsign-core` or
any `services/*` crate. Hashing, MACs, asymmetric signing, AES-GCM encryption,
and secure random generation are provided by a
`reqsign_core::crypto::CryptoProvider` resolved through the `Context` supplied
to each signer, granter, or credential provider.

The change is deliberately breaking: a context without a resolvable provider,
or a provider that does not implement a requested operation, returns
`ErrorKind::ConfigInvalid` instead of falling back to a bundled implementation.

Two provider crates ship with this design:

- `reqsign-crypto-rustcrypto`, a pure-Rust workspace member with
  `wasm32-unknown-unknown` support for its supported subset.
- `reqsign-crypto-boring`, an independent, native-only crate built on
  BoringSSL and excluded from the main workspace.

Both provider crates start at `1.0.0` and version independently from the core
and service lockstep line and from each other.

## Provider Contract

```rust
pub trait CryptoProvider: Debug + Send + Sync + 'static {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]>;
    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]>;
    fn md5(&self, input: &[u8]) -> Result<[u8; 16]>;
    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]>;
    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]>;
    fn hmac_sha512(&self, key: &[u8], input: &[u8]) -> Result<[u8; 64]>;

    fn rsa_pkcs1v15_sha256_sign(
        &self,
        private_key_pem: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>>;

    fn rsa_pss_sha256_sign(
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

`sha1`, `sha256`, `hmac_sha1`, and `hmac_sha256` are mandatory. All other
operations have default implementations that explicitly report unsupported
operations as `ConfigInvalid`. Adding an optional method does not require
changes to existing providers.

`CryptoProvider` has a blanket implementation for `Arc<T>` where
`T: CryptoProvider + ?Sized`. A caller that already holds an
`Arc<dyn CryptoProvider>` can pass it directly to `Context::with_crypto` or
`install_default`; there are no separate `with_crypto_arc` or
`install_default_arc` entry points. The implementation forwards every
operation, including optional methods, to the wrapped provider.

### Operation Semantics

- `sha1` and `sha256` return the digest as a fixed-width byte array.
- `md5` returns a 16-byte digest. MD5 is not collision resistant and exists
  only for legacy protocols such as Upyun's request signature. A provider that
  cannot offer MD5 for policy reasons returns `ConfigInvalid`.
- `hmac_sha1`, `hmac_sha256`, and `hmac_sha512` return the MAC as a fixed-width
  byte array. HMAC accepts keys of any length, including empty and
  longer-than-block keys.
- `rsa_pkcs1v15_sha256_sign` implements RSASSA-PKCS1-v1_5 with SHA-256. The key
  is an unencrypted PKCS#8 (`PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) PEM
  document. The result is the big-endian signature with the modulus width.
- `rsa_pss_sha256_sign` implements PS256 using RSASSA-PSS with SHA-256,
  MGF1 with SHA-256, and a fresh 32-byte salt. It accepts the same PEM
  encodings with a modulus of at least 2048 bits and returns a big-endian
  signature with the modulus width. [RFC 7518 §3.5](https://www.rfc-editor.org/rfc/rfc7518#section-3.5)
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

## Context Resolution

`Context` owns crypto resolution for all work performed through it:

```rust
impl Context {
    pub fn with_crypto(self, provider: impl CryptoProvider) -> Self;
    pub fn crypto_provider(&self) -> Result<&dyn CryptoProvider>;
}
```

`crypto_provider()` resolves in this order at the point of use:

1. the provider bound with `Context::with_crypto`;
2. the process-wide provider installed with
   `reqsign_core::crypto::install_default`;
3. otherwise `ErrorKind::ConfigInvalid`.

The order is fixed. Resolution does not fall through because a provider returns
an error or reports an operation as unsupported.

A context never installs or freezes the process-wide registration. Creating,
using, or cloning a context does not change `get_default()`. A context with an
explicit binding keeps that provider for its lifetime, including after a global
provider is installed later. An unbound context observes the current global
registration at the point of use. Cloning a context preserves its binding.

`Context::new()` starts without an explicit binding. Resolution may still find
a process-wide provider; otherwise portable core code must bind a provider on
the context or install a global one. The facade's `default_context()` binds
RustCrypto when the global slot is empty at construction, as described below.

## Global Registration

```rust
pub fn install_default(
    provider: impl CryptoProvider,
) -> std::result::Result<(), Arc<dyn CryptoProvider>>;

pub fn get_default() -> Option<&'static Arc<dyn CryptoProvider>>;
```

Global installation is optional and backed by
`OnceLock<Arc<dyn CryptoProvider>>`. It succeeds at most once per process.

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

Applications own the process-wide choice. A top-level application that wants a
global provider installs it before constructing facade contexts; contexts
created afterward use the global provider, while contexts that already bind
RustCrypto keep that binding. Integrating middleware, such as OpenDAL, must not
install a global provider on behalf of its users: doing so would take away the
application's choice and can race with the application's own initialization.

## Failure Semantics

| Condition | Error kind | Retryable |
| --- | --- | --- |
| No provider resolvable through the context | `ConfigInvalid` | no |
| Installed provider does not support the operation | `ConfigInvalid` | no |
| A backend feature for the operation is disabled | `ConfigInvalid` | no |
| Provider policy excludes the operation, such as MD5 in a FIPS build | `ConfigInvalid` | no |
| Unencrypted-key material is malformed, not RSA, out of range, or has an invalid AES key length | `CredentialInvalid` | no |
| Backend, FFI, allocator, or random-source failure | `Unexpected` | no |

`ConfigInvalid` is a configuration/ownership error, not a transient failure. A
caller that retries it without binding, installing, or changing a provider
cannot succeed. A feature-disabled operation names the missing backend feature
in its message, so the caller can enable it or choose another provider.
`CredentialInvalid` identifies key material supplied by the
caller or loaded from a credential source.

Reqsign must not panic when no provider resolves, an operation is unsupported,
or key material is malformed. Backends must use their fallible APIs rather than
unwrap backend errors.

## Core Helpers

`reqsign_core::hash` keeps its pure encoding helpers unchanged:

```rust
pub fn base64_encode(content: &[u8]) -> String;
pub fn base64_decode(content: &str) -> Result<Vec<u8>>;
```

The digest, MAC, and encoded digest/MAC helpers require an explicitly supplied
provider and return `Result`:

```rust
pub fn sha1(provider: &dyn CryptoProvider, content: &[u8]) -> Result<[u8; 20]>;
pub fn sha256(provider: &dyn CryptoProvider, content: &[u8]) -> Result<[u8; 32]>;
pub fn hmac_sha1(provider: &dyn CryptoProvider, key: &[u8], content: &[u8]) -> Result<[u8; 20]>;
pub fn hmac_sha256(provider: &dyn CryptoProvider, key: &[u8], content: &[u8]) -> Result<[u8; 32]>;
pub fn hex_sha1(provider: &dyn CryptoProvider, content: &[u8]) -> Result<String>;
pub fn hex_sha256(provider: &dyn CryptoProvider, content: &[u8]) -> Result<String>;
pub fn hex_hmac_sha1(provider: &dyn CryptoProvider, key: &[u8], content: &[u8]) -> Result<String>;
pub fn hex_hmac_sha256(provider: &dyn CryptoProvider, key: &[u8], content: &[u8]) -> Result<String>;
pub fn base64_hmac_sha1(provider: &dyn CryptoProvider, key: &[u8], content: &[u8]) -> Result<String>;
pub fn base64_hmac_sha256(provider: &dyn CryptoProvider, key: &[u8], content: &[u8]) -> Result<String>;
```

Callers with a `Context` pass `ctx.crypto_provider()?`. These helpers never
perform a context or global lookup themselves, so they cannot silently bypass
the caller's selected provider.

`reqsign-core` has no JWT module or `jwt` feature. Azure and Google own their
compact JWS headers and claims and use the resolved provider to sign. Azure
client-certificate authentication defaults to PS256 with `x5t#S256` and uses
`CryptoProvider::rsa_pss_sha256_sign`. A custom provider must implement this
operation to use the default assertion. `with_legacy_rs256()` selects the
RS256 assertion with `x5t` explicitly and uses
`CryptoProvider::rsa_pkcs1v15_sha256_sign`, which Google service-account
exchanges also use.

Standalone public crypto entry points follow the same rule. For example,
Azure Storage's `ServiceSharedAccessSignature::token` takes
`&dyn CryptoProvider`; callers resolve it from their context.

## Official Providers

### `reqsign-crypto-rustcrypto`

Location: `crypto/rustcrypto`. Workspace member. It has its own independent
version line, starting at `1.0.0`.

`RustCryptoProvider::new()`, `Default`, and
`RustCryptoProvider::install_default()` are the public entry points.

MD5, SHA-1, SHA-256, HMAC-SHA-1/256/512 are unconditional. The remaining
operations are selected by three additive features, all enabled by default:

| Feature | Default | Operation | Native | `wasm32-unknown-unknown` |
| --- | --- | --- | --- | --- |
| — | — | MD5, SHA-1, SHA-256, HMAC-SHA-1/256/512 | yes | yes |
| `p256` | yes | ECDSA P-256 with SHA-256 | yes | yes |
| `rsa` | yes | RSA PKCS#1 v1.5 and RSA-PSS with SHA-256 | yes | unsupported (`ConfigInvalid`) |
| `aes-gcm` | yes | AES-128/256-GCM | yes | unsupported (`ConfigInvalid`) |
| `aes-gcm` | yes | Secure random bytes (via `getrandom`) | yes | unsupported (`ConfigInvalid`) |

When a feature is disabled, its operations return `ConfigInvalid` and name the
missing feature. When a native-only feature is enabled on `wasm32`, the
operation keeps returning `ConfigInvalid` with a target-specific message. The
`aes-gcm` feature also enables `getrandom`; there is no separate random feature.

Consumers that only need hashes and MACs set `default-features = false`. The
facade does this and weakly enables only the algorithms selected by its service
features.

Native RSA signing accepts PKCS#8 and PKCS#1 PEM and uses OS randomness for
blinding and PSS salts. The WASM subset matches the services reqsign supports on
`wasm32-unknown-unknown` and avoids requiring a JavaScript random source.

### `reqsign-crypto-boring`

Location: `crypto/boring`. Excluded from the root workspace so the main
workspace, `--all-features`, Windows/macOS builds, WASM builds, and release
planning never require CMake or a C/C++ toolchain.

`BoringCryptoProvider::new()`, `Default`, and
`BoringCryptoProvider::install_default()` are the public entry points. The
provider implements the operations through safe, stateless BoringSSL calls
and contains no `unsafe` code. The optional `fips` feature forwards to
`boring/fips`.

When BoringSSL runs in FIPS mode, `md5` returns `ConfigInvalid` because FIPS
does not approve MD5. The provider does not fall back to a non-FIPS MD5
implementation. SHA-512 and HMAC-SHA-512 remain available.

The crate has an independent version cadence (`1.0.0` initially) and is
verified by `.github/workflows/crypto_boring.yml`. It is excluded from
`cargo publish --workspace`; the release plan carries it as an explicit
standalone manifest entry (`crypto/boring/Cargo.toml`), and the release
workflow publishes it by manifest path after `reqsign-core`.

## Facade and Features

The `reqsign` facade adds:

```toml
default = ["default-context", "default-crypto"]
default-crypto = ["dep:reqsign-crypto-rustcrypto"]
```

The facade has no algorithm features. Its workspace dependency on the backend
sets `default-features = false`, and service features weakly enable only the
operations those services need:

```toml
aws-v4a = ["dep:reqsign-aws-v4a", "reqsign-crypto-rustcrypto?/p256"]
azure = ["dep:reqsign-azure-storage", "reqsign-crypto-rustcrypto?/rsa"]
google = ["dep:reqsign-google", "reqsign-crypto-rustcrypto?/rsa"]
oracle = ["dep:reqsign-oracle", "reqsign-crypto-rustcrypto?/rsa"]
http-message-signatures = [
  "dep:reqsign-http-message-signatures",
  "reqsign-crypto-rustcrypto?/rsa",
]
```

The weak `?` mapping enables the algorithm only when `default-crypto` has
already pulled the backend. A service feature without `default-crypto` does not
pull the backend. With `default-crypto`, `aws-v4a` selects `p256`; `azure`,
`google`, `oracle`, and `http-message-signatures` select `rsa`; every other
service feature uses only the unconditional hash and HMAC operations. `full`
selects `rsa` and `p256`, not `aes-gcm`. There is no facade feature for
`aes-gcm` or for client-side Google Credential Access Boundary generation.
Enabling `reqsign-google/credential-access-boundary-client-side` directly adds
the API. If the same graph also enables the facade `google` feature, Cargo
unifies features on the single `reqsign-google` package, so facade re-exports
can still expose the type; that is feature unification, not a facade feature.
Bind a provider that supports AES-GCM and secure random generation, and supply
an `HttpSend` transport for the STS exchange.

`default-crypto` re-exports `RustCryptoProvider`. When it is enabled,
`default_context()` checks the process-wide registration at construction. If
the slot is empty it binds `RustCryptoProvider` with `with_crypto`; if a global
provider is already installed it leaves the context unbound so the global
provider is used. It never writes the process-wide slot.

Without `default-crypto`, `default_context()` resolves a provider only from an
explicit binding or a process-wide installation. `Context::new()` starts
unbound.

The facade's per-service `default_signer(...)` helpers take the caller-supplied
`Context` as their first argument. Passing `default_context()` inherits the
conditional RustCrypto binding described above; passing a custom context keeps
that context's explicit or global provider selection. The signer owns the
context, and replacing it with `Signer::with_context` also isolates the
credential cache.

Applications that select a different backend disable `default-crypto` and take
the backend crate directly. Applications that use only hashing can provide
their own minimal `CryptoProvider`.

## Migration

### Applications and bare core users

Facade users can construct a context with `default_context()` and pass it to a
per-service `default_signer(...)` without installing anything. To select one
provider for the whole application, install it once before constructing facade
contexts; contexts that were already bound to RustCrypto keep their binding:

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
global provider. To keep a provider local, bind it with
`Context::new().with_crypto(provider)` instead. Applications that intentionally
compose several libraries should settle the global choice before any of them
loads credentials.

Bare `reqsign-core` users must provide a provider through the context or install
a global one before signing. Hash helpers take the provider directly; service JWT formatting
also uses the selected provider, with no implicit lookup.

The generic credential chain continues past provider errors and returns
`Ok(None)` when every source is exhausted; services that select an identity
before loading, such as AWS SSO, propagate that identity's errors instead. A
context without a provider found through the generic chain can therefore surface
as credential absence, and `Signer::sign` reports `CredentialInvalid` ("failed
to load signing credential") with the request unchanged. This preserves the
existing chain and `Ok(None)` contract; a missing-provider `ConfigInvalid` is
visible only outside the chain, which reports credential absence instead.

Chain fall-through is deliberate discovery: a source that returns an error is
treated as unavailable so a later source can supply the credential. When one
provider is the intended credential source, pass it directly to `Signer::new`
instead of wrapping it in a chain; its error, including `ConfigInvalid` from a
missing or unsupported provider, is then returned unchanged. Use
`ProvideCredentialChain` only when a failed source should be skipped in favor
of the next one.

### Core and Service Crates

No crate outside `crypto/*` may declare a direct dependency on a raw
cryptographic implementation crate such as `sha1`, `sha2`, `hmac`, `rsa`,
`p256`, `aes-gcm`, `md-5`, `getrandom`, `boring`, `openssl`, `ring`, or
`aws-lc-rs`.
This applies to `[dependencies]`, `[dev-dependencies]`, and
`[build-dependencies]`, including target-specific tables, renamed packages, and
`[workspace.dependencies]` entries in any repo-local workspace. Provider crates
such as `reqsign-crypto-rustcrypto` remain permitted as dependencies and
dev-dependencies. Encoding (`base64`, `hex`), PEM parsing (`pem`), secret
zeroization (`zeroize`), and interoperability reference harnesses such as
`aws-sigv4` remain ordinary dependencies where needed. Backend crates under
`crypto/*` own primitive verification and cross-backend parity.

All former hash and MAC call sites propagate `?` and resolve the provider from
the `Context` supplied to the signing, granting, or credential-loading entry
point. Public signing, granting, and credential entry points already return
`Result`, so this changes error propagation but not their success contracts.
AWS SigV4/SigV4a, Azure Storage SAS and Shared Key, Google signed URLs and CAB
tokens, Oracle, Aliyun OSS, Huawei Cloud OBS, Tencent COS, and Volcengine TOS
keep their existing canonicalization and encodings.

Notable service-specific details:

- AWS SigV4a derives the P-256 scalar in pure Rust, keeps the scalar in
  `Zeroizing<[u8; 32]>`, and performs the fixed-width range check against
  `n - 2` before incrementing. The signature is still DER-encoded hex.
- `azure-storage` loads the certificate and key PEM and builds the client
  assertion. It uses the provider's SHA-256 for `x5t#S256` and SHA-1 for `x5t`
  when the caller selects legacy RS256. In both cases it hashes the first
  certificate's DER bytes.
- Azure `ServiceSharedAccessSignature::token` takes the resolved provider.
- Google service-account signing encodes the provider's RSA signature as hex;
  its private JWT helper is shared by the signer and service-account token
  provider. Client-side credential access boundary encryption uses AES-GCM
  through the provider and gets its nonce from `fill_random`. Malformed
  service-account key material returns `CredentialInvalid` while signing the
  exchange JWT.

### Backend feature selection

`reqsign-crypto-rustcrypto` keeps MD5, SHA-1, SHA-256, and the HMAC operations
unconditional. `rsa`, `p256`, and `aes-gcm` are additive features and all three
are enabled by default. A hash/HMAC-only caller disables default features:

```toml
[dependencies]
reqsign-crypto-rustcrypto = { version = "1", default-features = false }
```

A caller that only needs P-256 ECDSA selects that feature alone:

```toml
[dependencies]
reqsign-crypto-rustcrypto = { version = "1", default-features = false, features = ["p256"] }
```

Disabled operations return `ConfigInvalid` and name the missing feature. The
`aes-gcm` feature also enables `getrandom`; secure random generation is
therefore disabled when `aes-gcm` is disabled.

The facade disables backend defaults and weakly maps its service features:
`aws-v4a` selects `p256`; `azure`, `google`, `oracle`, and
`http-message-signatures` select `rsa`. Other services need only hashes and
HMACs. A service feature without `default-crypto` does not pull the backend.
The facade never exposes `rsa`, `p256`, or `aes-gcm` as features, and `full`
does not select `aes-gcm`.

Client-side Google Credential Access Boundary generation is no longer a facade
feature. Depend on `reqsign-google` with
`credential-access-boundary-client-side` and bind a provider that supports
AES-GCM and secure random generation, for example `RustCryptoProvider` with its
default `aes-gcm` feature.

### Removed APIs

- The facade's `google-credential-access-boundary-client-side` feature is
  removed. Use `reqsign-google` directly with
  `credential-access-boundary-client-side` and an AES-GCM-capable provider.
- The public `reqsign_core::jwt` module and `jwt` feature are removed. Azure
  and Google own their private JWS formatting and sign through the resolved
  provider.
- Hash and MAC helpers take `&dyn CryptoProvider` and return `Result`.
- `reqsign-core` no longer provides crypto implementations, so a context with no
  provider binding and no global provider fails with `ConfigInvalid` at the
  point of use.

## Verification

The repository verifies this contract with:

- Separate `reqsign-core` integration test binaries for the bare missing
  context, early global lookup, rejected second installation, concurrent
  installation, and context resolution priority. The priority test covers
  explicit priority over global and independent providers on distinct
  contexts. The `Arc<T>` forwarding impl is checked through generic dispatch and
  a separate global-installation test binary.
- Facade tests with and without `default-crypto`, including installation before
  and after context construction, OnceLock non-occupation, a default signer
  using its bound provider, and a signer whose explicitly selected provider is
  used.
- RustCrypto provider tests for published MD5, SHA-1, SHA-256, and
  HMAC-SHA-1/256/512 vectors, block-size key boundaries, PKCS#1 and PKCS#8 PEM
  signing with both RSA algorithms, AES-128/256-GCM with and without AAD, ECDSA verification, invalid scalars,
  invalid AES key lengths, random output, and unsupported-operation defaults.
- A backend feature matrix runs the provider tests with default features, no
  default features, each algorithm feature alone, and all three together. The
  no-feature and individual-feature cases assert `ConfigInvalid` messages that
  name the missing `rsa`, `p256`, or `aes-gcm` feature, including random
  generation. WASM checks cover the default, no-default, and per-feature
  combinations.
- A downstream facade probe builds and runs every service feature in its own
  Cargo invocation with `default-crypto`. It exercises the actual RSA, P-256,
  AES-GCM, random, hash, and HMAC operations, verifies that `aws-v4a` selects
  P-256 and `azure`, `google`, `oracle`, and `http-message-signatures` select
  RSA, and confirms every other service remains hash/HMAC-only. The same probe
  checks that each service feature alone does not pull the backend.
- Google's client-side Credential Access Boundary tests run with the direct
  `reqsign-google` feature; its dev-dependency enables the RustCrypto `rsa` and
  `aes-gcm` operations. A runnable rustdoc example drives `Granter::grant(None)`
  against a mock STS with only the `aes-gcm` backend feature.
- BoringSSL parity tests against `reqsign-crypto-rustcrypto` for byte-identical
  hashes, HMACs, RS256 signatures, and AES-GCM output, plus PS256 and ECDSA
  verification, MD5 availability outside FIPS and `ConfigInvalid` in FIPS mode;
  error-kind checks; and an AWS SigV4 end-to-end signing test with an explicit
  BoringSSL context.
- A per-root `cargo tree --all-features --target all --edges normal` check
  confirms that no core or service production graph contains a cryptographic
  implementation crate, without workspace feature unification hiding optional
  paths.
- A manifest check rejects direct cryptographic implementation dependencies
  outside `crypto/*` in every dependency kind, including target-specific and
  renamed declarations, and rejects unused entries in any repo-local
  `[workspace.dependencies]`.
- `cargo check -p reqsign-crypto-rustcrypto --target wasm32-unknown-unknown`,
  the workspace test suite, doc tests, formatting, clippy with `-D warnings`,
  license headers, the standalone BoringSSL workflow, and the website provider
  catalog validator.
