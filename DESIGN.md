# Architecture and Design

This document defines the architectural model, ownership boundaries, public API invariants, and design principles for Apache Reqsign. Subsystem specifications live in [docs/crypto-provider.md](docs/crypto-provider.md), [docs/default-credential-provider-api.md](docs/default-credential-provider-api.md), and [docs/caller-provided-subject-tokens.md](docs/caller-provided-subject-tokens.md); security boundaries and vulnerability triage live in [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md); caller-facing guides, provider inventories, and runnable examples live in [README.md](README.md), [website/docs/](website/docs/architecture.md), and API documentation.

## Scope and Ownership Boundaries

Reqsign separates cloud request authentication into explicit layers of ownership so each concern evolves at its own boundary:

| Boundary | Owns | Excludes |
| :------- | :--- | :------- |
| Host applications (e.g. OpenDAL, Lance) | End-user authentication and authorization, endpoint/region/bucket policy, business request construction, HTTP transport lifecycle, and retry/backoff policy | Re-implementing cloud credential chains, token exchanges, or request canonicalization |
| `reqsign-core` | Runtime-agnostic traits (`ProvideCredential`, `SignRequest`, `GrantCredential`, `SigningCredential`, `CryptoProvider`, I/O traits), `Context`, `Signer`, `Granter`, `SigningRequest`, `Error`, and `Timestamp` | Cloud wire protocols, concrete crypto backends, concrete HTTP/file/command runtimes, and JWT or service framing |
| Runtime adapters (`context/*`) | Concrete `FileRead`, `HttpSend`, and `CommandExecute` adapters for specific runtimes | Signing protocols, credential semantics, and default chains |
| Crypto providers (`crypto/*`) | Concrete `CryptoProvider` implementations (`rustcrypto`, `boring`) behind byte-oriented trait methods | Protocol-specific framing (JWT, SigV4 KDF, SAS) and hidden process-global installation |
| Services (`services/*`) | Provider-specific credential types, credential loaders, default chains, config/profile parsing, canonicalization, request signing, credential granting, and shared protocol crates (e.g. `aws-core`, `oauth2`) | Core lifecycle orchestration, built-in crypto backends, and host-specific option mapping or fallback policy |
| `reqsign` facade | Re-exporting crates behind service and runtime features, `default_context()`, and per-service `default_signer()` wiring | Core contracts, signing algorithms, and algorithm-level feature flags |

- Promote behavior to `reqsign-core` only when multiple services share an observable contract—inputs, outputs, lifetime, and failure semantics. Code shared only by a single provider family (such as AWS credential parsing and SigV4/SigV4a canonicalization) belongs in a shared service crate (`aws-core`), not in `reqsign-core`.
- Keep `Credential`, `RequestSigner`, and configuration types service-specific by design. The differences across SigV4, Shared Key, OAuth, and bearer tokens are protocol facts; what stays uniform across services is the composition shape.
- Reading shared cloud configuration (such as AWS profiles or region discovery) must stay side-effect free with respect to credential resolution—it must not execute a credential process or contact instance metadata endpoints.
- Assign every concern to the narrowest boundary that owns it. `reqsign-core` and supported services remain compilable for `wasm32-unknown-unknown` through `MaybeSend` futures and trait-injected capabilities rather than native OS assumptions.

## Core Primitives and Composition Topology

Reqsign models credential discovery, exchange, granting, and request signing through six orthogonal primitives:

| Primitive | Question Answered | Representation |
| :-------- | :---------------- | :------------- |
| `Context` | Where do runtime I/O, environment, process execution, and cryptography come from? | Cheap `Clone`, `Send + Sync` bundle of trait objects (`FileRead`, `HttpSend`, `Env`, `CommandExecute`, optional `CryptoProvider`) |
| `SigningCredential` | What authentication material is produced, and when is it usable? | Service-owned `Clone + Debug + Send + Sync + Unpin + 'static` value separating cache freshness (`is_valid`) from exact deadline usability (`is_valid_at`) |
| `ProvideCredential` / `ProvideCredentialChain` | How is a credential discovered or exchanged? | Async trait erased once at `ProvideCredentialDyn`; ordered chain probes sources sequentially |
| `SignRequest` | How is a wire-ready HTTP request authenticated for a service? | Async trait erased once at `SignRequestDyn`, declaring an operation deadline (`required_valid_until`) and mutating the request head |
| `GrantCredential` | How does a source credential issue an independently usable, bounded credential? | Async trait erased once at `GrantCredentialDyn` binding service-specific resource and permission scope in the granter type |
| `Signer<K>` / `Granter<K>` | What handle do applications hold and share to sign requests or issue credentials? | Cheap `Clone`, `Send + Sync` orchestrators owning `Context`, source provider, operation, and credential cache |

- Every core async trait has a `*Dyn` counterpart with a blanket implementation and `Arc<T>` forwarding, keeping backends concrete while erasing types once inside `Signer` and `Granter` and preserving `MaybeSend` compatibility for WASM.
- `Context::new()` and `Context::default()` wire no-op stubs for file reads, HTTP sends, environment access, and command execution, and leave cryptography unbound. Ambient access is always opt-in via explicit adapters or the facade's `default_context()`.
- `CryptoProvider` is a byte-oriented, stateless, concurrently callable trait. `Context` resolves cryptography in fixed order: explicit `Context::with_crypto` binding, then process-wide registration (`reqsign_core::crypto::install_default`), then `ErrorKind::ConfigInvalid`. `default_context()` binds the default RustCrypto provider to that context only when no global provider is installed, and never mutates process-wide registration. Embedding middleware must leave global installation to the application (see [docs/crypto-provider.md](docs/crypto-provider.md)).
- `Signer::clone()` and `Granter::clone()` share their underlying credential cache. `with_context()` and `with_credential_provider()` must create an isolated empty cache so credentials never leak across contexts or identities, while `with_request_signer()` and `with_credential_granter()` retain the source credential cache.

## Credential Lifecycle, Caching, and Granting

- Separate cache freshness from fitness for the current operation. `SigningCredential::is_valid()` answers whether a cached credential is still fresh and may include a proactive refresh window; `SigningCredential::is_valid_at(ts)` answers whether the credential is strictly valid at `ts` with no refresh buffer.
- Services define the operation deadline via `required_valid_until`: an AWS presigned URL requires a temporary credential covering the entire presign window, whereas a Google OAuth token used for IAM `signBlob` only needs to cover that RPC.
- `Signer` reads warm cached credentials without awaiting by borrowing an `Arc<K>` snapshot, avoiding per-sign cloning. Refreshes serialize behind an async refresh lock. A caller waiting behind an in-flight refresh may reuse a newly published snapshot only if it differs from what the caller observed before waiting and satisfies its own operation deadline; a stale snapshot observed before waiting is never reused.
- A freshly loaded credential only needs to satisfy the exact operation deadline (`is_valid_at(required_until)`), allowing short-lived credentials inside their proactive refresh window to authorize the current operation. If it fails that check, return `ErrorKind::CredentialInvalid`.
- When the request URI itself depends on fields of the credential, callers acquire the credential via `Signer::credential_for`, build the URI, and sign via `Signer::sign_with_credential`. `sign_with_credential` never loads, refreshes, or mutates the cache and checks only exact deadline usability.
- `Granter` caches only the source credential. Every `Granter::grant` call invokes the service granter and validates the returned credential after granting I/O completes; granted credentials are never cached or written back into the source cache and must own material independent of the source credential. Core makes no universal claim that every grant narrows permissions (for example, AWS `AssumeRole` can cross authority domains); scope and permission bounds live in the service granter type.
- Caller-provided subject tokens (such as incoming OIDC assertions) remain opaque to Reqsign, are validated locally against any caller-supplied absolute expiration before exchange I/O, and never join a default credential chain. Independently authenticated identities must use separate providers and `Signer` instances to isolate cached credentials (see [docs/caller-provided-subject-tokens.md](docs/caller-provided-subject-tokens.md)).

## Request Wire Semantics and Signing Contracts

- `SignRequest` accepts a wire-ready `http::request::Parts`: the URI must include an authority, and path and query components must already be percent-encoded exactly once by the caller. Signers derive canonical bytes locally and never decode-and-rewrite or double-encode the caller's path or query, preserving encoded separators, repeated keys, and key order. Query-signing implementations construct the final URI directly from the original wire URI.
- `SigningRequest` is a read-only canonicalization view and staged header buffer, not a wire URI builder. Committing `SigningRequest` writes headers only.
- Request mutation is atomic at the signing boundary. `Signer::sign` executes the service signer against a private candidate copy: on `Err`, `http::request::Parts` remains unchanged; on `Ok`, only `uri` and `headers` are committed while `method`, `version`, and `extensions` stay caller-owned and request bodies are never touched. `SignRequest` implementations must uphold the same contract for direct callers.
- `expires_in` is a service-specific validity input, not a universal header-versus-query mode switch—each service defines whether it selects presigning, bounds credential validity, is ignored, or is rejected. Three invariants hold everywhere: the credential used must cover the required window, exceeding a provider maximum fails explicitly instead of truncating silently, and `expires_in` never shortens a credential's own lifetime nor implies non-expiring artifacts when `None`.

## Public API Grammar and Provider Discipline

- Keep defaults ergonomic and explicit choices authoritative. Assemble default runtimes and credential chains at facade or service entry points, and preserve caller-supplied I/O and provider choices through every composition step—for example, applying an AWS profile after `.no_sso()` must keep SSO disabled.
- Export `DefaultCredentialProvider` and `DefaultCredentialProviderBuilder` only when a service has at least one documented ambient or automatic credential source (environment variables, profiles or well-known files, CLI sessions, or instance metadata). Services whose documented sources require explicit caller input must not export empty default providers.
- Every exported `DefaultCredentialProvider` exposes one uniform surface (`new`, `default`, `builder`, `with_chain`, `push_front`), and its builder exposes symmetric per-slot controls (`.<slot>(provider)` and `.no_<slot>()`). Never introduce `configure_*` patch methods, `disable_*(bool)` toggles, or `build()`-time fallback re-enabling of removed slots (see [docs/default-credential-provider-api.md](docs/default-credential-provider-api.md)).
- The `reqsign` facade exposes no cryptographic algorithm features; each service feature weakly enables only the backend operations it actually requires (`rsa`, `p256`, `aes-gcm`). Keep one canonical API path per concern rather than parallel dialects.
- Match verification evidence to the claim: use fixed inputs to verify exact wire bytes and injected failures to verify mutation atomicity; claiming live coverage for a credential provider requires invoking that provider against the real identity endpoint or accepting its returned credential at the cloud service, rather than running signer tests with hand-built static credentials.

## Error Handling, Retry Boundaries, and Secret Safety

- `reqsign_core::Error` separates *what failed* (`ErrorKind`) from *whether retrying makes sense* (`is_retryable()`), while preserving the underlying `source` chain and structured non-secret operational context. `CommandExecute` adapters distinguish an unavailable command environment from an execution failure via `is_command_unavailable()`.
- `Signer` and `Granter` perform no internal retries and never fall back to a previously cached stale credential on refresh failure. Retry loops and backoff belong to the host application so nested retries do not amplify throttling.
- Separate multi-source discovery from direct execution: `ProvideCredentialChain` probes configured providers in order and continues past missing or failed entries, whereas direct provider calls, exhausted chains, and `SignRequest` or `GrantCredential` failures propagate errors directly.
- Secrets must never leak through formatting, logs, or errors. Credential types and sensitive intermediate views (such as `SigningRequest` query entries) implement `Debug` manually with redaction helpers (`Redact`); composite handles (`Signer`, `Granter`) print structure rather than contents; non-secret operational metadata (expirations, regions, provider names) remains inspectable.
- Treat presigned URLs and signed `Authorization` headers as secret-bearing capability material in any Reqsign-owned log, error, or `Debug` output. Security boundaries and vulnerability disclosure follow [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).
