# CLAUDE.md

## Project Overview

Apache Reqsign — a Rust library for signing HTTP API requests across
cloud providers (AWS, Azure, Cloudflare, Dropbox, GitHub, Google, OneDrive,
Aliyun, Huawei, Tencent, Oracle, Volcengine, Vercel, Yandex Disk).

## Architecture

The codebase is a Cargo workspace with three layers:

- **`core`** (`reqsign-core`): traits (`ProvideCredential`, `SignRequest`,
  `SigningCredential`) and the runtime-agnostic `Context` / `Signer` types.
- **`context/*`**: pluggable runtime adapters (`file-read-tokio`,
  `http-send-reqwest`, `command-execute-tokio`).
- **`services/*`**: per-cloud signing implementations, each its own crate.
  AWS support is split into shared credentials/canonicalization (`aws-core`),
  SigV4 (`aws-v4`), and SigV4a (`aws-v4a`).
- **`reqsign`**: facade crate re-exporting everything behind feature flags;
  provides `default_context()` and per-service `default_signer()`.

### Key Design Decisions

- **No default implementations in `Context`**: `Context::new()` wires up
  no-op stubs. Users (or `default_context()`) must explicitly plug in
  `FileRead`, `HttpSend`, `Env`, `CommandExecute`.
- **`MaybeSend` futures**: core traits use `MaybeSend` instead of `async_trait`
  so that the crate compiles for `wasm32-unknown-unknown`.
- **Dyn-trait pairs**: every async trait `Foo` has a `FooDyn` counterpart and a
  blanket `impl FooDyn for T: Foo`, enabling `Arc<dyn FooDyn>` inside `Signer`.

## API Design References

Consult [DESIGN.md](DESIGN.md) as the living source of truth for Reqsign's
architectural model, ownership boundaries, core invariants, and public API
design principles before introducing public APIs, new services, or
cross-boundary changes, and update it when architectural invariants change.

When working on an API area with a dedicated subsystem design document, follow
that document as the source of truth instead of inferring policy from the
current implementation.

For security-sensitive changes, follow [SECURITY.md](SECURITY.md) and
[THREAT_MODEL.md](THREAT_MODEL.md) as the source of truth for Reqsign's
security boundary and its relationship to OpenDAL and other host applications.

### Crypto Provider

All signing cryptography goes through a `reqsign_core::crypto::CryptoProvider`
resolved by `Context` (explicit binding, then the process-wide registration).
`reqsign-core` and every `services/*` crate carry no production cryptographic
implementation. `reqsign-core` exposes no public JWT module or feature. Azure
and Google own their private JWS formatting. `reqsign-crypto-rustcrypto`
keeps hash and HMAC operations unconditional and exposes only the additive
`rsa`, `p256`, and `aes-gcm` features, all enabled by default. The facade has no
algorithm features; its service features weakly select only the backend
operations they need. Follow
[docs/crypto-provider.md](docs/crypto-provider.md) as the source of truth for
the provider contract, resolution and installation ownership, error semantics,
and the official RustCrypto/BoringSSL implementations.

### Default Credential Provider

All future refactors and API reviews around `DefaultCredentialProvider` must
follow the authoritative design in
[docs/default-credential-provider-api.md](docs/default-credential-provider-api.md).

Treat any future API change that reintroduces the following as a design
regression unless explicitly approved: `configure_*`, `disable_*(bool)`,
fallback-based re-enabling of removed slots during `build()`.

## Build & Test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --no-fail-fast            # unit tests
cargo test --doc --all-features --workspace  # doc tests
```

### Integration Tests

Integration tests live per-service under `services/<name>/tests/` and are gated
by `REQSIGN_<SERVICE>_TEST*` env vars. Secrets are loaded via 1Password Connect
in CI. Some providers (IMDS, ECS, SSO, Process, Cognito) use Python mock
servers checked into `services/aws-v4/tests/mocks/`.

## WASM Compatibility

`reqsign-core` and a subset of services (`aws-v4`, `aws-v4a`, `azure`,
`aliyun`, `aliyun-drive`, `b2`, `baidu-netdisk`, `tencent`, `cloudflare`,
`oauth2`, `dropbox`, `http-message-signatures`, `github`, `koofr`, `onedrive`,
`upyun`, `seafile`, `vercel`, `yandex-disk`) must compile for
`wasm32-unknown-unknown`. CI verifies this supported subset. GitHub environment,
static, and anonymous signing need no JavaScript clock; GitHub CLI discovery
still requires a `CommandExecute` adapter at runtime and is unavailable in bare
WASM runtimes. Cloudflare and Vercel environment, static, and header signing
need no JavaScript clock. Yandex Disk static credentials without an expiry and
header signing need no JavaScript clock; the shared OAuth 2.0 and Dropbox paths
need a JavaScript host clock.

## Versioning

- Established service crates and core share a lockstep major version
  (`4.0.0`): `reqsign-core`, `reqsign-aws-core`, every established
  `reqsign-<provider>` service crate, `reqsign-http-message-signatures`,
  `reqsign-file-read-tokio`, and `reqsign-command-execute-tokio`. A breaking
  change in core bumps this whole line together.
- Provider and shared crates (`reqsign-b2`, `reqsign-aliyun-drive`,
  `reqsign-baidu-netdisk`, `reqsign-cloudflare`, `reqsign-dropbox`,
  `reqsign-github`, `reqsign-koofr`, `reqsign-oauth2`, `reqsign-onedrive`,
  `reqsign-seafile`, `reqsign-upyun`, `reqsign-vercel`, `reqsign-yandex-disk`)
  start independent `1.0.0` version lines and depend on the current core major.
- `reqsign-http-send-reqwest` has its own major (`5.0.0`), one major ahead of
  the core lockstep. It moves when the core lockstep major changes, so a
  reqwest major bump never forces a core major.
- `reqsign-crypto-rustcrypto` and `reqsign-crypto-boring` each have independent
  version lines, starting at `1.0.0`.
- The facade `reqsign` crate follows an independent scheme (`0.21.0`).
- Release is triggered by pushing a `v*.*.*` tag. `plan.py` is the
  authoritative crates.io package set: the root workspace members plus the
  explicit standalone `crypto/boring/Cargo.toml` manifest. `cargo publish
  --workspace` covers the members; the release workflow publishes
  `reqsign-crypto-boring` by manifest path after `reqsign-core`. A workspace
  exclusion alone does not add a package to the plan.

## License

Apache-2.0 (ASF). All source files must carry the Apache header, enforced by
hawkeye via `licenserc.toml`.
