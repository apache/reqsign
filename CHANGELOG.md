# Apache Reqsign Changelog

Release notes for Apache Reqsign. The facade `reqsign` version names the
release; every other crate keeps its own line. Migration steps for the current
major are in
[Upgrading to Reqsign 0.21](website/docs/guides/upgrading-to-0.21.md).

## 0.21.0 - Unreleased

0.21 is a coordinated major for the core and the established service crates,
and the first crates.io release of the provider crates added since 0.20.8. It
moves cryptography out of the signing crates into a `CryptoProvider` selected
through the `Context`, passes the `Context` explicitly to facade
`default_signer` helpers, and raises the minimum supported Rust version to
1.87.

### Breaking changes

- **Cryptography is resolved through `Context`.** `reqsign-core` and every
  `services/*` crate no longer link SHA-1, SHA-256, HMAC, RSA, P-256, or
  AES-GCM. `Context::new()` starts unbound; a context without a provider, or a
  provider without the requested operation, fails with `ConfigInvalid`. Bind a
  provider with `Context::with_crypto`, install one process-wide with
  `reqsign_core::crypto::install_default`, or use the facade's
  `default_context()`, which binds `RustCryptoProvider` when no global provider
  is installed and the `default-crypto` feature is enabled.
- **`reqsign_core::jwt` is removed** together with the core `jwt` feature. Azure
  client-certificate and Google service-account flows format RS256 JWS in
  private service helpers through the selected provider. Hash and MAC helpers
  now take `&dyn CryptoProvider` and return `Result`; Azure
  `ServiceSharedAccessSignature::token` takes the resolved provider.
- **Facade `default_signer` takes the `Context` first.** For example
  `aws::default_signer(ctx, "s3", "us-east-1")`. The `default-context` feature
  no longer gates `DefaultSigner` or `default_signer`; both exist whenever the
  service feature is enabled.
- **`Signer::with_context` isolates the credential cache** instead of reusing
  the previous context's cached credential, because a different context can
  resolve a different identity. To replace only the signing or granting
  operation and keep the cache, use `Signer::with_request_signer` or
  `Granter::with_credential_granter`.
- **OBS and TOS `Credential` gained `expires_at`**, which breaks struct-literal
  construction. Use `Credential::new` plus `with_expires_at` (and
  `with_session_token` for TOS).

### Added

- Crypto backend crates `reqsign-crypto-rustcrypto` (workspace member,
  `wasm32-unknown-unknown` for its supported subset) and
  `reqsign-crypto-boring` (native-only, excluded from the main workspace and
  the workspace publish plan, optional `fips` feature), both `1.0.0`.
  `reqsign-crypto-boring` is included in the source release; it is not
  published to crates.io by this release, and publishing it requires a
  separate decision.
- Provider crates and facade features, all first release at `1.0.0`:
  `reqsign-aliyun-drive`, `reqsign-b2` (facade feature `b2`),
  `reqsign-baidu-netdisk`, `reqsign-cloudflare`, `reqsign-dropbox`,
  `reqsign-github`, `reqsign-koofr`, `reqsign-oauth2`, `reqsign-onedrive`,
  `reqsign-seafile`, `reqsign-upyun`, `reqsign-vercel`, `reqsign-yandex-disk`.
- `reqsign-http-message-signatures` for RFC 9421 request signing, facade
  feature `http-message-signatures`.
- Shared OAuth 2.0 refresh grants and OpenStack static-token credentials and
  Swift TempURL presigning.
- `Signer::credential_for` and `Signer::sign_with_credential` for services whose
  credential carries routing metadata. The caller can load the credential
  before building the request URI and sign with that same credential, without a
  refresh in between changing it.
- Optional MD5 and HMAC-SHA512 provider operations.
- Opt-in IMDSv1 fallback for AWS credentials, and AssumeRole providers that
  honor STS endpoint settings.

### Changed

- Minimum supported Rust version is 1.87.0. The RustCrypto backend's
  `rsa 0.10.0` requirement is the reason.
- The facade `default` feature enables `default-context` and `default-crypto`.
- Lockstep major `4.0.0` for `reqsign-core`, `reqsign-aws-core`, every
  established service crate, `reqsign-file-read-tokio`, and
  `reqsign-command-execute-tokio`. `reqsign-http-send-reqwest` moves to
  `5.0.0`, its own line offset from the core major.

### Fixed

- `reqsign-azure-storage` accepts SAS tokens with a leading `?`. SAS values
  copied from a full URL now sign the same query text as values without the
  delimiter.

### Carried over from the v0.20.9 release

The 0.21 source also contains the changes released in v0.20.9. Callers
upgrading from 0.20.8 or earlier receive them from either release:

- AWS SSO-backed assume-role profile chains, S3 Express session-token selection
  by service, and configurable SigV4 canonical URI encoding.
- Google service-account OAuth2 token caching for the request signer.
- Oracle caller-supplied request body-header signing and profile field
  inheritance.
- Huawei Cloud OBS IAM agency granter, Volcengine TOS STS `AssumeRole` granter,
  and Tencent COS `GetFederationToken` granter.
- Absolute credential expiry for OBS and TOS (see breaking changes above).
- OpenStack catalog search across all matching entries.
- Credential and security-token redaction in OBS and TOS debug output.

### Crate versions

| Crate | 0.21.0 |
| --- | --- |
| `reqsign` | 0.21.0 |
| `reqsign-core` | 4.0.0 |
| `reqsign-command-execute-tokio` | 4.0.0 |
| `reqsign-file-read-tokio` | 4.0.0 |
| `reqsign-http-send-reqwest` | 5.0.0 |
| `reqsign-aws-core` | 4.0.0 |
| `reqsign-aws-v4` | 4.0.0 |
| `reqsign-aws-v4a` | 4.0.0 |
| `reqsign-aliyun-oss` | 4.0.0 |
| `reqsign-azure-storage` | 4.0.0 |
| `reqsign-google` | 4.0.0 |
| `reqsign-huaweicloud-obs` | 4.0.0 |
| `reqsign-http-message-signatures` | 4.0.0 |
| `reqsign-openstack-keystone` | 4.0.0 |
| `reqsign-oracle` | 4.0.0 |
| `reqsign-tencent-cos` | 4.0.0 |
| `reqsign-volcengine-tos` | 4.0.0 |
| `reqsign-crypto-rustcrypto` | 1.0.0 |
| `reqsign-crypto-boring` | 1.0.0 (source release only) |
| `reqsign-aliyun-drive` | 1.0.0 |
| `reqsign-b2` | 1.0.0 |
| `reqsign-baidu-netdisk` | 1.0.0 |
| `reqsign-cloudflare` | 1.0.0 |
| `reqsign-dropbox` | 1.0.0 |
| `reqsign-github` | 1.0.0 |
| `reqsign-koofr` | 1.0.0 |
| `reqsign-oauth2` | 1.0.0 |
| `reqsign-onedrive` | 1.0.0 |
| `reqsign-seafile` | 1.0.0 |
| `reqsign-upyun` | 1.0.0 |
| `reqsign-vercel` | 1.0.0 |
| `reqsign-yandex-disk` | 1.0.0 |

## Earlier releases

Release notes before 0.21.0 were published with each
[GitHub release](https://github.com/apache/reqsign/releases).
