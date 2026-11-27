# reqsign-google

Google Cloud Platform signing implementation for reqsign.

This crate signs Google Cloud requests with OAuth 2.0 access tokens or service
account credentials. Its default Application Default Credentials chain checks
`GOOGLE_APPLICATION_CREDENTIALS`, the well-known gcloud credentials file, and
the Compute Engine metadata service.

> Signing needs a `CryptoProvider` resolved through the `Context`: bind one with
> `Context::with_crypto`, install a process-wide default, or use a facade
> `default_context()` (which binds RustCrypto when the global slot is empty). A
> bare `Context::new()` starts unbound. See
> [CryptoProvider](https://github.com/apache/reqsign/blob/main/docs/crypto-provider.md).

## Quick Start

```rust,no_run
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_google::{DefaultCredentialProvider, RequestSigner};
use reqsign_http_send_reqwest::ReqwestHttpSend;

let context = Context::new().with_crypto(RustCryptoProvider::new())
    .with_file_read(TokioFileRead)
    .with_http_send(ReqwestHttpSend::default())
    .with_env(OsEnv);

let signer = Signer::new(
    context,
    DefaultCredentialProvider::new(),
    RequestSigner::new("storage"),
);
```

### Client-side Credential Access Boundary

Server-side CAB is available through the crate's normal API. For local
client-side token generation, enable `credential-access-boundary-client-side`
on `reqsign-google` directly, bind a `CryptoProvider` with AES-GCM and secure
random support, and supply an `HttpSend` transport for the STS exchange. Only
the `aes-gcm` backend feature is required:

```toml
[dependencies]
reqsign-core = "4"
reqsign-google = { version = "4", features = ["credential-access-boundary-client-side"] }
reqsign-crypto-rustcrypto = { version = "1", default-features = false, features = ["aes-gcm"] }
bytes = "1"
http = "1"
tokio = { version = "1", features = ["macros", "rt"] }
```

The facade `google` feature still covers request signing and server-side CAB,
but it no longer declares a client-side CAB feature. Enabling the service
feature directly adds the API. If the same dependency graph also enables the
facade `google` feature, Cargo unifies features on the single `reqsign-google`
package, so `reqsign::google` re-exports can still expose the type. That is
feature unification, not a facade feature; depend on `reqsign-google` directly
for this API.

For a complete runnable example that mocks the STS exchange and calls
`Granter::grant(None)` with no real credentials, see the
[`ClientSideCredentialAccessBoundaryGranter`](https://docs.rs/reqsign-google/latest/reqsign_google/struct.ClientSideCredentialAccessBoundaryGranter.html)
rustdoc.

For query signing, credential providers preserve a target service account email
when they can determine it from impersonation or VM metadata configuration. The
request signer uses that identity with IAMCredentials `signBlob`. An email set
with `RequestSigner::with_signer_email` takes precedence over the
provider-discovered identity.

## ADC service-account impersonation

An `impersonated_service_account` credential file accepts `authorized_user`,
`service_account`, or `external_account` in `source_credentials`. Legacy
`authorized_user` sources may omit `type`. List intermediate service accounts
in order in `delegates`. A nested `impersonated_service_account` source is rejected.

Service-account and external-account source tokens use the IAM scope.
Authorized-user sources use their existing refresh grant. The configured OAuth
scope or `GOOGLE_SCOPE` applies to the target token, whose signer identity comes
from `service_account_impersonation_url`.

Executable external-account sources require
`GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1` in the `Context` environment.

## Trusted OAuth token endpoints

`ServiceAccountTokenCredentialProvider::with_token_uri` and
`AuthorizedUserCredentialProvider::with_token_uri` select an explicit OAuth
endpoint. Both default to `https://oauth2.googleapis.com/token`. The
service-account provider uses the selected URI for both the HTTP request and
JWT `aud`, preserving scope, signer identity, expiration, and refresh behavior.
The authorized-user provider sends its existing refresh-token request to that URI.

Credential structs and the existing file, static, and default providers continue
to ignore JSON `token_uri`. An adapter that accepts trusted credential JSON can
retain that field alongside `ServiceAccount` or `OAuth2Credentials` with Serde
flattening, then pass its selection to `with_token_uri`. Prefer explicit adapter
configuration, then the trusted file's `token_uri`, then the canonical default:

```rust
use reqsign_google::{AuthorizedUserCredentialProvider, OAuth2Credentials};
use serde::Deserialize;

#[derive(Deserialize)]
struct TrustedAuthorizedUser {
    #[serde(flatten)]
    credential: OAuth2Credentials,
    token_uri: Option<String>,
}

fn provider(
    input: TrustedAuthorizedUser,
    configured_uri: Option<&str>,
) -> reqsign_core::Result<AuthorizedUserCredentialProvider> {
    let provider = AuthorizedUserCredentialProvider::new(input.credential);
    match configured_uri.or(input.token_uri.as_deref()) {
        Some(uri) => provider.with_token_uri(uri),
        None => Ok(provider),
    }
}
```

The same pattern applies to `ServiceAccount` and
`ServiceAccountTokenCredentialProvider::new`. A service-account provider can
also wrap an existing credential source using `from_provider(...).with_token_uri(...)`.
Both OAuth providers compose directly with the existing `Granter` APIs; adapters
do not need to construct JWTs or implement OAuth exchanges.

Only absolute HTTP(S) URIs with a host, valid port when present, and no userinfo
or fragment are accepted. Invalid configuration fails before the exchange, and
an exchange failure never falls back to another endpoint. URI query values and
secret-bearing response bodies are omitted from provider debug output and errors.

The caller must trust the endpoint: it receives a signed assertion or refresh
token and client secret. Validation checks URI syntax, not endpoint ownership or
network policy. Use HTTPS for production credentials; HTTP is supported for
trusted local testing. The caller also owns the HTTP transport's TLS, proxy,
redirect, and logging policy. Untrusted credential files must not select endpoints.

## Examples

- [Credential-chain logging](examples/chain_logging.rs)
- [Custom credential chain](examples/custom_chain.rs)

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
