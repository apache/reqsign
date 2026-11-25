# reqsign-yandex-disk

Yandex Disk OAuth access-token credentials and request signing for Reqsign.

The Yandex Disk REST API authenticates requests with
`Authorization: OAuth <access token>`. This crate supplies an opaque access
token type, a static credential provider, and a request signer that adds the
header.

## Credential discovery

Yandex Disk documents no environment variable, CLI token store, or well-known
credential file for OAuth access tokens. Reqsign does not invent one, and this
crate exports no default provider or builder. Supply the token explicitly, or
use the facade's `default_signer(ctx, access_token)`, which selects
`StaticCredentialProvider`:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_yandex_disk::{RequestSigner, StaticCredentialProvider};

# async fn example() -> Result<()> {
let signer = Signer::new(
    Context::new(),
    StaticCredentialProvider::new("yandex-disk-oauth-token"),
    RequestSigner,
);

let mut req = http::Request::get(
    "https://cloud-api.yandex.net/v1/disk/resources?path=disk%3A%2Ffolder%2Ffile",
)
.body(())
.unwrap()
.into_parts()
.0;
signer.sign(&mut req, None).await?;
# Ok(())
# }
```

Pass one provider directly to `Signer::new`; a single provider keeps its own
error behavior. For several sources, the caller owns the composition.
`ProvideCredentialChain` tries providers in insertion order and logs a provider
error before continuing. It is not equivalent to fail-closed, last-added-first
ordering; keep that ordering in a caller-owned `ProvideCredential`
implementation when it is required. A deliberate empty `ProvideCredentialChain`
yields no credential.

Token issuance, refresh, revocation, and the permissions attached to the OAuth
app stay with the caller and Yandex OAuth. This crate does not implement
authorization-code, device, or interactive flows. A static token without an
expiry is cached for the signer's lifetime; use
`StaticCredentialProvider::with_expires_at` when the token has a known fixed
lifetime, or a dynamic `ProvideCredential` that returns a fresh credential with
an expiry when the token rotates.

## Request ownership

The caller owns the API host, API version, resource path, query parameters,
`Accept` and `Content-Type` headers, and any upload or download URL returned by
Yandex Disk. Signing inserts a sensitive `Authorization` header and preserves
the URI and every other header. There is no query authentication, so signing
rejects `expires_in`.

## Failure behavior

An empty or non-ASCII token is rejected before it becomes a header value. A
missing credential fails with `CredentialInvalid`; an invalid explicit static
token fails with `ConfigInvalid`. `Debug` output for the token, credential, and
static provider never includes the token. On `wasm32-unknown-unknown`, static
credentials without an expiry and header signing need no JavaScript clock;
expiring credentials read the clock from a wasm-bindgen JavaScript host such as
a browser or Node.

The caller owns the HTTP client and its redirect policy. Do not forward a
signed `Authorization` header to a different host.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
