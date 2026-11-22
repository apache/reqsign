# reqsign-yandex-disk

Yandex Disk OAuth access-token credentials and request signing for Reqsign.

The Yandex Disk REST API authenticates requests with
`Authorization: OAuth <access token>`. This crate supplies an opaque access
token type, a static credential provider, an empty default provider that can be
composed with explicit providers, and a request signer that adds the header.

## Credential discovery

Yandex Disk documents no environment variable, CLI token store, or well-known
credential file for OAuth access tokens. Reqsign does not invent one, so the
default provider has no automatic source. Supply the token explicitly:

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

The default provider is the composition point when you want a provider chain:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_yandex_disk::{
    DefaultCredentialProvider, RequestSigner, StaticCredentialProvider,
};

# fn example(context: Context) -> Result<()> {
let provider = DefaultCredentialProvider::new()
    .push_front(StaticCredentialProvider::new("yandex-disk-oauth-token"));
let signer = Signer::new(context, provider, RequestSigner);
# let _ = signer;
# Ok(())
# }
```

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
credentials and header signing need no JavaScript clock.

The caller owns the HTTP client and its redirect policy. Do not forward a
signed `Authorization` header to a different host. On
`wasm32-unknown-unknown`, static credentials without an expiry and header
signing need no JavaScript clock.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
