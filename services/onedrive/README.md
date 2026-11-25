# reqsign-onedrive

OneDrive authentication and request signing for Reqsign. OneDrive requests go
to Microsoft Graph with a Microsoft Entra access token in an
`Authorization: Bearer` header; the caller builds the request, for example
`GET https://graph.microsoft.com/v1.0/me/drive/root`.

Microsoft documents no environment variable or shared configuration file that
carries a Microsoft Graph user token, and MSAL token caches are
library-specific. This crate therefore exports no default provider or builder:
it does not run the Azure CLI, read MSAL caches, or start a login flow. Every
credential comes from an explicit provider passed to `Signer::new`. The facade
entry `reqsign::onedrive::default_signer(ctx, access_token)` selects
`StaticCredentialProvider` for a caller-managed token.

## Quick Start

```rust,no_run
use reqsign_core::{Context, Signer};
use reqsign_onedrive::{RequestSigner, StaticCredentialProvider};

# async fn example(context: Context) -> reqsign_core::Result<()> {
let signer = Signer::new(
    context,
    StaticCredentialProvider::new("graph-access-token"),
    RequestSigner,
);

let mut req = http::Request::get("https://graph.microsoft.com/v1.0/me/drive")
    .body(())
    .unwrap()
    .into_parts()
    .0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

## Provider composition

Pass one provider directly to `Signer::new`. A single provider keeps its own
error behavior; an invalid explicit credential fails instead of selecting a
different identity.

For several sources, the caller owns the composition.
`ProvideCredentialChain` tries providers in insertion order and logs a provider
error before continuing. It is not equivalent to the fail-closed,
last-added-first ordering that an empty default provider used to provide; keep
that ordering in a caller-owned `ProvideCredential` implementation when it is
required. A deliberate empty `ProvideCredentialChain` yields no credential.

## Refresh tokens

The authorization request must include `offline_access` to receive a refresh
token, and `Files.ReadWrite` to read, create, update, and delete the signed-in
user's files. The provider then refreshes through
`https://login.microsoftonline.com/common/oauth2/v2.0/token`.

Public clients — desktop, mobile, browserless, or client-side apps — cannot
store an application secret, so the exchange sends none:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_onedrive::{RefreshCredentialProvider, RequestSigner};

# fn example(context: Context) -> Result<()> {
let provider = RefreshCredentialProvider::new("client-id", "refresh-token")?;
let signer = Signer::new(context, provider, RequestSigner);
# let _ = signer;
# Ok(())
# }
```

Confidential clients — web apps, web APIs, and daemons that keep the secret on
the server side — add it to the same exchange:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_onedrive::{RefreshCredentialProvider, RequestSigner};

# fn example(context: Context) -> Result<()> {
let provider = RefreshCredentialProvider::builder("client-id", "refresh-token")
    .client_secret("client-secret")
    .build()?;
let signer = Signer::new(context, provider, RequestSigner);
# let _ = signer;
# Ok(())
# }
```

The example above passes the refresh provider directly to `Signer::new`. The
facade `default_signer(ctx, access_token)` is the static-token convenience; it
does not take a refresh provider.

Microsoft returns a new refresh token with every successful exchange and
documents that the client must discard the previous one. A provider keeps only
the latest refresh token in memory, clones share it, and exchanges are
serialized. A lost refresh token cannot be recovered; obtain a new one through
the authorization flow.

## Tenant, scope, and endpoint

The default token endpoint is the global Microsoft Entra v2.0 endpoint for the
`common` tenant. Select another documented tenant with `.tenant(...)`:

```rust,no_run
use reqsign_onedrive::RefreshCredentialProvider;

# fn example() -> reqsign_core::Result<()> {
let provider = RefreshCredentialProvider::builder("client-id", "refresh-token")
    .tenant("contoso.onmicrosoft.com")
    .build()?;
# let _ = provider;
# Ok(())
# }
```

By default the exchange omits `scope`, so the access token keeps the scopes of
the original grant. To repeat them explicitly, use `.scope("offline_access
Files.ReadWrite")`; Microsoft requires the value to be equivalent to or a
subset of the original grant.

National clouds publish a different authentication endpoint. Replace the whole
endpoint instead of the tenant when targeting one; it must be HTTPS:

```rust,no_run
use reqsign_onedrive::RefreshCredentialProvider;

# fn example() -> reqsign_core::Result<()> {
let provider = RefreshCredentialProvider::builder("client-id", "refresh-token")
    .token_endpoint("https://login.microsoftonline.us/common/oauth2/v2.0/token")
    .build()?;
# let _ = provider;
# Ok(())
# }
```

`RequestSigner` adds only a sensitive `Authorization: Bearer` header. It rejects
`expires_in` because this crate implements header authentication only, and it
never changes the URI or other headers. Access-token caching belongs to
`reqsign_core::Signer`.

On `wasm32-unknown-unknown`, this crate enables Jiff's `js` feature. Runtime
signing or refresh requires a wasm-bindgen JavaScript host such as a browser or
Node; a bare WASM runtime without a JavaScript clock can compile the crate but
is not a supported runtime. CI exercises the public signing and refresh paths
under `wasm-bindgen-test` in Node.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
