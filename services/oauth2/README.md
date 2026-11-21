# reqsign-oauth2

Shared RFC 6749 OAuth 2.0 refresh-token support for Reqsign.

This crate covers one protocol slice: the
[refresh token grant](https://www.rfc-editor.org/rfc/rfc6749#section-6),
form-encoded client credentials in the request body, and the resulting Bearer
token. Service crates such as `reqsign-dropbox` own endpoint defaults,
credential discovery, service-specific `Credential` types, and request signing.

## Scope

`RefreshTokenGrant` sends `grant_type`, `refresh_token`, `client_id`, and
optional `client_secret` and `scope` fields as
`application/x-www-form-urlencoded`. It never sends HTTP Basic authentication or
an `Authorization` header at the same time. This form-body mode is used by the
first consumers of this crate (Dropbox and Microsoft Graph) and by the RFC 6749
refresh token grant itself. It is not a general client-authentication policy.
An endpoint that requires HTTP Basic, mTLS, or a provider-specific assertion
needs a different implementation.

The token endpoint is explicit and must be an absolute HTTPS URI with a host and
without userinfo or a fragment. The caller owns endpoint trust and the HTTP
adapter's TLS, proxy, redirect, timeout, and retry policy. The grant builds no
fallback endpoint and performs no retry.

## State and caching

Each grant keeps only the latest refresh token in memory. Clones share that
state. Every call holds an async lock from reading the current refresh token
until the response is received and a replacement, when present, is committed.
Concurrent calls through one grant therefore exchange tokens one at a time, and
later calls use the latest token. Independent grants and processes do not
coordinate, and the crate never writes tokens to disk.

Access-token caching belongs to `reqsign_core::Signer`. This crate does not keep
a second access-token cache.

## Expiration

`AccessToken::expires_at` is the absolute expiration derived from `expires_in`
and the time the refresh request started, or `None` when the response omitted
`expires_in`. Services that require an expiration must reject an unknown
expiration instead of caching the token as permanent. `AccessToken::is_valid`
uses a 120-second refresh window; `AccessToken::is_valid_at` checks the true
expiration without that window.

## Example

```rust,no_run
use reqsign_core::Context;
use reqsign_oauth2::RefreshTokenGrant;

# async fn example(ctx: &Context) -> reqsign_core::Result<()> {
let grant = RefreshTokenGrant::new(
    "https://api.example.com/oauth2/token",
    "client-id",
    Some("client-secret".to_string()),
    "refresh-token",
    None,
)?;

let token = grant.refresh(ctx).await?;
let authorization = token.bearer_header_value()?;
# let _ = authorization;
# Ok(())
# }
```

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
