# reqsign-cloudflare

Cloudflare API token discovery and request signing for Reqsign.

This crate signs Cloudflare API v4 requests with an API token, which is what
the Workers KV and D1 endpoints authenticate with. The token is sent as
`Authorization: Bearer <token>`.

## Resource identifiers belong to the caller

The account ID, D1 database ID, and KV namespace ID are part of the request URL,
not part of authentication:

```text
KV  {account_id}/storage/kv/namespaces/{namespace_id}/values/{key}
D1  {account_id}/d1/database/{database_id}/query
```

They stay with the code that builds the request, so one credential signs for
every account, database, and namespace the token is scoped to. Reqsign does not
build the business URL, choose the HTTP method, or touch the request body.

## Credential discovery

The default credential chain reads `CLOUDFLARE_API_TOKEN` through
`reqsign_core::Context` environment access. That is the variable Wrangler and
Cloudflare's official SDKs use for non-interactive authentication.

Cloudflare's global API key is not an API token source: it requires a different
header pair (`X-Auth-Key` and `X-Auth-Email`) rather than a bearer token, so this
chain does not read `CLOUDFLARE_API_KEY` or `CLOUDFLARE_EMAIL`. Supply a custom
provider when a request really needs that authentication.

The configured sources fail closed. A present but unusable
`CLOUDFLARE_API_TOKEN`, or an invalid prepended or static provider, fails signing
instead of silently selecting a different identity. An absent token yields no
credential, and signing then reports `CredentialInvalid`.

`CLOUDFLARE_ACCOUNT_ID` is not read. It selects a resource in the URL, not an
identity.

## Request signing

`RequestSigner` inserts a sensitive `Authorization` header and leaves the URI and
every other header unchanged, so the caller keeps `Content-Type`, multipart
encoding for KV writes, and the JSON body for D1 queries. The Cloudflare API has
no query authentication, so signing rejects `expires_in`.

Cloudflare assigns an API token its permissions and optional expiry when the
token is created; neither is readable from the token. Reqsign does not track that
expiry, and signing writes no protocol time, so signing has no clock dependency.
A token that Cloudflare has expired fails at the API, so rotate it with the
mechanism your deployment already uses.

The caller owns the HTTP client and its redirect policy. Do not forward a signed
`Authorization` header to a different host.

On `wasm32-unknown-unknown`, environment and static credentials plus header
signing need no JavaScript clock.

## Quick Start

```rust,no_run
use reqsign_core::{Context, OsEnv, Result, Signer};
use reqsign_cloudflare::{DefaultCredentialProvider, RequestSigner};

# async fn example() -> Result<()> {
let ctx = Context::new().with_env(OsEnv);
let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);

// The caller owns the account, namespace, and key.
let mut req = http::Request::get(
    "https://api.cloudflare.com/client/v4/accounts/my-account/storage/kv/namespaces/my-namespace/values/my-key",
)
.body(())
.unwrap()
.into_parts()
.0;

signer.sign(&mut req, None).await?;
# Ok(())
# }
```

For an explicit token, replace the default provider:

```rust,no_run
use reqsign_core::{Context, Result, Signer};
use reqsign_cloudflare::{RequestSigner, StaticCredentialProvider};

# fn example(context: Context) -> Result<()> {
let signer = Signer::new(
    context,
    StaticCredentialProvider::new("cloudflare-api-token"),
    RequestSigner,
);
# let _ = signer;
# Ok(())
# }
```

The builder supports one positive method and one removal method per slot:

```rust,no_run
use reqsign_cloudflare::{DefaultCredentialProvider, EnvCredentialProvider};

let provider = DefaultCredentialProvider::builder()
    .no_env()
    .env(EnvCredentialProvider::new())
    .build();
```

Removed slots are not re-enabled during `build()`. `push_front` composes a
higher-priority provider, and an error from a prepended provider is returned
instead of falling through to the default chain.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
