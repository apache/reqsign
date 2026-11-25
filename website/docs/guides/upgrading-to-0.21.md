---
title: Upgrading to Reqsign 0.21
sidebar_label: Upgrade to 0.21
description: Migrate to reqsign 0.21, reqsign-core 4.0, explicit contexts, and CryptoProvider-based cryptography.
---

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

# Upgrading to Reqsign 0.21

0.21 moves the core and every established service crate to one new lockstep
major (`4.0.0`), publishes the provider crates added since 0.20.8, and removes
cryptographic implementations from the signing crates. Most applications need
three steps:

1. Update the facade to `0.21` and let it pull the matching `4.0.0` components.
2. Make sure the `Context` handed to a signer can resolve a `CryptoProvider`.
3. Pass the `Context` explicitly to `default_signer`.

Everything else on this page is the detail behind those steps.

## Dependency versions

| Crate | 0.20 line | 0.21 line |
| --- | --- | --- |
| `reqsign` | `0.20.x` | `0.21.x` |
| `reqsign-core`, `reqsign-aws-core`, every established service crate, `reqsign-file-read-tokio`, `reqsign-command-execute-tokio` | `3.x` | `4.0.0` |
| `reqsign-http-send-reqwest` | `4.0.x` | `5.0.0` |
| `reqsign-crypto-rustcrypto` | — | `1.0.0` |
| `reqsign-crypto-boring` | — | `1.0.0` |
| `reqsign-aliyun-drive`, `reqsign-baidu-netdisk`, `reqsign-cloudflare`, `reqsign-dropbox`, `reqsign-github`, `reqsign-koofr`, `reqsign-oauth2`, `reqsign-onedrive`, `reqsign-seafile`, `reqsign-upyun`, `reqsign-vercel`, `reqsign-yandex-disk`, and the B2 crate `reqsign-b2` | — | `1.0.0` |

Mixing core majors does not compile, because the traits are the compatibility
boundary. Upgrade the facade and every directly used `reqsign-*` crate in the
same change:

```toml
[dependencies]
reqsign = "0.21"

# Only if you use these crates directly:
reqsign-core = "4"
reqsign-aws-v4 = "4"
reqsign-http-send-reqwest = "5"
```

## Cryptography now comes from the context

Reqsign no longer links SHA-1, SHA-256, HMAC, RSA, P-256, or AES-GCM into
`reqsign-core` or any service crate. Signing resolves a
`reqsign_core::crypto::CryptoProvider` through the `Context`, in this order:

1. `Context::with_crypto(provider)` — explicit binding, highest priority.
2. `reqsign_core::crypto::install_default(provider)` — process-wide
   registration.
3. Otherwise `ErrorKind::ConfigInvalid` at the point of use.

`Context::new()` and `Context::default()` start unbound. Signing with an
unbound context fails instead of silently using a bundled implementation.

### Facade users

`default_context()` keeps working. With the `default-crypto` feature, which is
part of `default`, it binds `RustCryptoProvider` when the process-wide slot is
empty; it never installs the global provider itself. No startup boilerplate is
required:

```rust
use reqsign::{aws, default_context};

let ctx = default_context();
let signer = aws::default_signer(ctx, "s3", "us-east-1");
```

To choose a single backend for the whole application, install it before
constructing contexts. Contexts that already bound RustCrypto keep that
binding; explicit `with_crypto` always wins:

```rust
use reqsign::RustCryptoProvider;

// Returns Err when another component already installed a provider.
RustCryptoProvider::install_default()
    .map_err(|_| "a CryptoProvider is already installed")?;
```

Middleware and libraries should not install a global provider. They should
accept the caller's `Context` instead.

### Bare `reqsign-core` users

```rust
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;

let ctx = Context::new()
    .with_crypto(RustCryptoProvider::new())
    .with_env(OsEnv);
```

### Custom providers

Implement `reqsign_core::crypto::CryptoProvider`. `sha1`, `sha256`,
`hmac_sha1`, and `hmac_sha256` are mandatory; the remaining operations have
default implementations that return `ConfigInvalid` so a minimal provider can
serve the services that only need hashing and MACs.

A provider or operation that is missing is a non-retryable `ConfigInvalid`.
Malformed key material is `CredentialInvalid`. Backend failures are
`Unexpected`.

The generic credential chain continues past provider errors and returns
`Ok(None)` when every source is exhausted, so a missing provider discovered
while loading credentials can surface as `CredentialInvalid` from
`Signer::sign` with the request unchanged. Bind or install a provider before
loading credentials to see the `ConfigInvalid` failure itself.

### Removed and changed crypto APIs

- The public `reqsign_core::jwt` module and the `jwt` feature are removed. Azure
  client-certificate and Google service-account flows format RS256 JWS
  internally through the resolved provider. Callers that used `reqsign_core::jwt`
  must call `CryptoProvider::rsa_pkcs1v15_sha256_sign` and format the JWS
  themselves.
- Hash and MAC helpers take a provider and return `Result`:

  ```rust
  // 0.20
  let digest = reqsign_core::hash::hex_sha256(body);

  // 0.21
  let digest = reqsign_core::hash::hex_sha256(ctx.crypto_provider()?, body)?;
  ```

- Azure `ServiceSharedAccessSignature::token` takes the resolved provider:
  `sas.token(ctx.crypto_provider()?)?`.
- Base64 helpers (`base64_encode`, `base64_decode`) are unchanged.

### Backend crates

- `reqsign-crypto-rustcrypto` implements all operations and supports
  `wasm32-unknown-unknown` for MD5, SHA-1, SHA-256, HMAC-SHA-1/256/512, and
  P-256 ECDSA. RSA, AES-GCM, and random generation report `ConfigInvalid` there.
- `reqsign-crypto-boring` is native-only, excluded from the main workspace,
  and forwards an optional `fips` feature. It is published to crates.io from
  the explicit standalone release-plan entry after `reqsign-core`. Bind it
  explicitly: `Context::new().with_crypto(BoringCryptoProvider::new())`.

## Default signers take an explicit `Context`

Every per-service `default_signer` now takes the context as its first argument.
The `default-context` feature no longer gates `DefaultSigner` or
`default_signer`: they exist whenever the service feature is enabled, including
custom-runtime and WASM builds.

```rust
// 0.20
let signer = reqsign::aws::default_signer("s3", "us-east-1");
let signer = reqsign::azure::default_signer();

// 0.21
let ctx = reqsign::default_context();
let signer = reqsign::aws::default_signer(ctx.clone(), "s3", "us-east-1");
let signer = reqsign::azure::default_signer(ctx);
```

Passing one shared context lets several signers and granters reuse the same
HTTP client and credential adapters instead of building a new runtime per
call.

## Replacing a signer's `Context` starts an empty credential cache

:::warning A silent cache miss, not a compile error
`Signer::with_context` now gives the returned signer a new, empty credential
cache. In 0.20 it kept the previous cache; in 0.21 the next `sign` has to load
a credential again. Code that replaces the context per request still compiles,
but each request's signer starts empty and repeats the provider's work, such
as IMDS or STS calls, OAuth 2.0 or Entra ID token requests, or reads of local
credential files.
:::

This isolation is intentional. A `Context` carries `Env`, `FileRead`,
`CommandExecute`, and `HttpSend`, so replacing it can change which identity or
endpoint a provider resolves. Reusing the previous cache could sign with a
credential that belongs to a different identity. Each signer owns its cache,
and replacing the context replaces that cache as well.

The common regression is replacing the context inside the request path, often
to inject a per-operation HTTP transport:

```rust
// Compiles, but each request starts with an empty cache and reloads.
let signer = self
    .signer
    .clone()
    .with_context(self.ctx.clone().with_http_send(transport.clone()));
signer.sign(&mut parts, expires_in).await?;
```

Bind the context and build the signer once, when the client or connection
scope is created:

```rust
let signer = Signer::new(
    ctx.with_http_send(transport),
    provider,
    request_signer,
);

// Then reuse that signer for every request in the same scope. Clones share
// its context and credential cache.
signer.sign(&mut parts, expires_in).await?;
```

If the application has several stable transports or credential scopes, keep
one signer for each and reuse it, for example in a map keyed by transport or
scope. Replace the context when the identity or transport genuinely changes,
not on every request just to inject the current transport.

The other builders follow the same cache boundary:

- `with_request_signer` replaces only the signing operation and keeps the
  context, provider, and cached credential.
- `with_credential_provider` and `with_context` both start an empty cache,
  because either can change the credential or the identity that resolves it.
- `Signer::new` and `default_signer` also start with an empty cache. Construct
  them once per stable credential scope instead of once per request.
- For `Granter`, `with_credential_granter` keeps the cached source credential,
  while `with_context` and `with_credential_provider` start an empty cache.

When the provider returns static credentials or caches them itself, the
repeated load can be cheap. That is a provider property, not a guarantee from
`Signer`.

## Sign with the credential that built the request URI

`Signer::sign` may refresh the cached credential before signing. When the
credential carries routing metadata that the request URI must agree with — for
example the Backblaze B2 `api_url` — load the credential first, build the URI
from it, and sign with that same credential:

```rust
let credential = signer.credential_for(None).await?;
let uri = format!(
    "{}/b2api/v4/b2_list_buckets?accountId={account_id}",
    credential.api_url()
);

let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri(uri)
    .body(())?
    .into_parts()
    .0;

signer.sign_with_credential(&mut req, &credential, None).await?;
```

`credential_for` uses the same serialized cache and operation-deadline checks
as `sign`. `sign_with_credential` never loads, refreshes, or stores a
credential; when the supplied credential cannot cover the requested operation,
it returns `CredentialInvalid` and leaves the request unchanged. Load a new
credential and rebuild the URI in that case. The
[Backblaze B2 provider page](/docs/providers/b2/) shows the complete example.

## Minimum supported Rust version is 1.87

The RustCrypto backend's `rsa 0.10` dependency requires Rust 1.87, and the
workspace declares `rust-version = "1.87.0"`. Builds on Rust 1.86 fail during
dependency resolution.

## New provider crates

These crates and facade features are published for the first time at `1.0.0`.
They depend on `reqsign-core` 4 and follow the same `Context` and signing
contracts as the established services:

| Facade feature | Crate | Scope |
| --- | --- | --- |
| `aliyun-drive` | `reqsign-aliyun-drive` | Aliyun Drive Open Platform OAuth and bearer signing |
| `b2` | `reqsign-b2` | Backblaze B2 Native API |
| `baidu-netdisk` | `reqsign-baidu-netdisk` | Baidu Netdisk static access-token query signing |
| `cloudflare` | `reqsign-cloudflare` | Cloudflare API token requests (KV, D1) |
| `dropbox` | `reqsign-dropbox` | Dropbox OAuth 2.0 bearer authentication |
| `github` | `reqsign-github` | GitHub.com bearer tokens and anonymous public access |
| `koofr` | `reqsign-koofr` | Koofr access-token exchange and request signing |
| `oauth2` | `reqsign-oauth2` | Shared OAuth 2.0 refresh grants |
| `onedrive` | `reqsign-onedrive` | Microsoft Graph OAuth 2.0 bearer authentication |
| `seafile` | `reqsign-seafile` | Seafile account-token authentication |
| `upyun` | `reqsign-upyun` | UPYUN header signing |
| `vercel` | `reqsign-vercel` | Vercel Blob and Artifacts bearer tokens |
| `yandex-disk` | `reqsign-yandex-disk` | Yandex Disk OAuth credentials and signing |

`reqsign-http-message-signatures` (RFC 9421, facade feature
`http-message-signatures`) is also new; it joins the lockstep line and starts at
`4.0.0` so it composes with `reqsign-core` 4.

### Credential construction

These crates have no earlier published API to migrate from. Their credential
types are built through constructors and builders and read through accessors
instead of public fields:

```rust
let credential = aliyun_drive::Credential::new(access_token)?
    .with_expires_at(expires_at);
```

Aliyun Drive's `Credential::new(access_token)` rejects an invalid token
immediately; `with_expires_at` records the optional expiry. B2 credentials are
created with `Credential::new(token, api_url, download_url)` and read with
`authorization_token()`, `api_url()`, `download_url()`, and `expires_at()`.
Upyun credentials are created with `Credential::new(operator, password)` and
read with `operator()` and `bucket()`. B2 and Upyun can construct incomplete
values, which are rejected by the B2 static provider or the signer at use.
The password is not exposed outside the signer.

### Explicit credentials

Baidu Netdisk has no ambient credential source, so the caller supplies the
token:

```rust
use reqsign::{baidu_netdisk, default_context};

let ctx = default_context();
let signer = baidu_netdisk::default_signer(ctx, access_token);
```

The caller still owns request policy, such as the `User-Agent` Baidu requires
on download requests. Reqsign only signs the `access_token` query parameter and
preserves the rest of the wire query.

Aliyun Drive, OneDrive, and Yandex Disk also have no documented ambient token
source. Their facade entries take the access token explicitly:

```rust
use reqsign::{aliyun_drive, default_context, onedrive, yandex_disk};

let ctx = default_context();
let signer = aliyun_drive::default_signer(ctx.clone(), access_token.clone());
let signer = onedrive::default_signer(ctx.clone(), access_token.clone());
let signer = yandex_disk::default_signer(ctx, access_token);
```

For a refresh provider or another explicit source, assemble the signer directly
instead of passing a dummy token:

```rust
use reqsign::{Signer, aliyun_drive, default_context};

let provider = aliyun_drive::RefreshCredentialProvider::new(
    "client-id",
    "client-secret",
    "refresh-token",
)?;
let signer = Signer::new(default_context(), provider, aliyun_drive::RequestSigner);
```

These three crates do not export an empty `DefaultCredentialProvider` or its
builder. The facade entries above are convenience wrappers around
`StaticCredentialProvider`; any other explicit provider goes directly to
`Signer::new`.

### Caller-owned provider composition

`DefaultCredentialProvider::with_chain(c)` becomes the chain itself:

```rust
let signer = Signer::new(ctx, c, service::RequestSigner);
```

It keeps `ProvideCredentialChain`'s error policy. A single
`push_front(provider)` becomes that provider directly, which keeps its `Err`
behavior. A deliberate no-credential provider is an empty chain:
`ProvideCredentialChain::<Credential>::new()`.

If the old code used several `push_front` calls, keep that composition
explicitly. The default provider tried the most recently prepended provider
first, returned an error immediately, moved on only after `None`, then ran the
original chain. This caller-owned provider implements exactly that policy:

```rust
use reqsign::aliyun_drive::Credential;
use reqsign::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};

#[derive(Debug)]
struct PrependThenChain {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = Credential>>>,
    fallback: ProvideCredentialChain<Credential>,
}

impl PrependThenChain {
    fn new(fallback: ProvideCredentialChain<Credential>) -> Self {
        Self {
            front: Vec::new(),
            fallback,
        }
    }

    fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.front.insert(0, Box::new(provider));
        self
    }
}

impl ProvideCredential for PrependThenChain {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        for provider in &self.front {
            if let Some(credential) = provider.provide_credential_dyn(ctx).await? {
                return Ok(Some(credential));
            }
        }

        self.fallback.provide_credential(ctx).await
    }
}
```

This example uses Aliyun Drive's credential type; use the same shape with the
service you are migrating. Build it in the same order as the old calls:
`push_front(first_provider)` and then `push_front(most_recent_provider)`.
`ProvideCredentialChain` itself logs a provider error and tries the next source.
That permissive fallback differs from the fail-closed composition above, so
replacing several `push_front` calls with `ProvideCredentialChain` can change
which identity signs.

## OBS and TOS credentials carry an absolute expiry

The Huawei Cloud OBS and Volcengine TOS `Credential` types gained
`expires_at: Option<Timestamp>` in the v0.20.9 release. That public field
breaks struct-literal construction:

```rust
// 0.20.8 and earlier
let credential = obs::Credential {
    access_key_id,
    secret_access_key,
    security_token, // Option<String>
};

// 0.20.9 and later, Huawei Cloud OBS: the constructor takes the key pair and
// an optional security token, and leaves the expiration unset.
let credential = obs::Credential::new(access_key_id, secret_access_key, security_token)
    .with_expires_at(expires_at);

// 0.20.9 and later, Volcengine TOS: the constructor takes only the key pair.
let credential = tos::Credential::new(&access_key_id, &secret_access_key)
    .with_session_token(&session_token)
    .with_expires_at(expires_at);
```

Header signing and presigning reject known-expiry credentials that do not cover
the requested operation deadline; presigning checks the full lifetime of the
signed URL. The STS granters (`AssumeRole` for TOS, IAM `Agency` for OBS) and
Tencent COS `GetFederationToken` return credentials that carry the exact
cloud-side expiration.

v0.20.9 is released, so these changes are new relative to the 0.20.8 crates
and already available on the 0.20 line. The 0.21 release carries them as well.

## Behavior preserved

Wire formats are unchanged: AWS SigV4/SigV4a, Azure Storage SAS/shared
key/client certificate, Google signed URLs and CAB tokens, Oracle, Aliyun OSS,
Huawei Cloud OBS, Tencent COS, and Volcengine TOS keep their canonicalization
and encodings. `Signer::sign` is still atomic: on error, the request head is
unchanged; on success, only the URI and headers may change.
