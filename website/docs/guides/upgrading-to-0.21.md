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
| `reqsign-crypto-rustcrypto`, `reqsign-crypto-boring` | — | `1.0.0` |
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
  `wasm32-unknown-unknown` for SHA-1, SHA-256, HMAC-SHA-1/256, and P-256 ECDSA.
  RSA, AES-GCM, and random generation report `ConfigInvalid` there.
- `reqsign-crypto-boring` is native-only, excluded from the main workspace, and
  forwards an optional `fips` feature. Bind it explicitly:
  `Context::new().with_crypto(BoringCryptoProvider::new())`.

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

`Signer::with_context` also changed: replacing the context now creates an
isolated, empty credential cache, because a different context can resolve a
different identity. To replace only the signing operation and keep the cached
credential, use `with_request_signer` or `with_credential_granter`.

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

## OBS and TOS credentials carry an absolute expiry

The Huawei Cloud OBS and Volcengine TOS `Credential` types gained
`expires_at: Option<Timestamp>` in the v0.20.9 release-candidate source. That
public field breaks struct-literal construction:

```rust
// 0.20 and earlier
let credential = obs::Credential {
    access_key_id,
    secret_access_key,
    security_token,
};

// 0.21, Huawei Cloud OBS: the constructor keeps the security token and leaves
// the expiration unset.
let credential = obs::Credential::new(access_key_id, secret_access_key, security_token)
    .with_expires_at(expires_at);

// 0.21, Volcengine TOS: the constructor takes only the key pair.
let credential = tos::Credential::new(&access_key_id, &secret_access_key)
    .with_session_token(&security_token)
    .with_expires_at(expires_at);
```

Header signing and presigning reject known-expiry credentials that do not cover
the requested operation deadline; presigning checks the full lifetime of the
signed URL. The STS granters (`AssumeRole` for TOS, IAM `Agency` for OBS) and
Tencent COS `GetFederationToken` return credentials that carry the exact
cloud-side expiration.

These changes already landed in the v0.20.9 release-candidate source, so they
are new relative to the published 0.20.8 crates. If the v0.20.9 vote completes
first, they reach crates.io there; the 0.21 release carries them either way.

## Behavior preserved

Wire formats are unchanged: AWS SigV4/SigV4a, Azure Storage SAS/shared
key/client certificate, Google signed URLs and CAB tokens, Oracle, Aliyun OSS,
Huawei Cloud OBS, Tencent COS, and Volcengine TOS keep their canonicalization
and encodings. `Signer::sign` is still atomic: on error, the request head is
unchanged; on success, only the URI and headers may change.
