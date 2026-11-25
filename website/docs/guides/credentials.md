---
title: Loading credentials
sidebar_label: Loading credentials
description: Use documented default credential chains, adjust their slots, compose explicit providers, or implement your own source.
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

Everything about getting credentials into a signer: use the documented default
chain where one exists, compose explicit providers, or replace the source
entirely.

## Use the default chain

Services with a documented ambient source ship a `DefaultCredentialProvider`
composing that source and others in a documented order — the same sources the
official CLIs and SDKs consult. A service whose only documented sources require
explicit caller input does not export an empty default provider or builder:
pass the provider directly to `Signer::new`, or use the facade `default_signer`
that takes the required identity. Each [provider page](/docs/providers/) lists
its exact sources and entry point.

```rust
use reqsign::aws::DefaultCredentialProvider;

// The documented default chain for AWS:
// env → profiles (including assume-role chains) → SSO → OIDC → process → ECS → IMDS
let provider = DefaultCredentialProvider::new();
```

Every service that exports a `DefaultCredentialProvider` exposes the same four
entry points:

```rust
DefaultCredentialProvider::new();                // the documented default chain
DefaultCredentialProvider::builder();            // default slots, then adjust
DefaultCredentialProvider::with_chain(chain);    // bypass defaults entirely
DefaultCredentialProvider::new().push_front(provider); // prepend a high-priority source
```

## Adjust the chain

The builder pre-populates the default slots. Each slot has exactly two
methods — one to replace it, one to remove it:

```rust
use reqsign::aws::{DefaultCredentialProvider, EnvCredentialProvider};

// Replace the env slot, drop IMDS, keep everything else as documented.
let provider = DefaultCredentialProvider::builder()
    .env(EnvCredentialProvider::new())
    .no_imds()
    .build();
```

There are no `configure_*` or `disable_*(bool)` methods by design: a removed
slot stays removed, and every slot is controlled by one positive and one
removal method.

### IMDSv1 fallback

The AWS IMDS provider uses IMDSv2 by default. To allow IMDSv1 when the IMDSv2
token request returns HTTP 403, 404, or 405, opt in on the IMDS slot:

```rust
use reqsign::aws::{DefaultCredentialProvider, IMDSv2CredentialProvider};

let provider = DefaultCredentialProvider::builder()
    .imds(IMDSv2CredentialProvider::new().with_imdsv1_fallback())
    .build();
```

Other token, transport, metadata, role, and credential failures are returned
without falling back. Enable this only for instances where IMDSv2 is unavailable.

## Fixed credentials

When the credential is decided elsewhere — tests, WASM, a control plane that
injects keys — skip chains entirely. Services without a default provider use
this path directly; otherwise `.with_credential_provider(provider)` keeps the
rest of the signer:

```rust file=reqsign/examples/static_credentials.rs region=static
```

Replacing a signer's context or credential provider clears its credential
cache, so a credential from the old configuration is never reused with the
new one.

## Implement your own source

When credentials come from somewhere Reqsign doesn't know — a secret
manager, a sidecar, an in-house vault — implement `ProvideCredential`:

```rust
use bytes::Bytes;
use reqsign::{Context, ProvideCredential, Result};
use reqsign::aws::Credential;

#[derive(Debug)]
struct VaultCredentialProvider {
    endpoint: String,
}

impl ProvideCredential for VaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context)
        -> Result<Option<Self::Credential>>
    {
        // Use the Context for I/O so your provider stays runtime-agnostic
        // and testable — here, an HTTP call through ctx.
        let req = http::Request::get(&self.endpoint).body(Bytes::new())?;
        let resp = ctx.http_send(req).await?;

        // Return Ok(None) when this source has nothing to offer,
        // so a chain can continue to the next provider.
        if resp.status() == http::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let credential = parse_vault_response(resp.body())?;
        Ok(Some(credential))
    }
}
```

The return-value protocol is what makes chains compose: `Ok(Some(_))`
resolves and `Ok(None)` passes to the next source. `ProvideCredentialChain`
also logs `Err(_)` and continues: a failing custom source can fall back to
profiles, metadata, or another configured identity. If all sources fail or
return `None`, the chain returns `Ok(None)`.

Report "not configured" as `None` and real failures as errors. A provider
installed directly on the signer propagates its error. A default provider's
`push_front` error policy is service-specific; follow its documentation. When
failure must stop credential resolution, install your provider directly on the
signer or keep that policy in a caller-owned provider. See
[Architecture § ProvideCredential](/docs/architecture/#providecredential).

## Plug it in

For a service that exports `DefaultCredentialProvider`, highest priority in
front of its documented default chain:

```rust
use reqsign::aws::DefaultCredentialProvider;

let provider = DefaultCredentialProvider::new().push_front(VaultCredentialProvider {
    endpoint: "http://127.0.0.1:8200/v1/aws/creds/my-role".into(),
});
```

Or a fully explicit chain that bypasses the defaults:

```rust
use reqsign::ProvideCredentialChain;

let chain = ProvideCredentialChain::new()
    .push(VaultCredentialProvider { endpoint })
    .push(EnvCredentialProvider::new());
let provider = DefaultCredentialProvider::with_chain(chain);
```

Then hand it to a default signer (`.with_credential_provider(provider)`) or
a custom `Signer::new`. If the service has no default provider, pass the
provider or chain directly to `Signer::new`.

## Freshness

The credential type you return implements `SigningCredential`; set its
expiration so
[caching](/docs/architecture/#credential-caching-and-validity) refreshes it
on time. Credentials without an expiration are cached by the signer until
its credential provider is replaced. Replacing the signer's `Context` also
clears the signer's credential cache.
