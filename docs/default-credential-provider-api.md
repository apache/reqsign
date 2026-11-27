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

# Default Credential Provider API Design

This document defines the repository's authoritative public API design for all
`DefaultCredentialProvider` types.

Implementations that do not match this document should be treated as legacy
debt. New code, reviews, and refactors must follow this document.

## Applicability

A service exports `DefaultCredentialProvider` and
`DefaultCredentialProviderBuilder` only when default construction can discover
at least one documented credential source, such as an environment variable, a
profile or well-known file, a CLI session, or instance metadata.

A service whose only documented sources require explicit caller input has no
default construction to wrap. It must not export an empty default provider or
builder. Callers pass the explicit provider to `Signer::new` or to the facade
`default_signer` that takes the required identity. Aliyun Drive, OneDrive, and
Yandex Disk are examples: none documents an automatic token source, so
their explicit providers are used directly. Baidu Netdisk and Koofr already
accept the identity explicitly and need no default provider either.

The rest of this document applies to every service that does export the
default-provider API.

## Goals

- Make provider participation explicit.
- Remove boolean toggles from the public API.
- Remove `configure_*` patch-style APIs from the public API.
- Keep the top-level `DefaultCredentialProvider` API uniform across the
  services that export it.
- Keep builder APIs predictable across those services while allowing
  service-specific provider slots.

## Product API

Every service that exports a default provider exposes the same product-level
API:

```rust
DefaultCredentialProvider::new()
DefaultCredentialProvider::builder()
DefaultCredentialProvider::with_chain(chain)
DefaultCredentialProvider::push_front(provider)
impl Default for DefaultCredentialProvider
```

### Semantics

- `new()` creates the documented default chain for that service.
- `default()` is identical to `new()`.
- `builder()` returns a builder pre-populated with the documented default slots.
- `with_chain(chain)` bypasses all default-chain assembly logic.
- `push_front(provider)` prepends a high-priority provider in front of the
  documented default chain.

## Builder API

Every `DefaultCredentialProviderBuilder` for such a service exposes:

```rust
DefaultCredentialProviderBuilder::new()
DefaultCredentialProviderBuilder::default()
.build()
```

For each supported provider slot, the builder exposes exactly two primary
methods:

```rust
.env(provider)
.no_env()
```

The same pattern applies to all other slots:

```rust
.profile(provider)
.no_profile()

.sso(provider)
.no_sso()

.imds(provider)
.no_imds()
```

### Rules

- Public builder APIs must not expose `configure_*`.
- Public builder APIs must not expose `disable_*(bool)`.
- Each slot is controlled by one positive method and one removal method.
- Slot names must match the actual provider concept, not an overloaded alias.
- Builders expose only the slots that a service actually supports.

### Cross-Slot Convenience Methods

A service may expose a narrowly scoped convenience method when one logical
input applies to multiple provider slots. Such a method must:

- Update only slots that are currently present; it must not re-enable a slot
  removed with `no_slot()`.
- Preserve every unrelated setting on each provider.
- Respect builder call order so that later slot-level replacement or removal
  still wins.

For AWS V4 and V4a, `with_profile(profile)` applies the explicit profile to the
`profile`, `sso`, `process`, and `web_identity` slots. The selected profile
provides credential and STS endpoint settings for `web_identity`. The independent
web identity slot is available with `no_profile()`. On `wasm32`, `with_profile`
applies to the available `profile` and `web_identity` slots.

Providers added with `push_front` run first. Environment credentials take
precedence when `AWS_PROFILE` or the default name selects the profile. When the
profile slot explicitly names a readable role chain, the provider checks the
role graph and source declarations before choosing credentials. An invalid
graph fails even when environment credentials are available. For a valid chain
with `credential_source = Environment`, the environment credential authorizes
the first STS call and the chain returns its final role credential. Other valid
chains keep the environment-first order.

When a role chain runs, it uses its declared source and propagates acquisition
errors, including disabled required slots. A selected `credential_process`
source or web identity role gets its profile settings from the merged config and
credentials files. Explicit settings on the corresponding provider still apply.

## Internal State Model

Each builder slot should be represented as:

```rust
Option<T>
```

with this meaning:

- `Some(T::default())`: slot enabled with the default provider configuration
- `Some(custom)`: slot enabled with a custom provider configuration
- `None`: slot removed from the chain

This implies:

- `DefaultCredentialProviderBuilder::default()` initializes all documented
  default slots to `Some(T::default())`.
- `.no_env()` sets `env` to `None`.
- `.env(provider)` sets `env` to `Some(provider)`.
- `build()` pushes only `Some(...)` slots and skips `None`.

No separate `enabled` flag is needed.

## Slot Naming

Use provider-concept names without the `CredentialProvider` suffix.

Examples:

- `env`
- `profile`
- `sso`
- `process`
- `ecs`
- `imds`
- `web_identity`
- `oidc`
- `config_file`
- `vm_metadata`

Do not collapse distinct concepts under a vague shared name.

Examples:

- Prefer `web_identity(...)` over `assume_role(...)` when the slot is actually
  `AssumeRoleWithWebIdentityCredentialProvider`.
- Prefer `oidc(...)` over `assume_role(...)` when the slot is specifically
  OIDC-based.

## Service Examples

### AWS V4

```rust
let provider = DefaultCredentialProvider::builder()
    .no_env()
    .profile(ProfileCredentialProvider::new().with_profile("prod"))
    .no_imds()
    .build();
```

Expected slots:

- `env`
- `profile`
- `sso`
- `web_identity`
- `process`
- `ecs`
- `imds`

### Aliyun OSS

```rust
let provider = DefaultCredentialProvider::builder()
    .env(EnvCredentialProvider::new())
    .no_oidc()
    .build();
```

Expected slots:

- `env`
- `oidc`

### Tencent COS

```rust
let provider = DefaultCredentialProvider::builder()
    .no_env()
    .web_identity(AssumeRoleWithWebIdentityCredentialProvider::new())
    .build();
```

Expected slots:

- `env`
- `web_identity`

## Migration Rules

When changing an existing service:

1. Confirm that default construction can discover a documented credential
   source. If it cannot, remove the empty default provider and builder instead
   of keeping them for API uniformity.
2. Remove all public `configure_*` methods.
3. Remove all public `disable_*(bool)` methods.
4. Initialize builder defaults with `Some(T::default())` for documented default
   slots.
5. Add `slot(provider)` and `no_slot()` methods for every supported slot.
6. Update tests to verify that `no_slot()` truly removes the provider from the
   chain.
7. Update examples and docs to use slot/no-slot APIs only.

### Removing an empty default provider

Translate existing composition without changing its error behavior:

- A single `push_front(provider)` becomes the provider itself. Passing it
  directly to `Signer::new` or `Signer::with_credential_provider` keeps the
  fail-closed behavior, including returning that provider's error.
- `with_chain(chain)` becomes the chain itself. `ProvideCredentialChain`
  implements `ProvideCredential` and keeps its existing permissive error
  policy.
- More than one `push_front` was an intentional composition: providers were
  tried last-added-first, an error was returned immediately, `None` advanced to
  the next provider, and then the service's documented chain, if any, ran last.
  `ProvideCredentialChain` is not equivalent because it treats a provider error
  as "try the next source". Callers that need the original ordering and error
  propagation must keep that composition in a caller-owned
  `ProvideCredential` implementation. An empty `ProvideCredentialChain` remains
  available when a caller deliberately wants a provider that yields no
  credential.

## Non-Goals

- This document does not require a repository-wide refactor in one patch.
- This document does not require every service to expose the same set of
  provider slots.
- This document does not remove `with_chain` or `push_front`; those remain the
  escape hatch for advanced composition.
