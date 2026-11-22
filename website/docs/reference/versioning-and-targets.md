---
title: Versioning and targets
sidebar_label: Versioning & targets
description: Version tracks across the Reqsign crates, and the supported Rust and WASM targets.
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

## Versioning

Reqsign publishes many crates on five tracks:

| Track | Crates | Scheme |
| --- | --- | --- |
| Core + established services | `reqsign-core`, `reqsign-aws-core`, every established `reqsign-<provider>` service crate, `reqsign-http-message-signatures`, `reqsign-file-read-tokio`, `reqsign-command-execute-tokio` | Lockstep major (currently `4.x`) |
| Provider and shared crates | `reqsign-b2`, `reqsign-aliyun-drive`, `reqsign-baidu-netdisk`, `reqsign-cloudflare`, `reqsign-dropbox`, `reqsign-github`, `reqsign-koofr`, `reqsign-oauth2`, `reqsign-onedrive`, `reqsign-seafile`, `reqsign-upyun`, `reqsign-vercel`, `reqsign-yandex-disk`, and later crates introduced after the lockstep line | Independent major, starting at `1.0.0` |
| Crypto backends | `reqsign-crypto-rustcrypto`, `reqsign-crypto-boring` | Independent major, starting at `1.0.0` |
| Reqwest adapter | `reqsign-http-send-reqwest` | Independent major (currently `5.x`), offset from the core major so reqwest major bumps do not force a core major |
| Facade | `reqsign` | Independent (currently `0.21.x`) |

Lockstep means any `4.x` established service crate composes with any `4.x`
core. Provider and shared crates start at `1.0.0` and depend on the current
core major, so a `1.x` crate composes with `4.x` core. Crypto backends version
independently of both, and the reqwest adapter moves to a new major when the
core lockstep major changes, one major ahead. Mixing core majors fails to
compile — the trait definitions are the compatibility boundary, and Cargo
enforces it.

Applications should depend on the facade and let it pin compatible
components; libraries should depend on `reqsign-core` plus their service
crates with major-only bounds, leaving context implementations to the
application:

```toml
# Application:
reqsign = { version = "0.21", features = ["aws"] }

# Library:
reqsign-core = "4"
reqsign-aws-v4 = "4"
```

Every release ships as an ASF source release plus crates.io packages — see
[Download](/download/). Release notes and migration steps for breaking
majors are published with each
[GitHub release](https://github.com/apache/reqsign/releases).

## Targets

**Rust version.** The workspace declares `rust-version = "1.87.0"` — the
minimum supported Rust. The RustCrypto backend's `rsa 0.10` dependency
requires this version. CI tracks stable; MSRV bumps are treated as
observable changes, not patch-level noise.

**Native.** Reqsign is pure Rust with no C dependencies of its own; CI
exercises Linux, macOS, and Windows. The default context components (Tokio
file reading and command execution, reqwest HTTP) run wherever those crates
do.

**WASM.** `wasm32-unknown-unknown` is a supported, CI-verified target for a
defined subset: `reqsign-core`, `reqsign-aws-core`, and the AWS SigV4, AWS
SigV4a, Azure Storage, GitHub, Aliyun OSS, Aliyun Drive, Backblaze B2,
Baidu Netdisk, Cloudflare, Vercel Blob, Vercel Artifacts, Tencent COS, Dropbox,
Koofr, OneDrive, Upyun, Yandex Disk, and Seafile providers. The shared
`reqsign-oauth2` crate and the `oauth2` facade feature are checked in the same
subset. Cloudflare and Vercel environment, static, and header signing work
without a JavaScript clock. Baidu Netdisk static query signing needs no
JavaScript clock. Seafile signing also needs no JavaScript clock. GitHub environment,
static, and anonymous signing work without a JavaScript clock; GitHub CLI
discovery needs a `CommandExecute` adapter and is unavailable in bare WASM
runtimes. Yandex Disk static credentials without an expiry and header signing
work without a JavaScript clock. Dropbox, OAuth2, Aliyun Drive, and OneDrive
runtime signing or refresh additionally requires a wasm-bindgen JavaScript host
for the clock; see the
[Custom runtimes & WASM guide](/docs/guides/custom-runtimes/). The
[provider matrix](/docs/providers/) is the authoritative per-provider
status.

**Async runtimes.** `reqsign-core` is runtime-agnostic — nothing in core
assumes Tokio. Runtime coupling lives only in the optional context crates;
swap them to run elsewhere.
