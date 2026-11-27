---
title: Getting Started
sidebar_label: Getting Started
description: Install Reqsign and sign your first cloud request in five minutes.
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

Five minutes from an empty project to a signed AWS request. The same shape
works for every provider — only the entry point differs.

## 1. Install

Add the `reqsign` facade with the feature for each provider you need
(features are additive):

```bash
cargo add reqsign --features aws
cargo add tokio --features full
cargo add http anyhow
```

| Feature | Enables |
| --- | --- |
| `aws` | AWS SigV4 (alias of `aws-v4`) |
| `aws-v4a` | AWS SigV4a multi-region signing |
| `aws-bearer` | AWS HTTP Bearer token authentication |
| `azure` | Azure Storage |
| `b2` | Backblaze B2 Native API |
| `baidu-netdisk` | Baidu Netdisk |
| `cloudflare` | Cloudflare API (KV, D1) |
| `dropbox` | Dropbox |
| `github` | GitHub.com |
| `google` | Google Cloud |
| `aliyun` | Aliyun OSS |
| `aliyun-drive` | Aliyun Drive Open Platform |
| `huaweicloud` | Huawei Cloud OBS |
| `http-message-signatures` | RFC 9421 request signatures |
| `oauth2` | Shared OAuth 2.0 refresh-token grant |
| `onedrive` | OneDrive |
| `openstack` | OpenStack Keystone |
| `oracle` | Oracle Cloud |
| `seafile` | Seafile |
| `tencent` | Tencent COS |
| `upyun` | Upyun |
| `vercel` | Vercel Blob and Artifacts |
| `volcengine` | Volcengine TOS |
| `yandex-disk` | Yandex Disk |
| `full` | Everything above |

The default features include `default-context`, which wires a ready-to-use
runtime (Tokio file reading, reqwest HTTP, Tokio command execution), and
`default-crypto`, which lets `default_context()` bind RustCrypto when no
process-wide provider is installed. The facade has no algorithm features: with
`default-crypto`, `aws-v4a` selects `p256`; `azure`, `google`, `oracle`, and
`http-message-signatures` select `rsa`; other service features use only the
unconditional hash and HMAC operations. A service feature alone does not pull
the crypto backend. Keep `default-context` unless you are
[bringing your own runtime](/docs/guides/custom-runtimes/); a custom context
must bind a `CryptoProvider` explicitly. Client-side Google Credential Access
Boundary generation requires the `credential-access-boundary-client-side`
feature on `reqsign-google` directly, a provider that supports AES-GCM, and an
`HttpSend` transport for the STS exchange; the facade `google` feature covers
request signing and server-side CAB. Requires
Rust 1.87.0+.

## 2. Sign your first request

This is the repository's compiled example — CI builds it on every commit:

```rust file=reqsign/examples/aws.rs
```

Three things happen here:

1. `default_context()` builds the default runtime context, and
   `aws::default_signer(ctx, "s3", "us-east-1")` composes it with AWS's full
   credential chain — environment variables, shared profiles, SSO, ECS, IMDS,
   and more. Reuse the same `Context` across multiple signers by cloning it.
   See [Loading credentials](/docs/guides/credentials/).
2. The request is built with the plain `http` crate. Reqsign signs
   `http::request::Parts` directly — there is no wrapper client to adopt.
3. `signer.sign(&mut req, None).await?` mutates the request head in place,
   adding the `Authorization` header and companions. Passing
   `Some(duration)` instead selects query authentication where the provider
   supports it — see [Presigning](/docs/guides/presigning/).

## 3. Run it

```bash
AWS_ACCESS_KEY_ID=AKIDEXAMPLE \
AWS_SECRET_ACCESS_KEY=example-secret \
cargo run
```

The example signs the request and prints a confirmation; sending it is your
HTTP client's job. Any placeholder credentials produce a structurally valid
signature — the service rejects them, but the wire format is real.

## Every provider, one pattern

Swap the entry point and the rest of the code stays the same. Each entry
composes that provider's documented credential sources, if any — the
[provider pages](/docs/providers/) document exactly which sources. Entries for
services without an ambient source take the required identity explicitly:

| Provider | Entry |
| --- | --- |
| [AWS SigV4](/docs/providers/aws-sigv4/) | `aws::default_signer(ctx, service, region)` |
| [AWS SigV4a](/docs/providers/aws-sigv4a/) | `aws::v4a::default_signer(ctx, service, region_set)` |
| [AWS HTTP Bearer](/docs/providers/aws-http-bearer/) | `aws::bearer::default_signer(ctx, signing_name)` |
| [Azure Storage](/docs/providers/azure-storage/) | `azure::default_signer(ctx)` |
| [Backblaze B2](/docs/providers/b2/) | `b2::default_signer(ctx)` |
| [Baidu Netdisk](/docs/providers/baidu-netdisk/) | `baidu_netdisk::default_signer(ctx, access_token)` |
| [Cloudflare](/docs/providers/cloudflare/) | `cloudflare::default_signer(ctx)` |
| [Dropbox](/docs/providers/dropbox/) | `dropbox::default_signer(ctx)` |
| [Vercel Blob](/docs/providers/vercel-blob/) | `vercel::default_blob_signer(ctx)` |
| [Vercel Artifacts](/docs/providers/vercel-artifacts/) | `vercel::default_artifacts_signer(ctx)` |
| [GitHub](/docs/providers/github/) | `github::default_signer(ctx)` |
| [OneDrive](/docs/providers/onedrive/) | `onedrive::default_signer(ctx, access_token)` |
| [Google Cloud](/docs/providers/google/) | `google::default_signer(ctx, service)` |
| [Aliyun OSS](/docs/providers/aliyun-oss/) | `aliyun::default_signer(ctx, bucket)` |
| [Aliyun Drive](/docs/providers/aliyun-drive/) | `aliyun_drive::default_signer(ctx, access_token)` |
| [Huawei Cloud OBS](/docs/providers/huaweicloud-obs/) | `huaweicloud::default_signer(ctx, bucket)` |
| [HTTP Message Signatures (RFC 9421)](/docs/providers/http-message-signatures/) | `http_message_signatures::RequestSigner::new(label, components)` |
| [OpenStack Keystone](/docs/providers/openstack-keystone/) | `openstack::default_signer(ctx)` |
| [Oracle Cloud](/docs/providers/oracle/) | `oracle::default_signer(ctx)` |
| [Seafile](/docs/providers/seafile/) | `seafile::default_signer(ctx)` |
| [Tencent COS](/docs/providers/tencent-cos/) | `tencent::default_signer(ctx)` |
| [Upyun](/docs/providers/upyun/) | `upyun::default_signer(ctx, bucket)` |
| [Volcengine TOS](/docs/providers/volcengine-tos/) | `volcengine::default_signer(ctx, region)` |
| [Yandex Disk](/docs/providers/yandex-disk/) | `yandex_disk::default_signer(ctx, access_token)` |

Aliyun Drive, OneDrive, and Yandex Disk have no documented ambient source.
Their facade entries take the access token explicitly, and their service crates
export no default provider or builder. For a refresh token or another explicit
provider, assemble `Signer::new(ctx, provider, RequestSigner)` directly instead
of passing a dummy token.

A default signer is an ordinary `Signer`: replace any component and keep the
rest —

```rust file=reqsign/examples/static_credentials.rs
```

## Where to go next

- Wire up credentials your way: [Loading credentials](/docs/guides/credentials/).
- Hand out URLs instead of headers: [Presigning](/docs/guides/presigning/).
- Understand the pieces you just used: [Architecture](/docs/architecture/).
- Check what your provider supports: [provider matrix](/docs/providers/).
