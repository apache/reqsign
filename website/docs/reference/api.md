---
title: API Reference
sidebar_label: API Reference
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

Precise, per-item API documentation lives on docs.rs, generated from the
source of every release. This site owns concepts, guides, and contracts; the
rustdoc owns signatures.

## Facade

- [`reqsign`](https://docs.rs/reqsign) — feature-gated entry point with
  `default_context()` and per-provider `default_signer` modules.

## Core

- [`reqsign-core`](https://docs.rs/reqsign-core) — `Context`, `Signer`,
  `Granter`, the `ProvideCredential` / `SignRequest` / `GrantCredential` /
  `SigningCredential` traits, and the `crypto::CryptoProvider` contract.

## Service crates

- [`reqsign-aws-v4`](https://docs.rs/reqsign-aws-v4)
- [`reqsign-aws-v4a`](https://docs.rs/reqsign-aws-v4a)
- [`reqsign-aws-core`](https://docs.rs/reqsign-aws-core) — shared AWS
  credential chain and canonicalization
- [`reqsign-azure-storage`](https://docs.rs/reqsign-azure-storage)
- [`reqsign-dropbox`](https://docs.rs/reqsign-dropbox)
- [`reqsign-vercel`](https://docs.rs/reqsign-vercel)
- [`reqsign-google`](https://docs.rs/reqsign-google)
- [`reqsign-aliyun-oss`](https://docs.rs/reqsign-aliyun-oss)
- [`reqsign-huaweicloud-obs`](https://docs.rs/reqsign-huaweicloud-obs)
- [`reqsign-openstack-keystone`](https://docs.rs/reqsign-openstack-keystone)
- [`reqsign-oracle`](https://docs.rs/reqsign-oracle)
- [`reqsign-tencent-cos`](https://docs.rs/reqsign-tencent-cos)
- [`reqsign-volcengine-tos`](https://docs.rs/reqsign-volcengine-tos)

## Shared token support

- [`reqsign-oauth2`](https://docs.rs/reqsign-oauth2) — RFC 6749
  refresh-token grants and Bearer access tokens shared by OAuth 2.0 service
  crates

## Crypto providers

- [`reqsign-crypto-rustcrypto`](https://docs.rs/reqsign-crypto-rustcrypto) —
  pure-Rust provider, including the supported WASM subset
- [`reqsign-crypto-boring`](https://docs.rs/reqsign-crypto-boring) — native
  BoringSSL provider, built outside the main workspace

## Context components

- [`reqsign-file-read-tokio`](https://docs.rs/reqsign-file-read-tokio)
- [`reqsign-http-send-reqwest`](https://docs.rs/reqsign-http-send-reqwest)
- [`reqsign-command-execute-tokio`](https://docs.rs/reqsign-command-execute-tokio)
