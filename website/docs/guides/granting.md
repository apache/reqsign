---
title: Scoped credential granting
sidebar_label: Credential granting
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

Granting exchanges a broad credential for a narrower one *before* any request
is signed: scoped to a bucket, a prefix, a permission, a time window. Vendor
SDKs rarely give these operations a common shape; Reqsign's
[`Granter`](/docs/architecture/#granter-and-grantcredential) does, while keeping each provider's
semantics explicit.

## The operations

| Provider | Operation | Scopes to |
| --- | --- | --- |
| AWS SigV4 | S3 Access Grants (`GetDataAccess`) | A registered grant: location, prefix, permission |
| AWS SigV4 | S3 Express Session (`CreateSession`) | One directory bucket, read-only or read-write |
| Azure Storage | User delegation SAS | Container/blob, permissions, validity window |
| Google Cloud | Credential Access Boundary (server-side) | Buckets/prefixes via an STS exchange |
| Google Cloud | Credential Access Boundary (client-side) | Same, derived locally without an STS round-trip |

Each operation is listed with source references on its
[provider page](/docs/providers/).

## Walkthrough: S3 Express session credentials

The same dependencies as [Getting Started](/docs/getting-started/) suffice.
This example uses the default context for environment, file, and HTTP access:

```rust file=reqsign/examples/s3_express_grant.rs
```

## Signing with automatically refreshed sessions

For a long-lived signer, use `S3ExpressSessionProvider`. It performs the same
CreateSession exchange when credentials are needed, preserves their expiration,
and lets `Signer` refresh the session. S3 Express uses the `s3express` signing
service and the directory bucket's zonal endpoint:

```rust file=reqsign/examples/s3_express_sign.rs
```

When passing a manually granted credential to another component, retain the
entire credential, including `expires_in`. Reconstructing it with AWS's
`StaticCredentialProvider` loses the expiration and automatic refresh behavior.
Keep granted keys and session tokens out of logs.

## Semantics to rely on

- The **source** credential is cached and revalidated per grant; the granted
  result owns independent material and never aliases the cache.
- `expires_in` requests a validity window where the operation supports one;
  the operation's own maximum applies.
- Errors returned by the configured source or grant operation propagate without
  retry or reuse of a stale cached source. A source configured as a credential
  chain can still fall back between its providers.

Credential fields and types are provider-specific — see
[docs.rs](https://docs.rs/reqsign-aws-v4) for the exact API.
