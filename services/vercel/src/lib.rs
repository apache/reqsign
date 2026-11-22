// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Vercel Blob and Artifacts token discovery and request signing for Reqsign.
//!
//! The two APIs share the `Authorization: Bearer <token>` wire format but use
//! different tokens, scopes, and endpoints. They therefore have separate
//! credential types, providers, and signers. A Blob credential cannot sign an
//! Artifacts request, and neither default provider falls back to the other
//! service's environment variables.
//!
//! ## Vercel Blob
//!
//! [`BlobCredential`], [`BlobDefaultCredentialProvider`], and
//! [`BlobRequestSigner`] cover Blob API requests authenticated with a read-write
//! token. The default provider reads only `BLOB_READ_WRITE_TOKEN`, the
//! long-lived token variable used by `@vercel/blob` when code runs outside
//! Vercel.
//!
//! The control-plane endpoint is caller-owned. Vercel's current SDK uses
//! `https://vercel.com/api/blob` for API calls, while blob content is served
//! from `*.blob.vercel-storage.com`. The pathname, method, access level, upload
//! options, and Blob API headers such as `x-api-version` are all part of the
//! request that the caller constructs.
//!
//! Vercel's OIDC (`VERCEL_OIDC_TOKEN` plus `BLOB_STORE_ID`) and client-token
//! flows need store or operation context in the request. This crate does not
//! discover or refresh them; those remain caller-managed credentials.
//!
//! ## Vercel Artifacts
//!
//! [`ArtifactsCredential`], [`ArtifactsDefaultCredentialProvider`], and
//! [`ArtifactsRequestSigner`] cover the Vercel Artifacts API used by the
//! Turborepo Remote Cache at `https://api.vercel.com/v8/artifacts/{hash}`.
//!
//! The default chain reads `TURBO_TOKEN`, the bearer token documented by
//! Turborepo for Remote Cache access, then `VERCEL_ARTIFACTS_TOKEN`, which
//! Vercel injects into its build environments. When both are present,
//! `TURBO_TOKEN` is tried first. `TURBO_TEAM`, `TURBO_TEAMID`, and
//! `VERCEL_ARTIFACTS_OWNER` select the cache scope in the request query and stay
//! with the caller. So do the cache key and headers such as
//! `x-artifact-duration`.
//!
//! Vercel also documents OIDC token exchange for CI. Reqsign accepts the
//! resulting bearer token but does not perform the exchange.
//!
//! ## Failure behavior
//!
//! Configured sources fail closed. A present but unusable token, or an invalid
//! prepended [`BlobStaticCredentialProvider`] or
//! [`ArtifactsStaticCredentialProvider`], returns an error instead of silently
//! selecting another identity. An absent token yields no credential, and signing
//! then reports `CredentialInvalid`.
//!
//! Signing inserts a sensitive `Authorization` header and leaves the URI and
//! every other header unchanged. Both APIs use header authentication only, so
//! signing rejects `expires_in`. Neither token has a readable expiry, and signing
//! writes no protocol time, so signing has no clock dependency.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, OsEnv, Result, Signer};
//! use reqsign_vercel::{
//!     ArtifactsDefaultCredentialProvider, ArtifactsRequestSigner,
//!     BlobDefaultCredentialProvider, BlobRequestSigner,
//! };
//!
//! # async fn example() -> Result<()> {
//! let ctx = Context::new().with_env(OsEnv);
//!
//! let blob = Signer::new(
//!     ctx.clone(),
//!     BlobDefaultCredentialProvider::new(),
//!     BlobRequestSigner,
//! );
//! let artifacts = Signer::new(
//!     ctx,
//!     ArtifactsDefaultCredentialProvider::new(),
//!     ArtifactsRequestSigner,
//! );
//!
//! // The caller owns the endpoint, pathname, cache key, and scope query.
//! let mut blob_req = http::Request::put(
//!     "https://vercel.com/api/blob/reports/2026%20Q1.csv?addRandomSuffix=0",
//! )
//! .body(())
//! .unwrap()
//! .into_parts()
//! .0;
//! blob.sign(&mut blob_req, None).await?;
//!
//! let mut artifact_req = http::Request::put(
//!     "https://api.vercel.com/v8/artifacts/example-hash?teamId=team_example",
//! )
//! .body(())
//! .unwrap()
//! .into_parts()
//! .0;
//! artifacts.sign(&mut artifact_req, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod bearer;

mod artifacts;
pub use artifacts::{
    ArtifactsCredential, ArtifactsDefaultCredentialProvider,
    ArtifactsDefaultCredentialProviderBuilder, ArtifactsEnvCredentialProvider,
    ArtifactsRequestSigner, ArtifactsStaticCredentialProvider,
    ArtifactsVercelEnvCredentialProvider,
};

mod blob;
pub use blob::{
    BlobCredential, BlobDefaultCredentialProvider, BlobDefaultCredentialProviderBuilder,
    BlobEnvCredentialProvider, BlobRequestSigner, BlobStaticCredentialProvider,
};
