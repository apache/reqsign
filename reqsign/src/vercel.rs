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

//! Vercel Blob and Artifacts support with convenience APIs.
//!
//! The two APIs use separate credentials and entry points. A Blob credential
//! never authenticates an Artifacts request, or the reverse.

pub use reqsign_vercel::*;

use crate::{Context, Signer};

/// Default Vercel Blob signer type with the documented credential chain.
pub type DefaultBlobSigner = Signer<BlobCredential>;

/// Create a default Vercel Blob signer with the supplied runtime context.
///
/// This composes:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()` when `default-context` is enabled)
/// - [`BlobDefaultCredentialProvider`], which reads `BLOB_READ_WRITE_TOKEN`
/// - [`BlobRequestSigner`], which adds a sensitive `Authorization: Bearer` header
///
/// The caller owns the endpoint, pathname, access level, upload options, and Blob
/// API headers.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::vercel::default_blob_signer(ctx);
///
/// let mut req = http::Request::put(
///     "https://vercel.com/api/blob/reports/2026%20Q1.csv?addRandomSuffix=0",
/// )
/// .body(())
/// .unwrap()
/// .into_parts()
/// .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_blob_signer(ctx: Context) -> DefaultBlobSigner {
    Signer::new(ctx, BlobDefaultCredentialProvider::new(), BlobRequestSigner)
}

/// Default Vercel Artifacts signer type with the documented credential chain.
pub type DefaultArtifactsSigner = Signer<ArtifactsCredential>;

/// Create a default Vercel Artifacts signer with the supplied runtime context.
///
/// This composes:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()` when `default-context` is enabled)
/// - [`ArtifactsDefaultCredentialProvider`], which reads `TURBO_TOKEN`, then `VERCEL_ARTIFACTS_TOKEN`
/// - [`ArtifactsRequestSigner`], which adds a sensitive `Authorization: Bearer` header
///
/// The caller owns the API endpoint, cache key, `teamId`/`slug` scope query, and
/// artifact headers.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::vercel::default_artifacts_signer(ctx);
///
/// let mut req = http::Request::put(
///     "https://api.vercel.com/v8/artifacts/example-hash?teamId=team_example",
/// )
/// .body(())
/// .unwrap()
/// .into_parts()
/// .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_artifacts_signer(ctx: Context) -> DefaultArtifactsSigner {
    Signer::new(
        ctx,
        ArtifactsDefaultCredentialProvider::new(),
        ArtifactsRequestSigner,
    )
}
