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

//! Upyun service support with convenience APIs.
//!
//! This module provides Upyun request signing along with convenience
//! functions for common use cases.

// Re-export all Upyun signing types.
pub use reqsign_upyun::*;

use crate::{Context, Signer};

/// Default Upyun Signer type with commonly used components.
pub type DefaultSigner = Signer<Credential>;

/// Create a default Upyun signer with the supplied runtime context and bucket.
///
/// The default credential chain reads the Upyun CLI (`upx`) session for
/// `bucket` from `~/.upx.cfg`. A matching current session is preferred; if the
/// current session belongs to another bucket, the first session for `bucket`
/// is selected. The discovered credential carries the bucket scope, and every
/// signature requires the first segment of the request's wire path to exactly
/// equal that bucket, including after the credential is cached. Use
/// [`Signer::with_credential_provider`] to install explicit credentials or
/// another source.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// use reqsign::upyun::StaticCredentialProvider;
///
/// let ctx = reqsign::default_context();
/// let signer = reqsign::upyun::default_signer(ctx, "bucket")
///     .with_credential_provider(StaticCredentialProvider::new("operator", "password"));
///
/// let mut req = http::Request::put("https://v0.api.upyun.com/bucket/object.txt")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_signer(ctx: Context, bucket: impl Into<String>) -> DefaultSigner {
    let provider = DefaultCredentialProvider::builder()
        .upx_config(UpxConfigCredentialProvider::new().with_bucket(bucket))
        .build();
    let signer = RequestSigner::new();
    Signer::new(ctx, provider, signer)
}
