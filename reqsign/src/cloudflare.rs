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

//! Cloudflare service support with convenience APIs.
//!
//! The signer covers Cloudflare API v4 requests authenticated with an API token,
//! including the KV and D1 endpoints. The account, database, and namespace
//! identifiers belong to the request URL that the caller builds.

pub use reqsign_cloudflare::*;

use crate::{Context, Signer};

/// Default Cloudflare signer type with the documented credential chain.
pub type DefaultSigner = Signer<Credential>;

/// Create a default Cloudflare signer with the supplied runtime context.
///
/// This function creates a signer with:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()` when `default-context` is enabled)
/// - The default credential provider, which reads `CLOUDFLARE_API_TOKEN`
/// - [`RequestSigner`], which adds a sensitive `Authorization: Bearer` header
///
/// The credential provider fails closed: an unusable configured token is an
/// error rather than a silent switch to another identity. Replace the provider
/// with [`StaticCredentialProvider`] when the token is managed explicitly.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::cloudflare::default_signer(ctx);
///
/// // The caller owns the account, namespace, and key.
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://api.cloudflare.com/client/v4/accounts/my-account/storage/kv/namespaces/my-namespace/values/my-key")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_signer(ctx: Context) -> DefaultSigner {
    Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner)
}
