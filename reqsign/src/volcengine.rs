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

//! Volcengine TOS service support with convenience APIs
//!
//! This module provides Volcengine TOS signing functionality along with convenience
//! functions for common use cases.

// Re-export all Volcengine TOS signing types
pub use reqsign_volcengine_tos::*;

use crate::{Context, Signer};

/// Default Volcengine TOS Signer type with commonly used components
pub type DefaultSigner = Signer<Credential>;

/// Create a default Volcengine TOS signer with the supplied runtime context.
///
/// This function creates a signer with:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()` when `default-context` is enabled)
/// - Default credential provider (reads from env vars)
/// - Request signer for the specified region
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::volcengine::default_signer(ctx, "cn-beijing");
///
/// // Sign a request
/// let mut req = http::Request::builder()
///     .method("GET")
///     .uri("https://mybucket.tos-cn-beijing.volces.com/myobject")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_signer(ctx: Context, region: &str) -> DefaultSigner {
    let provider = DefaultCredentialProvider::new();
    let signer = RequestSigner::new(region);
    Signer::new(ctx, provider, signer)
}
