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

//! Backblaze B2 Native API support with convenience APIs.
//!
//! This module provides B2 account authorization and Native API request
//! signing, re-exported from `reqsign-b2`.

pub use reqsign_b2::*;

use crate::{Context, Signer};

/// Default Backblaze B2 signer type.
pub type DefaultSigner = Signer<Credential>;

/// Create a default Backblaze B2 signer with the supplied runtime context.
///
/// The signer uses:
/// - the caller-supplied [`Context`] (for example `reqsign::default_context()`
///   when `default-context` is enabled);
/// - the default credential provider, which reads `B2_APPLICATION_KEY_ID` and
///   `B2_APPLICATION_KEY` and calls `b2_authorize_account`;
/// - a request signer that inserts the Native API `Authorization` header.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::b2::default_signer(ctx);
///
/// let mut req = http::Request::get(
///     "https://api001.backblazeb2.com/b2api/v4/b2_list_buckets?accountId=account-id",
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
pub fn default_signer(ctx: Context) -> DefaultSigner {
    Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner)
}
