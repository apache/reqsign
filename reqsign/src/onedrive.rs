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

//! OneDrive service support with convenience APIs.
//!
//! Microsoft documents no automatic Microsoft Graph credential source, so the
//! default signer takes an explicit access token and this crate exports no
//! default provider. For the documented refresh exchange or another provider,
//! assemble a [`Signer`] directly.

pub use reqsign_onedrive::*;

use crate::{Context, Signer};

/// Default OneDrive signer type with an explicit static access token.
pub type DefaultSigner = Signer<Credential>;

/// Create a OneDrive signer with an explicit Microsoft Graph access token.
///
/// Microsoft documents no ambient Microsoft Graph user-token source, so there
/// is no default provider to discover one. This helper selects
/// [`StaticCredentialProvider`] and [`RequestSigner`], which adds a sensitive
/// `Authorization: Bearer` header. Tokens are short lived; use
/// [`StaticCredentialProvider::with_expires_at`] when the caller knows the
/// expiration.
///
/// For the documented Microsoft Entra refresh-token exchange or another
/// explicit provider, assemble the signer directly instead of passing a dummy
/// token:
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # fn example(ctx: reqsign::Context) -> reqsign_core::Result<()> {
/// use reqsign::{Signer, onedrive};
///
/// let provider = onedrive::RefreshCredentialProvider::new("client-id", "refresh-token")?;
/// let signer = Signer::new(ctx, provider, onedrive::RequestSigner);
/// # let _ = signer;
/// # Ok(())
/// # }
/// ```
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// use reqsign::onedrive::default_signer;
///
/// let ctx = reqsign::default_context();
/// let signer = default_signer(ctx, "graph-access-token");
///
/// // The caller owns the Microsoft Graph endpoint, drive path, and query.
/// let mut req = http::Request::get("https://graph.microsoft.com/v1.0/me/drive")
///     .body(())
///     .unwrap()
///     .into_parts()
///     .0;
///
/// signer.sign(&mut req, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_signer(ctx: Context, access_token: impl Into<String>) -> DefaultSigner {
    Signer::new(
        ctx,
        StaticCredentialProvider::new(access_token),
        RequestSigner,
    )
}
