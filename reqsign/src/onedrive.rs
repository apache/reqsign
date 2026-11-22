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
//! default signer composes a default provider with an empty automatic chain.
//! Prepend an explicit provider before signing.

pub use reqsign_onedrive::*;

use crate::{Context, Signer};

/// Default OneDrive signer type with the documented default credential chain.
pub type DefaultSigner = Signer<Credential>;

/// Create a default OneDrive signer with the supplied runtime context.
///
/// This composes:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()`
///   when `default-context` is enabled)
/// - [`DefaultCredentialProvider`], whose automatic chain is empty because
///   Microsoft documents no ambient Microsoft Graph user-token source
/// - [`RequestSigner`], which adds a sensitive `Authorization: Bearer` header
///
/// Configure the credential through the default provider instead of letting
/// Reqsign guess. Prepend the provider for the flow you chose with
/// `DefaultCredentialProvider::push_front`, or replace the provider entirely:
///
/// - `DefaultCredentialProvider::new().push_front(RefreshCredentialProvider::new(..)?)`
///   for the documented Microsoft Entra refresh-token exchange
/// - `DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(..))`
///   for a caller-managed access token
///
/// Both paths replace the signer's provider with
/// [`Signer::with_credential_provider`](reqsign_core::Signer::with_credential_provider),
/// which also resets the credential cache.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// use reqsign::onedrive::{DefaultCredentialProvider, StaticCredentialProvider, default_signer};
///
/// let ctx = reqsign::default_context();
/// let provider = DefaultCredentialProvider::new()
///     .push_front(StaticCredentialProvider::new("graph-access-token"));
/// let signer = default_signer(ctx).with_credential_provider(provider);
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
pub fn default_signer(ctx: Context) -> DefaultSigner {
    Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner)
}
