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

//! Koofr service support with convenience APIs.
//!
//! Koofr does not publish a production environment-variable credential
//! convention, so [`default_signer`] requires the caller to supply the account
//! email and an application-specific password explicitly.

pub use reqsign_koofr::*;

use crate::{Context, Signer};

/// Default Koofr signer type with the login credential exchange.
pub type DefaultSigner = Signer<Credential>;

/// Create a Koofr signer with the official API endpoint.
///
/// The signer exchanges the supplied email and application-specific password
/// for an access token at `https://app.koofr.net/token`, caches the token in
/// the signer, and adds `Authorization: Token token=<token>` to each request.
/// Use `LoginCredentialProvider::with_endpoint` with a custom provider for a
/// Koofr-compatible API.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::koofr::default_signer(
///     ctx,
///     "me@example.com",
///     "application-specific-password",
/// );
///
/// let mut request = http::Request::get(
///     "https://app.koofr.net/api/v2/mounts/primary/files/list?path=%2F",
/// )
/// .body(())
/// .unwrap()
/// .into_parts()
/// .0;
///
/// signer.sign(&mut request, None).await?;
/// # Ok(())
/// # }
/// ```
pub fn default_signer(ctx: Context, email: &str, app_password: &str) -> DefaultSigner {
    Signer::new(
        ctx,
        LoginCredentialProvider::new(email, app_password),
        RequestSigner,
    )
}
