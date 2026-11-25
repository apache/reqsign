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

//! Aliyun Drive Open Platform service support with convenience APIs.
//!
//! The credential providers cover a caller-managed access token and Aliyun
//! Drive's JSON refresh-token exchange. The drive ID, file paths, upload URLs,
//! request bodies, and storage API requests stay in the caller's code.

pub use reqsign_aliyun_drive::*;

use crate::{Context, Signer};

/// Default Aliyun Drive signer type with an explicit static access token.
pub type DefaultSigner = Signer<Credential>;

/// Create an Aliyun Drive signer with an explicit access token.
///
/// Aliyun Drive Open Platform does not define an ambient CLI, SDK, environment,
/// or file credential contract, so there is no default provider to discover
/// one. This helper selects [`StaticCredentialProvider`] for a caller-managed
/// token and [`RequestSigner`].
///
/// For a confidential-client refresh token or another explicit provider,
/// assemble the signer directly instead of passing a dummy token:
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # fn example(ctx: reqsign::Context) -> reqsign_core::Result<()> {
/// use reqsign::{Signer, aliyun_drive};
///
/// let provider = aliyun_drive::RefreshCredentialProvider::new(
///     "client-id",
///     "client-secret",
///     "refresh-token",
/// )?;
/// let signer = Signer::new(ctx, provider, aliyun_drive::RequestSigner);
/// # let _ = signer;
/// # Ok(())
/// # }
/// ```
///
/// Official PKCE public clients receive an access token, not a refresh token.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// use reqsign::aliyun_drive::default_signer;
///
/// let ctx = reqsign::default_context();
/// let signer = default_signer(ctx, "access-token");
///
/// // The caller owns the drive ID, path, and request body.
/// let mut req = http::Request::builder()
///     .method("POST")
///     .uri("https://openapi.alipan.com/adrive/v1.0/openFile/get_by_path")
///     .header(http::header::USER_AGENT, "my-application")
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
