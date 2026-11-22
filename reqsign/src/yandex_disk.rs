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

//! Yandex Disk support with convenience APIs.
//!
//! Yandex Disk documents no automatic OAuth credential source, so the default
//! signer takes the access token explicitly. Use a custom credential provider
//! when tokens rotate.

pub use reqsign_yandex_disk::*;

use crate::{Context, Signer};

/// Default Yandex Disk signer type with the explicit static credential source.
pub type DefaultSigner = Signer<Credential>;

/// Create a default Yandex Disk signer with the supplied runtime context and
/// OAuth access token.
///
/// This composes:
/// - The caller-supplied [`Context`] (for example `reqsign::default_context()` when `default-context` is enabled)
/// - [`DefaultCredentialProvider`] with [`StaticCredentialProvider`] prepended
/// - [`RequestSigner`], which adds a sensitive `Authorization: OAuth` header
///
/// Yandex Disk has no documented environment variable, CLI token store, or
/// well-known credential file, so the token is an explicit argument rather than
/// ambient discovery. The caller owns the API host, API version, resource path,
/// query parameters, and upload or download URLs.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::yandex_disk::default_signer(ctx, "yandex-disk-oauth-token");
///
/// let mut req = http::Request::get(
///     "https://cloud-api.yandex.net/v1/disk/resources?path=disk%3A%2Ffolder%2Ffile",
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
pub fn default_signer(ctx: Context, access_token: impl Into<String>) -> DefaultSigner {
    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(access_token));
    Signer::new(ctx, provider, RequestSigner)
}
