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

//! Baidu Netdisk Open Platform support with convenience APIs.
//!
//! Baidu Netdisk does not publish an ambient access-token source for this
//! crate, so [`default_signer`] requires the caller to supply an authorized
//! access token explicitly.

pub use reqsign_baidu_netdisk::*;

use crate::{Context, Signer};

/// Default Baidu Netdisk signer type with a static access token.
pub type DefaultSigner = Signer<Credential>;

/// Create a Baidu Netdisk signer with an explicit access token.
///
/// The signer adds the form-encoded `access_token` query parameter to each
/// request and removes any existing `access_token` parameter first. Other
/// query parameters and all headers are preserved. OAuth refresh and token
/// persistence stay with the caller.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "default-context")]
/// # async fn example() -> reqsign_core::Result<()> {
/// let ctx = reqsign::default_context();
/// let signer = reqsign::baidu_netdisk::default_signer(ctx, "baidu-netdisk-access-token");
///
/// let mut request = http::Request::get(
///     "https://pan.baidu.com/rest/2.0/xpan/file?method=list&dir=%2Fapps%2FMyApp",
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
pub fn default_signer(ctx: Context, access_token: impl Into<String>) -> DefaultSigner {
    Signer::new(
        ctx,
        StaticCredentialProvider::new(access_token),
        RequestSigner,
    )
}
