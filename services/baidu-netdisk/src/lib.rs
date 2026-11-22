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

//! Baidu Netdisk Open Platform access-token credentials and request signing.
//!
//! Baidu Netdisk's xpan APIs authenticate requests with an `access_token`
//! query parameter. [`Credential`] holds the token,
//! [`StaticCredentialProvider`] supplies an explicitly configured token, and
//! [`RequestSigner`] adds the form-encoded parameter to the request URI.
//!
//! ## Credential discovery
//!
//! This crate does not read an environment variable, well-known credential
//! file, or OAuth token endpoint for Baidu Netdisk. The caller obtains an
//! access token through Baidu's Open Platform authorization flow and supplies
//! it explicitly. OAuth refresh, single-use refresh-token rotation, and token
//! persistence stay with the caller and are not part of this crate.
//!
//! The token is a secret. `Debug` output for [`Credential`] and
//! [`StaticCredentialProvider`] never contains it. A token without an expiry
//! is reused for the lifetime of the [`reqsign_core::Signer`]. Replacing the
//! signer's credential provider starts a new cache.
//!
//! ## Request ownership
//!
//! The caller owns the API host, method, path, other query parameters,
//! headers (including `User-Agent`), and request body. Signing removes any
//! existing `access_token` query parameter and appends one encoded
//! `access_token` parameter. It preserves the raw representation and order of
//! unrelated query parameters, including existing percent escapes, duplicate
//! keys, empty values, and literal `+` characters. All headers are preserved.
//!
//! Because the access token appears in the request URI, treat signed URLs,
//! logs that include the URI, and error output as secret-bearing material. Do
//! not forward a signed request to an unrelated host. Query authentication has
//! no separate presign lifetime in this crate, so signing rejects
//! `expires_in`.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, Result, Signer};
//! use reqsign_baidu_netdisk::{RequestSigner, StaticCredentialProvider};
//!
//! # async fn example() -> Result<()> {
//! let signer = Signer::new(
//!     Context::new(),
//!     StaticCredentialProvider::new("baidu-netdisk-access-token"),
//!     RequestSigner,
//! );
//!
//! let mut req = http::Request::get(
//!     "https://pan.baidu.com/rest/2.0/xpan/file?method=list&dir=%2Fapps%2FMyApp",
//! )
//! .body(())
//! .unwrap()
//! .into_parts()
//! .0;
//!
//! signer.sign(&mut req, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod credential;
pub use credential::Credential;

mod provide_credential;
pub use provide_credential::StaticCredentialProvider;

mod sign_request;
pub use sign_request::RequestSigner;
