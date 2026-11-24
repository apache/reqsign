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

//! Upyun request signing for reqsign.
//!
//! Upyun REST API requests authenticate with
//! `Authorization: UPYUN <operator>:<signature>` and a `Date` header. The
//! signature is
//!
//! ```text
//! base64(HMAC-SHA1(MD5(password), METHOD&URI&DATE[&CONTENT-MD5]))
//! ```
//!
//! `RequestSigner` signs the request's wire path and includes `Content-MD5`
//! when the caller already added it to the request. The signed URI is the wire
//! path exactly as supplied: the signer does not decode, normalize, or rebuild
//! it, and makes no claim about server-side path rewriting. It does not
//! construct requests, choose endpoints, sign query-string authentication, or
//! send anything over the network.
//!
//! ## Crypto
//!
//! Signing resolves a [`CryptoProvider`](reqsign_core::crypto::CryptoProvider)
//! through the supplied [`Context`](reqsign_core::Context). It requires the
//! provider's optional MD5 operation and its HMAC-SHA1 operation. A provider
//! that does not implement MD5, such as a FIPS-restricted backend, returns
//! [`ErrorKind::ConfigInvalid`](reqsign_core::ErrorKind::ConfigInvalid) and the
//! signer does not fall back to another implementation.
//!
//! ```no_run
//! use reqsign_core::{Context, Signer};
//! use reqsign_crypto_rustcrypto::RustCryptoProvider;
//! use reqsign_upyun::{RequestSigner, StaticCredentialProvider};
//!
//! # async fn example() -> reqsign_core::Result<()> {
//! let ctx = Context::new().with_crypto(RustCryptoProvider::new());
//! let signer = Signer::new(
//!     ctx,
//!     StaticCredentialProvider::new("operator", "password"),
//!     RequestSigner::new(),
//! );
//!
//! let mut req = http::Request::put("https://v0.api.upyun.com/bucket/object.txt")
//!     .body(())
//!     .unwrap()
//!     .into_parts()
//!     .0;
//!
//! signer.sign(&mut req, None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Credential sources
//!
//! - [`StaticCredentialProvider`] uses credentials supplied by the caller.
//! - [`UpxConfigCredentialProvider`] reads a session from the Upyun CLI (`upx`)
//!   configuration at `~/.upx.cfg`. The file is bucket-scoped; use
//!   `UpxConfigCredentialProvider::with_bucket` to select the session for the
//!   request's bucket. The discovered credential carries that bucket, and every
//!   signature requires the first segment of the request's wire path to exactly
//!   equal that bucket.
//! - [`DefaultCredentialProvider`] uses the current Upyun CLI session by
//!   default. The facade `default_signer(ctx, bucket)` pins discovery to the
//!   request's bucket, and the signer enforces the selected scope.

mod credential;
pub use credential::Credential;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, StaticCredentialProvider,
    UpxConfigCredentialProvider,
};

mod sign_request;
pub use sign_request::RequestSigner;

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn test_context() -> reqsign_core::Context {
    reqsign_core::Context::new().with_crypto(reqsign_crypto_rustcrypto::RustCryptoProvider::new())
}
