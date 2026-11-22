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

//! OpenStack Keystone authentication for reqsign.
//!
//! This crate authenticates against the Keystone v3 identity API with password
//! credentials or accepts a pre-issued token, signs OpenStack service requests
//! with the resulting token, and keeps the service catalog that Keystone
//! returns for a scoped token so that callers can resolve the endpoint of a
//! service such as Swift.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_core::{Context, OsEnv, Result, Signer};
//! use reqsign_file_read_tokio::TokioFileRead;
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use reqsign_openstack_keystone::{DefaultCredentialProvider, RequestSigner};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let ctx = Context::new()
//!         .with_file_read(TokioFileRead)
//!         .with_http_send(ReqwestHttpSend::default())
//!         .with_env(OsEnv);
//!
//!     // The default chain reads OS_AUTH_TOKEN, or OS_AUTH_URL, OS_USERNAME,
//!     // and OS_PASSWORD for password authentication.
//!     let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
//!
//!     let mut req =
//!         http::Request::get("https://swift.example.com/v1/AUTH_test/container/object")
//!             .body(())
//!             .unwrap()
//!             .into_parts()
//!             .0;
//!
//!     signer.sign(&mut req, None).await?;
//!     Ok(())
//! }
//! ```
//!
//! A non-empty `OS_AUTH_TOKEN` takes priority over password authentication and
//! makes no Keystone request. Authentication with explicit credentials,
//! pre-issued tokens, and endpoint lookup from the catalog are available through
//! [`KeystoneCredentialProvider`], [`StaticCredentialProvider`], and
//! [`Credential::endpoint_in_region`].
//!
//! ## Swift TempURL
//!
//! [`TempUrlSigner`] creates Swift TempURLs with an explicit account or
//! container key. TempURL signing never uses the Keystone `X-Auth-Token` as its
//! key and does not require a [`Signer`](reqsign_core::Signer). The signature
//! covers the request method, the integer expiration time, and the object path
//! after decoding percent escapes once, matching Swift's decoded request path.
//! The outgoing URI keeps its encoded path and query bytes and order. Existing
//! non-auth query parameters are preserved, and existing TempURL authentication
//! parameters are rejected even when their names are percent-encoded.
//!
//! Current Swift accepts the algorithm-tagged Base64 form emitted for SHA-1,
//! SHA-256, and SHA-512, subject to the deployment's
//! `tempurl.allowed_digests`. Historical middleware that accepts only raw
//! hexadecimal SHA-1 is not supported. Swift also rebuilds the downstream query
//! string and filters incoming headers according to its configuration, so
//! arbitrary query or header forwarding through TempURL is not guaranteed.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use reqsign_core::{Context, Result};
//! use reqsign_crypto_rustcrypto::RustCryptoProvider;
//! use reqsign_openstack_keystone::TempUrlSigner;
//!
//! # fn main() -> Result<()> {
//! let ctx = Context::new().with_crypto(RustCryptoProvider::new());
//! let signer = TempUrlSigner::new("account-tempurl-key");
//! let uri = "https://swift.example.com/v1/AUTH_test/container/object"
//!     .parse()
//!     .unwrap();
//! let presigned = signer.presign(
//!     &ctx,
//!     &http::Method::GET,
//!     &uri,
//!     Duration::from_secs(3600),
//! )?;
//! # let _ = presigned;
//! # Ok(())
//! # }
//! ```

mod credential;
pub use credential::{CatalogEntry, Credential, Endpoint};

mod sign_request;
pub use sign_request::RequestSigner;

mod temp_url;
pub use temp_url::{TempUrlHashAlgorithm, TempUrlKey, TempUrlSigner};

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, EnvCredentialProvider,
    KeystoneCredentialProvider, StaticCredentialProvider,
};
