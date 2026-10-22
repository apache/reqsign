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
//! credentials, signs OpenStack service requests with the resulting token, and
//! keeps the service catalog that Keystone returns for a scoped token so that
//! callers can resolve the endpoint of a service such as Swift.
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
//!     // The default chain reads OS_AUTH_URL, OS_USERNAME, and OS_PASSWORD.
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
//! Authentication with explicit credentials and endpoint lookup from the
//! catalog are available through [`KeystoneCredentialProvider`] and
//! [`Credential::endpoint_in_region`].

mod credential;
pub use credential::{CatalogEntry, Credential, Endpoint};

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, EnvCredentialProvider,
    KeystoneCredentialProvider,
};
