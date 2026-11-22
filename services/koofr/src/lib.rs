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

//! Koofr credential exchange and request signing for reqsign.
//!
//! Koofr authenticates API requests with
//! `Authorization: Token token=<access-token>`. The token is obtained by
//! the JSON exchange used by Koofr's first-party Go SDK and OpenDAL: an account
//! email and an application-specific password are posted to
//! `POST {endpoint}/token` with a JSON body:
//!
//! ```json
//! {"email":"me@example.com","password":"application-specific-password"}
//! ```
//!
//! A successful response is `{"token":"..."}`. Koofr's API Swagger documents
//! Bearer and app-password Basic schemes separately; it does not describe this
//! `/token` exchange. The exchange does not return an expiry, so the token stays
//! cached until the caller replaces the [`reqsign_core::Signer`] or installs a
//! provider/context that starts a new cache. Koofr rejecting the token does not
//! invalidate the cache automatically.
//!
//! Koofr's first-party SDKs do not define a production environment-variable
//! credential source. This crate therefore does not read ambient credentials:
//! configure [`LoginCredentialProvider`] or [`StaticCredentialProvider`]
//! explicitly. An explicit `http://` endpoint sends the email and application
//! password in cleartext; redirect policy belongs to the configured
//! [`reqsign_core::HttpSend`] adapter.
//!
//! Mount selection, file paths, and business requests remain caller-owned.
//!
//! # Example
//!
//! ```no_run
//! use reqsign_core::{Context, Signer};
//! use reqsign_koofr::{LoginCredentialProvider, RequestSigner};
//!
//! # async fn example() -> reqsign_core::Result<()> {
//! // Configure HttpSend and any other context components before signing.
//! let ctx = Context::new();
//! let signer = Signer::new(
//!     ctx,
//!     LoginCredentialProvider::new("me@example.com", "application-password"),
//!     RequestSigner,
//! );
//!
//! let mut request = http::Request::get(
//!     "https://app.koofr.net/api/v2/mounts/primary/files/list?path=%2F",
//! )
//! .body(())
//! .unwrap()
//! .into_parts()
//! .0;
//!
//! signer.sign(&mut request, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{LoginCredentialProvider, StaticCredentialProvider};
