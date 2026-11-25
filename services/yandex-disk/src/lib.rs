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

//! Yandex Disk OAuth access-token credentials and request signing for Reqsign.
//!
//! The Yandex Disk REST API authenticates requests with
//! `Authorization: OAuth <access token>`. [`Credential`] holds the token as an
//! opaque [`AccessToken`], [`RequestSigner`] inserts that header, and
//! [`StaticCredentialProvider`] supplies an explicitly configured token.
//!
//! ## Credential discovery
//!
//! Yandex Disk documents no environment variable, CLI token store, or
//! well-known credential file for OAuth access tokens. Reqsign therefore does
//! not invent one, and this crate exports no default provider or builder.
//! Pass [`StaticCredentialProvider`] or another explicit
//! [`reqsign_core::ProvideCredential`] implementation directly to
//! [`reqsign_core::Signer::new`], or use the facade's
//! `default_signer(ctx, access_token)`.
//!
//! Token issuance, refresh, revocation, and the permissions attached to the
//! OAuth app stay with the caller and Yandex OAuth. This crate does not
//! implement authorization-code, device, or interactive flows.
//!
//! A credential without an expiration is cached for the signer's lifetime. Use
//! [`Credential::with_expires_at`] or [`Credential::with_expires_in`], or
//! [`StaticCredentialProvider::with_expires_at`], when the token has a known
//! fixed lifetime. A dynamic provider returns a fresh credential with an
//! expiry when the token rotates.
//!
//! ## Request ownership
//!
//! The caller owns the API host, API version, resource path, query parameters,
//! `Accept` and `Content-Type` headers, and any upload or download URL returned
//! by Yandex Disk. Signing only inserts the sensitive `Authorization` header
//! and preserves the URI and every other header. There is no query
//! authentication, so signing rejects `expires_in`.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, Result, Signer};
//! use reqsign_yandex_disk::{RequestSigner, StaticCredentialProvider};
//!
//! # async fn example() -> Result<()> {
//! let signer = Signer::new(
//!     Context::new(),
//!     StaticCredentialProvider::new("yandex-disk-oauth-token"),
//!     RequestSigner,
//! );
//!
//! let mut req = http::Request::get(
//!     "https://cloud-api.yandex.net/v1/disk/resources?path=disk%3A%2Ffolder%2Ffile",
//! )
//! .body(())
//! .unwrap()
//! .into_parts()
//! .0;
//! signer.sign(&mut req, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod credential;
pub use credential::{AccessToken, Credential};

mod provide_credential;
pub use provide_credential::StaticCredentialProvider;

mod sign_request;
pub use sign_request::RequestSigner;
