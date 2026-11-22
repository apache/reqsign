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

//! Seafile authentication and request signing for reqsign.
//!
//! This crate loads a Seafile account token, either from an explicit value or
//! by exchanging a username and password with the configured Seafile server,
//! and signs API requests with the token header that Seafile clients use.
//!
//! ## Account token exchange
//!
//! [`AccountTokenCredentialProvider`] sends the documented
//! `application/x-www-form-urlencoded` `username` and `password` fields to
//! `{server}/api2/auth-token/` and reads the `token` field from the JSON
//! response. The current OpenAPI document describes a JSON request body, but
//! Seafile's server-side example, `seaf-cli`, and the Python SDK post form
//! fields; this crate follows those executable clients. The configured server
//! may be a self-hosted Seafile deployment,
//! including any base path that a reverse proxy requires, such as
//! `https://files.example.com/seafile`. A successful exchange returns an
//! account token with no expiration field, so this crate does not assign one.
//! Seafile documents repository API tokens as valid until they are deleted;
//! account token lifetime is controlled by the server.
//!
//! The provider constructs only the initial request to the configured server.
//! The configured [`reqsign_core::HttpSend`] adapter owns redirect policy; the
//! default `ReqwestHttpSend` follows redirects. Use an adapter whose client
//! disables redirects for this credential-bearing exchange:
//!
//! ```no_run
//! use reqsign_core::{Context, Signer};
//! use reqsign_http_send_reqwest::ReqwestHttpSend;
//! use reqsign_seafile::{AccountTokenCredentialProvider, RequestSigner};
//! use reqwest::redirect::Policy;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = reqwest::Client::builder()
//!     .redirect(Policy::none())
//!     .build()?;
//! let context = Context::new().with_http_send(ReqwestHttpSend::new(client));
//! let signer = Signer::new(
//!     context,
//!     AccountTokenCredentialProvider::new(
//!         "https://files.example.com/seafile",
//!         "user@example.com",
//!         "password",
//!     ),
//!     RequestSigner,
//! );
//! # let _ = signer;
//! # Ok(())
//! # }
//! ```
//!
//! The exchange uses [`reqsign_core::Context::http_send`]. It never discovers a
//! server, username, or password on its own. Because the request carries a
//! login secret, use HTTPS in production. An explicit `http://` endpoint sends
//! the username and password in cleartext; it is supported only because
//! self-hosted deployments may run Seafile over HTTP on a private network, as
//! OpenDAL already permits. The caller chooses and owns that endpoint and the
//! adapter redirect policy.
//!
//! ## Credential discovery
//!
//! The default provider reads `server` and `token` from the `[account]` section
//! of `~/.seafile.conf`, the user configuration file read by the first-party
//! `seaf-cli` tool, and binds the credential to that deployment. The `server`
//! value is required and may include an explicit HTTP endpoint or a reverse-proxy
//! base path. Duplicate `[account]` sections or repeated parsed keys are
//! rejected. If the caller selects an account with
//! [`ConfigFileCredentialProvider::with_account_user`], the `[account] user`
//! value must be present and match exactly. The provider does not read
//! environment variables, run a login command, or parse the newer
//! `~/.config/seafile` files used by Seafile's repository-token skill. Use
//! [`StaticCredentialProvider`] when the caller already has a token, or
//! [`AccountTokenCredentialProvider`] when the caller wants to perform the
//! exchange with explicitly supplied credentials.
//!
//! ## Request signing
//!
//! [`RequestSigner`] inserts a sensitive `Authorization: Token <token>` header.
//! Seafile's own `seaf-cli`, its web API examples, and OpenDAL use this form.
//! Seafile 11 and newer also accept `Authorization: Bearer <token>`, but this
//! crate keeps `Token` so the same credential works with older self-hosted
//! servers and with existing OpenDAL behavior.
//!
//! Credentials discovered from `seaf-cli` configuration or obtained through the
//! account exchange are bound to the server deployment that supplied them.
//! Before writing the header, the signer checks the request scheme, host,
//! effective port, and deployment base path on a segment boundary. For example,
//! a `/seafile` deployment accepts `/seafile` and `/seafile/...` but not
//! `/seafile-other`. It also rejects a duplicate or conflicting `Host` header
//! and ambiguous path forms that the HTTP adapter would normalize. A mismatch
//! fails without changing the request. Static caller-supplied credentials carry
//! no deployment scope and keep the explicit caller contract.
//!
//! The signer changes only the `Authorization` header. Repository discovery,
//! repository-scoped upload and download links, and all business requests stay
//! with the caller. Seafile tokens in this crate carry no protocol time and no
//! expiration, so signing has no clock dependency. Redirect policy after
//! signing remains the caller's adapter responsibility.
//!
//! ## Quick Start
//!
//! ```no_run
//! use reqsign_core::{Context, Result, Signer};
//! use reqsign_seafile::{RequestSigner, StaticCredentialProvider};
//!
//! # async fn example() -> Result<()> {
//! let signer = Signer::new(
//!     Context::new(),
//!     StaticCredentialProvider::new("seafile-token"),
//!     RequestSigner,
//! );
//!
//! let mut req = http::Request::get("https://files.example.com/api2/repos/")
//!     .body(())
//!     .unwrap()
//!     .into_parts()
//!     .0;
//!
//! signer.sign(&mut req, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod constants;

mod credential;
pub use credential::Credential;

mod scope;

mod provide_credential;
pub use provide_credential::{
    AccountTokenCredentialProvider, ConfigFileCredentialProvider, DefaultCredentialProvider,
    DefaultCredentialProviderBuilder, StaticCredentialProvider,
};

mod sign_request;
pub use sign_request::RequestSigner;
