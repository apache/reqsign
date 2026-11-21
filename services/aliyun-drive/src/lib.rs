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

//! Aliyun Drive Open Platform credentials and request signing for Reqsign.
//!
//! This crate covers the OAuth access token and the `Authorization: Bearer`
//! header used by the Aliyun Drive Open Platform API. It does not build storage
//! requests: the drive ID, file paths, upload URLs, request bodies, and every
//! other business parameter stay with the caller.
//!
//! ## Credential sources
//!
//! Aliyun Drive documents OAuth authorization and the token endpoint, but it
//! does not define a CLI, SDK, environment-variable, or local-file credential
//! discovery contract. This crate therefore reads no ambient credential source.
//!
//! Use [`StaticCredentialProvider`] for an access token that the caller already
//! holds, or [`RefreshCredentialProvider`] to exchange an Aliyun Drive refresh
//! token. [`DefaultCredentialProvider`] keeps the uniform empty default chain
//! and composes explicit providers through `push_front` or `with_chain`.
//!
//! ## Refresh token exchange
//!
//! Aliyun Drive uses OAuth 2.0 authorization but not the RFC 6749 form-encoded
//! refresh request. [`RefreshCredentialProvider`] sends a vendor-specific JSON
//! body to the trusted token endpoint:
//!
//! ```text
//! POST https://openapi.alipan.com/oauth/access_token
//! Content-Type: application/json
//! User-Agent: reqsign-aliyun-drive/<version>
//!
//! {"client_id":"...","client_secret":"...","grant_type":"refresh_token","refresh_token":"..."}
//! ```
//!
//! All three confidential-client credentials are required. Aliyun Drive's
//! official PKCE public-client flow returns a 30-day access token without a
//! refresh token, so public clients use [`StaticCredentialProvider`] with the
//! access token they obtained. The endpoint requires a non-empty `User-Agent`.
//! [`RefreshCredentialProvider::with_token_endpoint`] can select another
//! explicitly trusted HTTPS endpoint.
//!
//! A successful exchange returns an access token, its lifetime in `expires_in`,
//! and a new single-use refresh token. A provider keeps only the latest refresh
//! token in memory; clones share that state and serialize exchanges, so
//! concurrent callers use the latest rotated token. A successful, parseable
//! response commits a non-empty rotated token even when the accompanying access
//! token or expiry is unusable, because the previous token was consumed.
//! Tokens are never persisted and Reqsign exposes no getter or persistence
//! callback. After a successful exchange, restarting with the original
//! configured refresh token may fail because that token was consumed. Restart
//! with a fresh authorized grant, or let the application manage and persist its
//! own exchange and supply the resulting access token through
//! [`StaticCredentialProvider`]. Access-token caching and refresh-on-expiry
//! belong to [`reqsign_core::Signer`].
//!
//! ## Request signing
//!
//! [`RequestSigner`] inserts a sensitive `Authorization: Bearer` header and
//! leaves the URI and every other header unchanged. It rejects `expires_in`
//! because the service has no query authentication. The first-party storage API
//! also requires a caller-supplied `User-Agent`; the signer does not add or
//! replace it.
//!
//! ## WASM
//!
//! Static credentials, refresh-token exchange with a caller-provided HTTP
//! adapter, and header signing compile for `wasm32-unknown-unknown`. On the
//! `wasm-bindgen`-hosted target this crate enables Jiff's JavaScript clock so
//! expiration checks can read time from the JS host. A bare WASM runtime without
//! a JavaScript clock can compile the crate but is not a supported runtime for
//! expiring credentials.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_aliyun_drive::{RefreshCredentialProvider, RequestSigner};
//! use reqsign_core::{Context, Result, Signer};
//!
//! # async fn example() -> Result<()> {
//! let ctx = Context::new().with_http_send(reqsign_core::NoopHttpSend);
//! let provider = RefreshCredentialProvider::new(
//!     "client-id",
//!     "client-secret",
//!     "refresh-token",
//! )?;
//! let signer = Signer::new(ctx, provider, RequestSigner);
//!
//! let mut req = http::Request::get(
//!     "https://openapi.alipan.com/adrive/v1.0/openFile/get_by_path",
//! )
//! .header(http::header::USER_AGENT, "my-application")
//! .body(())
//! .unwrap()
//! .into_parts()
//! .0;
//! signer.sign(&mut req, None).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod constants;

mod credential;
pub use credential::Credential;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, RefreshCredentialProvider,
    StaticCredentialProvider,
};

mod sign_request;
pub use sign_request::RequestSigner;
