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

//! OneDrive authentication and request signing for reqsign.
//!
//! OneDrive requests go to Microsoft Graph with a Microsoft Entra access token
//! in an `Authorization: Bearer` header. This crate supplies the credential for
//! that header; the caller builds the business request, for example
//! `GET https://graph.microsoft.com/v1.0/me/drive/root`.
//!
//! ## Credentials
//!
//! Microsoft documents no environment variable or shared configuration file
//! that carries a Microsoft Graph user token, and MSAL token caches are
//! library-specific. This crate therefore has no automatic source: it does not
//! run the Azure CLI, read MSAL caches, or start a login flow. The caller
//! obtains a token through the flow it chose and configures it explicitly:
//!
//! - [`StaticCredentialProvider`] for an existing access token. Tokens are
//!   short lived; pass an expiration with
//!   [`StaticCredentialProvider::with_expires_at`] when the caller knows it.
//! - [`RefreshCredentialProvider`] for a refresh token. The provider exchanges
//!   it through the shared [`reqsign_oauth2::RefreshTokenGrant`].
//!
//! A service whose only documented sources require explicit caller input has no
//! default construction to wrap, so this crate exports no default provider or
//! builder. Pass one provider directly to [`reqsign_core::Signer::new`]; the
//! facade's `default_signer(ctx, access_token)` selects
//! [`StaticCredentialProvider`].
//!
//! ## Public and confidential clients
//!
//! Microsoft distinguishes public clients, which cannot hold an application
//! secret, from confidential clients, which can. Both flows authorize the same
//! delegated Microsoft Graph scopes:
//!
//! ```rust,no_run
//! use reqsign_core::{Context, Result, Signer};
//! use reqsign_onedrive::{RefreshCredentialProvider, RequestSigner};
//!
//! # fn example(context: Context) -> Result<()> {
//! // Public client: a desktop, mobile, browserless, or client-side app.
//! // The exchange sends no client secret.
//! let provider = RefreshCredentialProvider::new("client-id", "refresh-token")?;
//! let signer = Signer::new(context.clone(), provider, RequestSigner);
//!
//! // Confidential client: a web app, web API, or daemon that can store a
//! // secret on the server side.
//! let provider = RefreshCredentialProvider::builder("client-id", "refresh-token")
//!     .client_secret("client-secret")
//!     .build()?;
//! let signer = Signer::new(context, provider, RequestSigner);
//! # let _ = signer;
//! # Ok(())
//! # }
//! ```
//!
//! ## Scopes and endpoints
//!
//! The refresh exchange defaults to
//! `https://login.microsoftonline.com/common/oauth2/v2.0/token`, the global
//! Microsoft Entra v2.0 token endpoint for the `common` tenant. Microsoft
//! documents `common`, `organizations`, `consumers`, or a tenant identifier
//! such as a domain name or GUID; select another tenant with
//! [`RefreshCredentialProviderBuilder::tenant`]. National clouds publish a
//! different authentication endpoint, which
//! [`RefreshCredentialProviderBuilder::token_endpoint`] replaces as a whole;
//! endpoints must be HTTPS.
//!
//! `offline_access` is the scope that makes Microsoft Entra issue a refresh
//! token, and `Files.ReadWrite` is the least privileged delegated Microsoft
//! Graph permission that lets an app read, create, update, and delete the
//! signed-in user's files. The original authorization request needs both, and the
//! refresh exchange may repeat them with
//! [`RefreshCredentialProviderBuilder::scope`]. By default the exchange omits
//! `scope`, which keeps the new access token limited to what the original grant
//! received; when a scope is set, Microsoft requires it to be equivalent to or
//! a subset of that grant.
//!
//! ## Rotation, expiration, and caching
//!
//! Microsoft returns a new refresh token with a successful exchange and
//! documents that the client must discard the previous one. A provider keeps
//! only the latest refresh token in memory, clones share it, and exchanges are
//! serialized through the shared grant. Reqsign never writes refresh tokens to
//! disk, and a rotated token that is lost with the process must be obtained
//! again through the authorization flow.
//!
//! [`reqsign_core::Signer`] owns access-token caching and refreshes a cached
//! token inside the shared proactive window. A token response carries
//! `expires_in`; a successful exchange that omits it, or whose token is already
//! expired, is rejected instead of being cached as a token with an unknown
//! lifetime, and the returned refresh token from that response is still
//! committed.
//!
//! [`RequestSigner`] adds only a sensitive `Authorization: Bearer` header. It
//! rejects `expires_in`, because this crate implements header authentication
//! only and not query authentication; signing never changes the URI or any
//! other header.
//!
//! A single provider passed to [`reqsign_core::Signer::new`] keeps its own
//! error behavior. When one signer needs several explicit sources, the caller
//! owns that composition: [`reqsign_core::ProvideCredentialChain`] tries every
//! provider in order and logs a provider error before continuing, so it is not
//! equivalent to fail-closed, last-added-first ordering. Keep that ordering in
//! a caller-owned [`reqsign_core::ProvideCredential`] implementation when it is
//! required.
//!
//! ## WASM
//!
//! On `wasm32-unknown-unknown`, this crate enables Jiff's `js` feature. Runtime
//! signing or refresh requires a wasm-bindgen JavaScript host such as a browser
//! or Node; a bare WASM runtime without a JavaScript clock can compile the crate
//! but is not a supported runtime.

mod constants;

mod credential;
pub use credential::Credential;

mod sign_request;
pub use sign_request::RequestSigner;

mod provide_credential;
pub use provide_credential::{
    RefreshCredentialProvider, RefreshCredentialProviderBuilder, StaticCredentialProvider,
};
