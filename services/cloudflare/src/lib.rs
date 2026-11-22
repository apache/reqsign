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

//! Cloudflare API token discovery and request signing for Reqsign.
//!
//! This crate covers the Cloudflare API v4 requests that Workers KV and D1 use,
//! authenticated with an API token. The token is sent as a bearer token:
//!
//! ```text
//! Authorization: Bearer <CLOUDFLARE_API_TOKEN>
//! ```
//!
//! ## Resource identifiers stay with the caller
//!
//! The account ID, D1 database ID, and KV namespace ID are part of the request
//! URL (`https://api.cloudflare.com/client/v4/accounts/<account>/...`), not part of
//! authentication. They stay with the code that builds the request:
//!
//! ```text
//! KV  /accounts/<account_id>/storage/kv/namespaces/<namespace_id>/values/<key>
//! D1  /accounts/<account_id>/d1/database/<database_id>/query
//! ```
//!
//! One credential therefore signs requests for every account, database, and
//! namespace that the token is scoped to, and Reqsign never builds the business
//! URL, picks the HTTP method, or touches the request body.
//!
//! ## Credential discovery
//!
//! [`DefaultCredentialProvider`] reads `CLOUDFLARE_API_TOKEN`, the variable
//! Wrangler and Cloudflare's official SDKs use for non-interactive
//! authentication. There is no other default source: Cloudflare's global API key
//! requires a different header pair (`X-Auth-Key` and `X-Auth-Email`), so it is
//! not an API token source and is not read implicitly.
//!
//! Provided sources fail closed. A present but unusable `CLOUDFLARE_API_TOKEN`,
//! or an invalid prepended [`StaticCredentialProvider`], returns an error instead
//! of signing with another identity. An absent token yields no credential, and
//! signing then fails with `CredentialInvalid`.
//!
//! ## Request signing
//!
//! [`RequestSigner`] inserts a sensitive `Authorization` header and leaves the URI
//! and every other header unchanged. KV writes need a caller-supplied
//! `Content-Type` and multipart body, and D1 queries need a caller-supplied JSON
//! body, so those stay with the caller. The Cloudflare API has no query
//! authentication, so signing rejects `expires_in`.
//!
//! ## Expiry and clocks
//!
//! Cloudflare assigns an API token its permissions and optional expiry when the
//! token is created; neither is readable from the token. Reqsign does not track
//! that expiry, and signing writes no protocol time, so signing has no clock
//! dependency. A token that Cloudflare has expired fails at the API, so rotate it
//! with the mechanism your deployment already uses.
//!
//! ## WASM
//!
//! Environment and static credentials plus header signing work on
//! `wasm32-unknown-unknown` without a JavaScript clock.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, OsEnv, Result, Signer};
//! use reqsign_cloudflare::{DefaultCredentialProvider, RequestSigner};
//!
//! # async fn example() -> Result<()> {
//! let ctx = Context::new().with_env(OsEnv);
//! let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
//!
//! // The caller owns the account, namespace, and object path.
//! let mut req = http::Request::get(
//!     "https://api.cloudflare.com/client/v4/accounts/my-account/storage/kv/namespaces/my-namespace/values/my-key",
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

mod constants;

mod credential;
pub use credential::Credential;

mod provide_credential;
pub use provide_credential::{
    DefaultCredentialProvider, DefaultCredentialProviderBuilder, EnvCredentialProvider,
    StaticCredentialProvider,
};

mod sign_request;
pub use sign_request::RequestSigner;
