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

//! GitHub.com credential discovery and request signing for Reqsign.
//!
//! The default credential chain reads `GH_TOKEN` before `GITHUB_TOKEN` through
//! [`reqsign_core::Context`] environment access. When the context has a command
//! executor, it then asks the GitHub CLI for the stored GitHub.com token with
//! `gh auth token --hostname github.com --no-refresh`. Discovery is read-only;
//! if the stored token has expired, run `gh auth refresh` to renew it and
//! recreate the signer so it loads the new token. If neither source yields a
//! token, the chain ends with an explicit anonymous credential so that public
//! resources remain readable without authentication.
//!
//! [`RequestSigner`] adds only a sensitive `Authorization: Bearer` header. It
//! does not add or replace `User-Agent` (GitHub requires the caller to send
//! one), `Accept`, or `X-GitHub-Api-Version`, and it rejects `expires_in`
//! because GitHub has no query authentication.
//!
//! ## Host and scope
//!
//! This crate targets GitHub.com and `https://api.github.com`. It deliberately
//! ignores `GH_HOST`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_ENTERPRISE_TOKEN`; a
//! GitHub Enterprise Server deployment should supply an explicit
//! [`StaticCredentialProvider`] or a custom provider. `GH_TOKEN` and
//! `GITHUB_TOKEN` are interpreted as the GitHub CLI's GitHub.com token; pass
//! the intended token explicitly when you use multiple hosts. A GitHub token
//! carries the host and scopes or repository permissions assigned by GitHub.
//! Reqsign neither requests nor inspects them.
//!
//! The caller owns the request, its headers, and its HTTP client's redirect
//! policy. Do not forward a signed `Authorization` header to a different host.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, OsEnv, Result, Signer};
//! use reqsign_github::{DefaultCredentialProvider, RequestSigner};
//!
//! # async fn example() -> Result<()> {
//! let ctx = Context::new().with_env(OsEnv);
//! let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
//!
//! let mut req = http::Request::get("https://api.github.com/repos/apache/reqsign")
//!     .header("user-agent", "my-application")
//!     .header("x-github-api-version", "2022-11-28")
//!     .body(())
//!     .unwrap()
//!     .into_parts()
//!     .0;
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
    AnonymousCredentialProvider, DefaultCredentialProvider, DefaultCredentialProviderBuilder,
    EnvCredentialProvider, GhCliCredentialProvider, StaticCredentialProvider,
};

mod sign_request;
pub use sign_request::RequestSigner;
