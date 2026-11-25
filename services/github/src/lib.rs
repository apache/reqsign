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
//! executor, it resolves the active stored account with
//! `gh config get user --host github.com`, then reads that account's token with
//! `gh auth token --hostname github.com --user <user> --no-refresh`. The
//! explicit user prevents `GH_TOKEN` or `GITHUB_TOKEN` in the child process
//! environment from shadowing the stored credential. Safe stored-token
//! discovery requires GitHub CLI 2.40.0 or newer.
//!
//! The default slots stop at the first error instead of silently selecting a
//! different identity. A malformed environment token, an invalid prepended or
//! static provider, or a GitHub CLI error or malformed CLI output fails
//! signing; the chain does not fall back to anonymous access. Only an absent
//! credential reaches the explicit anonymous slot: a command executor that
//! reports command execution as unavailable (no executor configured, an
//! unsupported target, or a confirmed cannot-spawn program), a confirmed
//! no-account response (`gh config get user` exiting with status 1 and exactly
//! `could not find key "user"` on stderr with no stdout), or an explicit
//! `no oauth token found` response. Any other command execution failure,
//! including a `NotFound` source inside a custom adapter's error, fails
//! signing. The command-unavailable marker permits anonymous fallback only
//! during this account lookup; a failure while reading the stored token,
//! including an unavailable executor, still fails signing. A successful
//! account lookup that is not a usable GitHub account
//! name is malformed, not an absent account. Ordinary logins accept legacy accounts
//! such as `A-` and `john--doe`; current registration rules are not used as a
//! validity check, so they only need to look like a login: ASCII letters,
//! digits, and hyphens, not starting with a hyphen, with at least one letter
//! or digit. Enterprise managed names append `_` and the three-to-eight
//! character alphanumeric enterprise shortcode to a normalized username that
//! has no leading, trailing, or consecutive dashes, are at most 39 characters
//! in total, and include the setup user's `octo_admin` form.
//!
//! `--no-refresh` keeps discovery read-only and is used on GitHub CLI 2.103.0
//! and newer. Older supported versions do not refresh when printing a stored
//! token, so the provider retries without the flag only after the CLI reports
//! that specific flag as unknown. If the stored token has expired, run
//! `gh auth refresh`, then recreate the signer so it loads the new token.
//!
//! [`RequestSigner`] adds a sensitive `Authorization: Bearer` header for a
//! token credential and removes any existing `Authorization` header for an
//! explicit anonymous credential, so a reused request cannot carry stale
//! authentication material. Other headers and the URI are unchanged. It does
//! not add or replace `User-Agent` (GitHub requires the caller to send one),
//! `Accept`, or `X-GitHub-Api-Version`, and it rejects `expires_in` because
//! GitHub has no query authentication. GitHub credentials in this crate carry
//! no expiration and signing writes no protocol time, so signing has no clock
//! dependency.
//!
//! ## Host and scope
//!
//! The built-in providers discover GitHub.com credentials only. They ignore
//! `GH_HOST`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_ENTERPRISE_TOKEN`; a GitHub
//! Enterprise Server deployment should supply an explicit
//! [`StaticCredentialProvider`] or a custom provider. `GH_TOKEN` and
//! `GITHUB_TOKEN` are interpreted as the GitHub CLI's GitHub.com token; pass
//! the intended token explicitly when you use multiple hosts. The signer does
//! not restrict the request host, so caller-supplied credentials may be used
//! with another GitHub host. A GitHub token carries the host and scopes or
//! repository permissions assigned by GitHub. Reqsign neither requests nor
//! inspects them.
//!
//! The caller owns the request, its headers, and its HTTP client's redirect
//! policy. Do not forward a signed `Authorization` header to a different host.
//!
//! ## WASM
//!
//! Environment, static, and anonymous signing work on `wasm32-unknown-unknown`
//! without a JavaScript clock. GitHub CLI discovery requires a
//! `CommandExecute` adapter and is unavailable in bare WASM runtimes.
//!
//! ## Example
//!
//! ```no_run
//! use reqsign_core::{Context, OsEnv, Result, Signer};
//! use reqsign_github::{DefaultCredentialProvider, RequestSigner};
//!
//! # async fn example() -> Result<()> {
//! // Add a CommandExecute adapter to enable GitHub CLI discovery.
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
