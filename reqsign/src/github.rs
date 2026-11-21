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

//! GitHub.com service support with convenience APIs.

pub use reqsign_github::*;

use crate::{Context, Signer};

/// Default GitHub signer type with the documented credential chain.
pub type DefaultSigner = Signer<Credential>;

/// Create a default GitHub signer with the supplied runtime context.
///
/// The default credential provider reads `GH_TOKEN`, then `GITHUB_TOKEN`
/// through the context environment. When a command executor is available, it
/// resolves the active stored GitHub.com account with
/// `gh config get user --host github.com` and reads the token with
/// `gh auth token --hostname github.com --user <user> --no-refresh`; safe
/// stored-token discovery requires GitHub CLI 2.40.0 or newer. Only an absent
/// credential reaches anonymous access, which removes any existing
/// `Authorization` header. A malformed configured source fails signing instead
/// of silently selecting a different identity. Replace the provider with
/// [`StaticCredentialProvider`] or a custom provider when the token is managed
/// explicitly.
pub fn default_signer(ctx: Context) -> DefaultSigner {
    Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner)
}
