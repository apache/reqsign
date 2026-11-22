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

use crate::Credential;
use crate::constants::{GH_TOKEN, GITHUB_TOKEN};
use reqsign_core::{Context, ProvideCredential, Result};

/// Loads a GitHub.com token from `GH_TOKEN`, then `GITHUB_TOKEN`.
///
/// The order matches the GitHub CLI environment contract, where `GH_TOKEN`
/// takes precedence over `GITHUB_TOKEN`. Empty variables are treated as unset.
/// The provider treats these variables as the GitHub CLI's GitHub.com token and
/// does not read `GH_HOST`, `GH_ENTERPRISE_TOKEN`, or
/// `GITHUB_ENTERPRISE_TOKEN`; this crate targets GitHub.com only.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvCredentialProvider;

impl EnvCredentialProvider {
    /// Create a new environment credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        for name in [GH_TOKEN, GITHUB_TOKEN] {
            let Some(token) = ctx.env_var(name) else {
                continue;
            };
            if token.is_empty() {
                continue;
            }

            return Credential::new(token).map(Some).map_err(|_| {
                reqsign_core::Error::config_invalid(format!("{name} is not a usable GitHub token"))
            });
        }

        Ok(None)
    }
}
