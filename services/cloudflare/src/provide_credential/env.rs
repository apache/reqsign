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

use log::debug;

use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::constants::CLOUDFLARE_API_TOKEN;
use crate::credential::Credential;

/// Loads a Cloudflare API token from `CLOUDFLARE_API_TOKEN`.
///
/// This is the variable Wrangler and Cloudflare's official SDKs read for
/// non-interactive authentication. A missing or empty variable yields no
/// credential. A present but unusable value fails instead of being treated as
/// absent, so a typo cannot silently sign with a different identity.
///
/// The account ID used by KV and D1 requests is not read here: it belongs to the
/// request URL that the caller constructs.
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
        let Some(api_token) = ctx.env_var(CLOUDFLARE_API_TOKEN) else {
            debug!("{CLOUDFLARE_API_TOKEN} not set, skipping env credential provider");
            return Ok(None);
        };
        if api_token.is_empty() {
            debug!("{CLOUDFLARE_API_TOKEN} is empty, skipping env credential provider");
            return Ok(None);
        }

        Credential::new(api_token).map(Some).map_err(|_| {
            Error::config_invalid(format!(
                "{CLOUDFLARE_API_TOKEN} is not a usable Cloudflare API token"
            ))
        })
    }
}
