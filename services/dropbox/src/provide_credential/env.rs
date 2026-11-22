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
use crate::constants::DBXCLI_ACCESS_TOKEN;
use reqsign_core::{Context, ProvideCredential, Result};
use reqsign_oauth2::AccessToken;

/// Loads a Dropbox access token from `DBXCLI_ACCESS_TOKEN`.
///
/// This is the environment variable documented by the official `dbxcli` tool.
/// The token has no known expiration, so it is returned without one. An empty
/// variable yields no credential; an unusable value is a configuration error.
#[derive(Debug, Default, Clone)]
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
        let access_token = match ctx.env_var(DBXCLI_ACCESS_TOKEN) {
            Some(access_token) if !access_token.is_empty() => access_token,
            _ => return Ok(None),
        };

        let access_token = AccessToken::new(access_token, None).map_err(|_| {
            reqsign_core::Error::config_invalid(
                "DBXCLI_ACCESS_TOKEN is not a usable Dropbox access token",
            )
        })?;

        Ok(Some(Credential::new(access_token)))
    }
}
