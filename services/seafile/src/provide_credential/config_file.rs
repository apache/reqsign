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
use crate::constants::{CLI_CONFIG_PATH, CLI_CONFIG_SECTION, CLI_CONFIG_TOKEN_KEY};
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};

/// Loads the account token from the first-party `seaf-cli` user configuration.
///
/// The default path is `~/.seafile.conf`, the file read by the `seaf-cli` tool
/// shipped with Seafile. The provider reads the `token` key from the `[account]`
/// section. A missing or unreadable file yields no credential so another
/// configured provider can run. A file that exists but cannot be parsed, or a
/// token that cannot be used as a header value, is a configuration error.
///
/// The provider reads only this file. It does not run `seaf-cli`, read the
/// `~/.config/seafile` repository-token files, inspect environment variables, or
/// discover a repository id.
#[derive(Debug, Default, Clone)]
pub struct ConfigFileCredentialProvider {
    path: Option<String>,
}

impl ConfigFileCredentialProvider {
    /// Create a provider that reads `~/.seafile.conf`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a specific `seaf-cli` style configuration file instead of the
    /// default path. A leading `~/` is expanded through the context home
    /// directory.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    fn path(&self) -> &str {
        self.path.as_deref().unwrap_or(CLI_CONFIG_PATH)
    }
}

impl ProvideCredential for ConfigFileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let path = match ctx.expand_home_dir(self.path()) {
            Some(path) => path,
            None => {
                debug!("Seafile CLI config home directory is unavailable");
                return Ok(None);
            }
        };

        let content = match ctx.file_read_as_string(&path).await {
            Ok(content) => content,
            Err(_) => {
                debug!("Seafile CLI config file was not readable at {path}");
                return Ok(None);
            }
        };

        let ini = ini::Ini::load_from_str(&content).map_err(|_| {
            Error::config_invalid(format!(
                "failed to parse the Seafile CLI config file at {path}"
            ))
        })?;
        let Some(section) = ini.section(Some(CLI_CONFIG_SECTION)) else {
            debug!("Seafile CLI config file has no [account] section");
            return Ok(None);
        };
        let Some(token) = section.get(CLI_CONFIG_TOKEN_KEY) else {
            debug!("Seafile CLI config file has no account token");
            return Ok(None);
        };
        if token.is_empty() {
            debug!("Seafile CLI config file has an empty account token");
            return Ok(None);
        }

        Credential::new(token.to_string()).map(Some).map_err(|_| {
            Error::config_invalid(format!(
                "Seafile CLI config file at {path} contains an unusable account token"
            ))
        })
    }
}
