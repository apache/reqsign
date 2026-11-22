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
use crate::constants::{
    CLI_CONFIG_PATH, CLI_CONFIG_SECTION, CLI_CONFIG_SERVER_KEY, CLI_CONFIG_TOKEN_KEY,
    CLI_CONFIG_USER_KEY,
};
use crate::scope::DeploymentScope;
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use std::fmt::{self, Debug, Formatter};

/// Loads the account token and its deployment from the first-party `seaf-cli`
/// user configuration.
///
/// The default path is `~/.seafile.conf`, the file read by the `seaf-cli` tool
/// shipped with Seafile. The provider reads `server` and `token` from the
/// `[account]` section and binds the credential to that deployment. A missing
/// or unreadable file yields no credential so another configured provider can
/// run. A token without a usable server, an invalid server, or an unusable
/// token is a configuration error. The error never includes the server URL,
/// login name, or token.
///
/// If the caller explicitly selects an account with
/// [`Self::with_account_user`], the `[account] user` value must be present and
/// match it exactly. Without that selection the provider does not need the
/// `user` value and does not expose it.
///
/// The provider reads only this file. It does not run `seaf-cli`, read the
/// `~/.config/seafile` repository-token files, inspect environment variables, or
/// discover a repository id.
#[derive(Default, Clone)]
pub struct ConfigFileCredentialProvider {
    path: Option<String>,
    account_user: Option<String>,
}

impl Debug for ConfigFileCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigFileCredentialProvider")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
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

    /// Require the `[account] user` value to match this explicitly selected
    /// account. The comparison is exact. A missing or different `user` is a
    /// configuration error rather than a fallback to another account.
    pub fn with_account_user(mut self, user: impl Into<String>) -> Self {
        self.account_user = Some(user.into());
        self
    }

    fn path(&self) -> &str {
        self.path.as_deref().unwrap_or(CLI_CONFIG_PATH)
    }
}

fn unique_property<'a>(
    section: &'a ini::Properties,
    key: &str,
    path: &str,
) -> Result<Option<&'a str>> {
    let mut values = section
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value);
    let value = values.next();
    if values.next().is_some() {
        return Err(Error::config_invalid(format!(
            "Seafile CLI config file at {path} repeats [account] {key}"
        )));
    }

    Ok(value)
}

impl ProvideCredential for ConfigFileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.account_user.as_deref() == Some("") {
            return Err(Error::config_invalid(
                "configured Seafile account user must not be empty",
            ));
        }

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

        let mut account_sections = ini.section_all(Some(CLI_CONFIG_SECTION));
        let Some(section) = account_sections.next() else {
            debug!("Seafile CLI config file has no [account] section");
            return Ok(None);
        };
        if account_sections.next().is_some() {
            return Err(Error::config_invalid(format!(
                "Seafile CLI config file at {path} repeats the [account] section"
            )));
        }

        let Some(token) = unique_property(section, CLI_CONFIG_TOKEN_KEY, &path)? else {
            debug!("Seafile CLI config file has no account token");
            return Ok(None);
        };
        if token.is_empty() {
            debug!("Seafile CLI config file has an empty account token");
            return Ok(None);
        }

        let server = unique_property(section, CLI_CONFIG_SERVER_KEY, &path)?
            .filter(|server| !server.is_empty())
            .ok_or_else(|| {
                Error::config_invalid(format!(
                    "Seafile CLI config file at {path} has no [account] server"
                ))
            })?;
        let config_user = unique_property(section, CLI_CONFIG_USER_KEY, &path)?;
        let deployment = DeploymentScope::from_server_url(server).map_err(|_| {
            Error::config_invalid(format!(
                "Seafile CLI config file at {path} has an invalid [account] server"
            ))
        })?;

        if let Some(expected_user) = &self.account_user {
            let user = config_user.filter(|user| !user.is_empty()).ok_or_else(|| {
                Error::config_invalid(format!(
                    "Seafile CLI config file at {path} has no [account] user to match"
                ))
            })?;
            if user != expected_user {
                return Err(Error::config_invalid(format!(
                    "Seafile CLI config file at {path} has an [account] user that does not match the configured account"
                )));
            }
        }

        Credential::new(token.to_string())
            .map(|credential| credential.with_deployment_scope(deployment))
            .map(Some)
            .map_err(|_| {
                Error::config_invalid(format!(
                    "Seafile CLI config file at {path} contains an unusable account token"
                ))
            })
    }
}
