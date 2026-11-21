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
use crate::constants::{GH_CLI, GITHUB_HOST};
use reqsign_core::{Context, Error, ProvideCredential, Result};

/// Loads the stored GitHub.com token from the GitHub CLI.
///
/// The provider runs `gh auth token --hostname github.com --no-refresh`
/// through [`Context::command_execute`]. The explicit host keeps discovery on
/// GitHub.com and independent of `GH_HOST` or a local Git remote. The command
/// is executed directly, never through a shell. Reqsign does not parse the
/// CLI's configuration files; the CLI remains the source of truth for account
/// and host selection. `--no-refresh` keeps discovery read-only so the CLI does
/// not refresh or rewrite its credential store; run `gh auth refresh` separately
/// when the stored token has expired, then recreate the signer so it loads the
/// renewed token.
///
/// A missing command adapter, a failed command, or empty output yields no
/// credential. Malformed output yields an error that never contains the
/// output or the CLI's stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct GhCliCredentialProvider;

impl GhCliCredentialProvider {
    /// Create a new GitHub CLI credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for GhCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let output = match ctx
            .command_execute(
                GH_CLI,
                &["auth", "token", "--hostname", GITHUB_HOST, "--no-refresh"],
            )
            .await
        {
            Ok(output) => output,
            Err(_) => return Ok(None),
        };

        if !output.success() || output.stdout.is_empty() {
            return Ok(None);
        }

        let token = match std::str::from_utf8(&output.stdout) {
            Ok(token) => token.trim(),
            Err(_) => {
                return Err(Error::config_invalid(
                    "`gh auth token` returned non-UTF-8 output",
                ));
            }
        };
        if token.is_empty() {
            return Ok(None);
        }
        if token.chars().any(char::is_whitespace) {
            return Err(Error::config_invalid(
                "`gh auth token` returned an unexpected token format",
            ));
        }

        Credential::new(token)
            .map(Some)
            .map_err(|_| Error::config_invalid("`gh auth token` returned an unusable token"))
    }
}
