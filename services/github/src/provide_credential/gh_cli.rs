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
use reqsign_core::{CommandOutput, Context, Error, ProvideCredential, Result};

/// The first GitHub CLI release with `gh auth token --user`. The explicit user
/// makes the CLI read the stored account and prevents `GH_TOKEN` or
/// `GITHUB_TOKEN` in the child process environment from overriding it.
///
/// The first-party history is `cli/cli` v2.40.0 for `--user` (`4e04b98f6`) and
/// v2.103.0 for `--no-refresh` together with token refresh (`c1a3f1184`).
pub(crate) const GH_CLI_MIN_VERSION: &str = "2.40.0";

/// Loads the stored GitHub.com token from the GitHub CLI.
///
/// The provider first runs `gh config get user --host github.com` to resolve
/// the active stored account without consulting token environment variables,
/// then runs
/// `gh auth token --hostname github.com --user <user> --no-refresh` through
/// [`Context::command_execute`]. Passing `--user` is required because
/// `gh auth token` otherwise prefers `GH_TOKEN` or `GITHUB_TOKEN` from the
/// child process environment, which would bypass `.no_env()` and a caller's
/// [`Context`] environment boundary. This safe path requires GitHub CLI
/// 2.40.0 or newer.
///
/// `--no-refresh` keeps discovery read-only. It was introduced in GitHub CLI
/// 2.103.0 together with token refresh; older supported versions do not
/// refresh when printing a stored token. The provider retries without
/// `--no-refresh` only when the CLI reports that specific flag as unknown.
/// Run `gh auth refresh` separately when the stored token has expired, then
/// recreate the signer so it loads the renewed token.
///
/// The command is executed directly, never through a shell. Reqsign does not
/// parse the CLI's configuration files; the CLI remains the source of truth
/// for account and host selection. A missing command adapter, a missing stored
/// account, or an absent stored token yields no credential. Malformed
/// successful token output and other stored-token failures, such as an expired
/// or revoked token, yield a redacted error instead of silently falling back.
/// Errors never contain the token, the output, or the CLI's stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct GhCliCredentialProvider;

impl GhCliCredentialProvider {
    /// Create a new GitHub CLI credential provider.
    pub fn new() -> Self {
        Self
    }

    async fn execute(&self, ctx: &Context, args: &[&str]) -> Option<CommandOutput> {
        ctx.command_execute(GH_CLI, args).await.ok()
    }

    async fn active_user(&self, ctx: &Context) -> Option<String> {
        let output = self
            .execute(ctx, &["config", "get", "user", "--host", GITHUB_HOST])
            .await?;
        if !output.success() {
            return None;
        }

        let user = std::str::from_utf8(&output.stdout).ok()?.trim();
        if user.is_empty()
            || user.starts_with('-')
            || !user.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return None;
        }

        Some(user.to_string())
    }

    async fn token_for_user(
        &self,
        ctx: &Context,
        user: &str,
        no_refresh: bool,
    ) -> Option<CommandOutput> {
        let mut args = vec!["auth", "token", "--hostname", GITHUB_HOST, "--user", user];
        if no_refresh {
            args.push("--no-refresh");
        }

        self.execute(ctx, &args).await
    }
}

impl ProvideCredential for GhCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(user) = self.active_user(ctx).await else {
            return Ok(None);
        };

        let mut output = match self.token_for_user(ctx, &user, true).await {
            Some(output) => output,
            None => return Ok(None),
        };

        if !output.success() {
            if command_failed_with_unknown_flag(&output, "--no-refresh") {
                output = match self.token_for_user(ctx, &user, false).await {
                    Some(output) => output,
                    None => return Ok(None),
                };
            } else if command_failed_with_unknown_flag(&output, "--user") {
                return Err(unsupported_gh_cli_error());
            } else if command_failed_because_token_is_missing(&output) {
                return Ok(None);
            } else {
                return Err(stored_token_failure());
            }
        }

        if !output.success() {
            if command_failed_with_unknown_flag(&output, "--user") {
                return Err(unsupported_gh_cli_error());
            }
            if command_failed_because_token_is_missing(&output) {
                return Ok(None);
            }
            return Err(stored_token_failure());
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

        Credential::new(token)
            .map(Some)
            .map_err(|_| Error::config_invalid("`gh auth token` returned an unusable token"))
    }
}

fn command_failed_with_unknown_flag(output: &CommandOutput, flag: &str) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains(&format!("unknown flag: {flag}"))
}

fn command_failed_because_token_is_missing(output: &CommandOutput) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("no oauth token found")
}

fn stored_token_failure() -> Error {
    Error::credential_invalid(
        "`gh auth token` could not read the stored GitHub.com token; run `gh auth refresh` or `gh auth login`, or set an explicit token",
    )
}

fn unsupported_gh_cli_error() -> Error {
    Error::config_invalid(format!(
        "the installed GitHub CLI is too old for safe stored-token discovery; gh {GH_CLI_MIN_VERSION} or newer is required, or set GH_TOKEN/GITHUB_TOKEN, use StaticCredentialProvider, or disable the gh_cli slot"
    ))
}
