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
/// for account and host selection.
///
/// The initial `gh config get user` lookup distinguishes an absent account
/// from a failure. A context without a command executor, a command adapter
/// that does not report a typed I/O cause, a missing `gh` executable, and the
/// confirmed absent-account response all yield no credential and permit
/// anonymous fallback. GitHub CLI 2.40.0 and 2.103.3 report a host without a
/// stored account with exit status 1, empty stdout, and exactly the stderr
/// diagnostic `could not find key "user"`; only that response is the absent
/// account. A typed command execution failure other than a missing executable,
/// any other exit status, and successful output that is not a usable GitHub
/// account name yield a redacted error instead of silently falling back.
/// Account names use ASCII letters, digits, hyphens, and underscores, begin
/// and end with a letter or digit, and include enterprise managed names such
/// as `mona-cat_octo`. After an active user is found, only an explicit
/// `no oauth token found` response yields no credential. Command execution
/// errors, empty or whitespace-only successful stdout, malformed output, and
/// other stored-token failures such as an expired or revoked token yield a
/// redacted error. Errors never contain the token, the output, or the CLI's
/// stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct GhCliCredentialProvider;

impl GhCliCredentialProvider {
    /// Create a new GitHub CLI credential provider.
    pub fn new() -> Self {
        Self
    }

    async fn active_user(&self, ctx: &Context) -> Result<Option<String>> {
        let output = match ctx
            .command_execute(GH_CLI, &["config", "get", "user", "--host", GITHUB_HOST])
            .await
        {
            Ok(output) => output,
            Err(error) => match io_error_kind(&error) {
                // `gh` is not installed: there is no stored account to read.
                Some(std::io::ErrorKind::NotFound) => return Ok(None),
                // No typed I/O cause: the adapter does not run commands in this
                // context, such as the no-op adapter installed by
                // `Context::new()` and bare WASM runtimes. The slot stays
                // absent instead of failing the chain.
                None => return Ok(None),
                // The adapter ran but could not spawn `gh`. Treating this as
                // an absent account would silently select anonymous access.
                Some(_) => return Err(unexpected_account_error()),
            },
        };

        if !output.success() {
            // GitHub CLI 2.40.0 and 2.103.3 both report a host without a stored
            // account with exit status 1 and this exact response. Any other
            // failure means the configuration could not be read.
            if command_confirms_missing_user(&output) {
                return Ok(None);
            }
            return Err(could_not_read_account_error());
        }

        let user = match std::str::from_utf8(&output.stdout) {
            Ok(user) => user.trim_end_matches(['\r', '\n']),
            Err(_) => return Err(malformed_account_error()),
        };
        // The first-party command prints one stored account name followed by a
        // newline. Anything that is not a usable GitHub account name is
        // malformed and must not reach the token query; a missing account is
        // only the confirmed status-1 response above.
        if !is_usable_account_name(user) {
            return Err(malformed_account_error());
        }

        Ok(Some(user.to_string()))
    }

    async fn token_for_user(
        &self,
        ctx: &Context,
        user: &str,
        no_refresh: bool,
    ) -> Result<CommandOutput> {
        let mut args = vec!["auth", "token", "--hostname", GITHUB_HOST, "--user", user];
        if no_refresh {
            args.push("--no-refresh");
        }

        ctx.command_execute(GH_CLI, &args)
            .await
            .map_err(|_| stored_token_failure())
    }
}

impl ProvideCredential for GhCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(user) = self.active_user(ctx).await? else {
            return Ok(None);
        };

        let mut output = self.token_for_user(ctx, &user, true).await?;

        if !output.success() {
            if command_failed_with_unknown_flag(&output, "--no-refresh") {
                output = self.token_for_user(ctx, &user, false).await?;
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
            Ok(token) => token.trim_end_matches(['\r', '\n']),
            Err(_) => {
                return Err(Error::config_invalid(
                    "`gh auth token` returned non-UTF-8 output",
                ));
            }
        };
        // The first-party command prints a non-empty token followed by a
        // newline on success and returns `no oauth token found` with a non-zero
        // status when no token exists. An empty or whitespace-only success is
        // therefore malformed, not an absent credential.
        if token.is_empty() {
            return Err(Error::config_invalid(
                "`gh auth token` returned an unusable token",
            ));
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

/// Returns the kind of the typed I/O error that caused a command failure, if
/// the adapter reports one.
///
/// The Tokio adapter wraps spawn failures in [`std::io::Error`], so a missing
/// `gh` is a typed `NotFound` rather than a message. Custom adapters that do
/// not report a typed I/O cause leave the failure unclassified.
fn io_error_kind(error: &Error) -> Option<std::io::ErrorKind> {
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            return Some(io_error.kind());
        }
        source = cause.source();
    }

    None
}

/// Check whether `gh config get user` confirmed that no account is stored.
///
/// GitHub CLI 2.40.0 and 2.103.3 both report a host without a stored account
/// with exit status 1, empty stdout, and exactly this stderr diagnostic. A
/// different status, output, or diagnostic is a failure, not an absent
/// account.
fn command_confirms_missing_user(output: &CommandOutput) -> bool {
    if output.status != 1 || !output.stdout.is_empty() {
        return false;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.trim_end_matches(['\r', '\n']) == "could not find key \"user\""
}

/// Check whether successful output is a usable GitHub account name.
///
/// GitHub.com account names and GitHub Enterprise managed account names
/// (`shortcode_username`) contain ASCII letters, digits, hyphens, and
/// underscores, and begin and end with a letter or digit. Punctuation-only or
/// otherwise malformed output such as `--help`, `...`, `bad user`, or
/// `user/name` is not an account name and must not reach the token query.
fn is_usable_account_name(user: &str) -> bool {
    let mut bytes = user.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let last = user.bytes().next_back().unwrap_or(first);

    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn could_not_read_account_error() -> Error {
    Error::config_invalid(
        "`gh config get user` could not read the stored GitHub.com account; run `gh auth status` to check the GitHub CLI configuration, or set an explicit token",
    )
}

fn unexpected_account_error() -> Error {
    Error::unexpected(
        "`gh config get user` failed to run; check that the GitHub CLI is installed correctly, or set an explicit token",
    )
}

fn malformed_account_error() -> Error {
    Error::config_invalid("`gh config get user` returned an unusable account name")
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
