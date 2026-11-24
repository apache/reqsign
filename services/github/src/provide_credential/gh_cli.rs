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
/// from a failure. Command executors report an unavailable operation through
/// [`Error::command_unavailable`]: the no-op executor installed by
/// `Context::new()`, an executor that does not support the target, and an
/// executor that confirms the requested program cannot be spawned. That marker
/// and the confirmed absent-account response yield no credential and permit
/// anonymous fallback. GitHub CLI 2.40.0 and 2.103.3 report a host without a
/// stored account with exit status 1, empty stdout, and exactly the stderr
/// diagnostic `could not find key "user"`; only that response is the absent
/// account. Every other command execution failure, including a `NotFound`
/// source inside a custom adapter's error, any other exit status, and
/// successful output that is not a usable GitHub account name yield a redacted
/// error instead of silently falling back.
/// Usable names are ordinary GitHub.com logins and enterprise managed user
/// names. Ordinary logins accept legacy accounts such as `A-` and
/// `john--doe`, so current registration rules are not used as a validity
/// check: they must only look like a login (ASCII letters, digits, and
/// hyphens, not starting with a hyphen, with at least one letter or digit).
/// Managed user names append `_` and the enterprise's three-to-eight character
/// alphanumeric shortcode to a normalized username (`IDP-USERNAME_SHORT-CODE`,
/// for example `mona-cat_octo`); the normalized part has no leading, trailing,
/// or consecutive dashes, the total is at most 39 characters, and the setup
/// user's `octo_admin` form fits the same shape. Letter casing is preserved.
/// After an active user is found, only an explicit `no oauth token found`
/// response yields no credential. Command execution errors, empty or
/// whitespace-only successful stdout, malformed output, and other stored-token
/// failures such as an expired or revoked token yield a redacted error. Errors
/// never contain the token, the output, or the CLI's stderr.
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
            // The executor reports that it cannot run commands here: no
            // executor configured, an unsupported target, or a confirmed
            // cannot-spawn program. The slot stays absent.
            Err(error) if error.is_command_unavailable() => return Ok(None),
            // Any other executor failure is a real execution failure,
            // including ambiguous or nested `NotFound` causes from custom
            // adapters. Treating it as an absent account would silently select
            // anonymous access.
            Err(_) => return Err(unexpected_account_error()),
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
/// Ordinary logins accept legacy accounts such as `A-` and `john--doe`, so
/// current registration rules are not used as a validity check. Enterprise
/// managed user names append an underscore and the enterprise shortcode to a
/// normalized username (`IDP-USERNAME_SHORT-CODE`, for example
/// `mona-cat_octo`), where the normalized part follows GitHub's rules and the
/// shortcode is a three-to-eight character alphanumeric string. The setup
/// user's name is `SHORT-CODE_admin` (for example `octo_admin`), which fits the
/// same shape. Anything else, including `--help`, `...`, `bad user`,
/// `user/name`, `The--Octocat_octo`, `mona-cat_`, or `mona_cat_octo`, is not an
/// account name and must not reach the token query.
fn is_usable_account_name(user: &str) -> bool {
    match user.split_once('_') {
        Some((username, shortcode)) => {
            user.len() <= 39 && is_normalized_managed_username(username) && is_shortcode(shortcode)
        }
        None => is_ordinary_login(user),
    }
}

/// Check whether the output looks like an ordinary GitHub login.
///
/// Existing accounts can predate the current registration policy; `A-` and
/// `john--doe` are supported by GitHub CLI 2.40 and 2.103. Reject only output
/// that cannot be a login: an empty value, a value that starts with `-` (CLI
/// help and flags), characters other than ASCII letters, digits, and hyphens,
/// or punctuation-only text without a letter or digit.
fn is_ordinary_login(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && name.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Check whether the normalized username part of a managed user name is valid.
///
/// GitHub normalizes unsupported characters in external identifiers to `-` and
/// only creates managed usernames that contain alphanumeric characters and
/// dashes, do not begin or end with a dash, and do not contain two consecutive
/// dashes. Letter casing is preserved.
fn is_normalized_managed_username(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Check whether the enterprise shortcode shape is valid.
///
/// An enterprise shortcode is an alphanumeric string between three and eight
/// characters. The setup user's `_admin` suffix has the same shape.
fn is_shortcode(shortcode: &str) -> bool {
    (3..=8).contains(&shortcode.len()) && shortcode.bytes().all(|byte| byte.is_ascii_alphanumeric())
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
