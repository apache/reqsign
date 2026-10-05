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
use ini::{Ini, ParseOption};
use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;

/// Process Credentials Provider
///
/// This provider executes an external process to retrieve credentials.
/// The process must output JSON in a specific format to stdout.
///
/// # Configuration
/// Process credentials are typically configured in ~/.aws/config:
/// ```ini
/// [profile my-process-profile]
/// credential_process = "/path/to/credential helper" --arg1 "value with spaces"
/// ```
///
/// Double quotes preserve spaces in executable paths and arguments. Backslashes
/// are literal, including in Windows paths. Commands are executed as a program
/// and argument vector without shell expansion. Unmatched double quotes and an
/// empty executable name are rejected before execution.
///
/// # Output Format
/// The process must output JSON with the following structure:
/// ```json
/// {
///   "Version": 1,
///   "AccessKeyId": "access_key",
///   "SecretAccessKey": "secret_key",
///   "SessionToken": "session_token",
///   "Expiration": "2023-12-01T00:00:00Z"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ProcessCredentialProvider {
    profile: Option<String>,
    command: Option<String>,
}

impl Default for ProcessCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCredentialProvider {
    /// Create a new process credential provider
    pub fn new() -> Self {
        Self {
            profile: None,
            command: None,
        }
    }

    /// Set the profile name to use
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the command directly
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    async fn get_command(&self, ctx: &Context) -> Result<String> {
        // If command is directly provided, use it
        if let Some(cmd) = &self.command {
            return Ok(cmd.clone());
        }

        // Otherwise, load from config file
        // Priority: 1. self.profile, 2. AWS_PROFILE env var, 3. "default"
        let profile_name = self
            .profile
            .clone()
            .or_else(|| ctx.env_var("AWS_PROFILE"))
            .unwrap_or_else(|| "default".to_string());
        self.load_command_from_config(ctx, &profile_name).await
    }

    async fn load_command_from_config(&self, ctx: &Context, profile: &str) -> Result<String> {
        // Load AWS config file
        let config_path = ctx
            .env_var("AWS_CONFIG_FILE")
            .unwrap_or_else(|| "~/.aws/config".to_string());

        let expanded_path = if config_path.starts_with("~/") {
            match ctx.expand_home_dir(&config_path) {
                Some(expanded) => expanded,
                None => return Err(Error::config_invalid("failed to expand home directory")),
            }
        } else {
            config_path
        };

        let content = ctx.file_read(&expanded_path).await.map_err(|_| {
            Error::config_invalid(format!("failed to read config file: {expanded_path}"))
        })?;

        // The command parser owns quoting; INI parsing must preserve Windows paths.
        let conf = Ini::load_from_str_opt(
            &String::from_utf8_lossy(&content),
            ParseOption {
                enabled_quote: false,
                enabled_escape: false,
                ..Default::default()
            },
        )
        .map_err(|e| Error::config_invalid(format!("failed to parse config file: {e}")))?;

        let profile_section = if profile == "default" {
            profile.to_string()
        } else {
            format!("profile {profile}")
        };

        let section = conf.section(Some(profile_section)).ok_or_else(|| {
            Error::config_invalid(format!("profile '{profile}' not found in config"))
        })?;

        section
            .get("credential_process")
            .ok_or_else(|| {
                Error::config_invalid(format!(
                    "credential_process not found in profile '{profile}'"
                ))
            })
            .map(|s| s.to_string())
    }

    async fn execute_process(
        &self,
        ctx: &Context,
        command: &str,
    ) -> Result<ProcessCredentialOutput> {
        debug!("executing credential process: {command}");

        let parts = parse_command(command)?;
        let program = parts[0].as_str();
        let args: Vec<&str> = parts[1..].iter().map(String::as_str).collect();

        // Execute the process using Context's command executor
        let output = ctx.command_execute(program, &args).await?;

        if !output.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::unexpected(format!(
                "credential process failed with status {}: {}",
                output.status, stderr
            )));
        }

        // Parse the output
        let stdout = &output.stdout;
        let creds: ProcessCredentialOutput = serde_json::from_slice(stdout).map_err(|e| {
            Error::unexpected(format!("failed to parse credential process output: {e}"))
        })?;

        // Validate version
        if creds.version != 1 {
            return Err(Error::unexpected(format!(
                "unsupported credential process version: {}",
                creds.version
            )));
        }

        Ok(creds)
    }
}

// AWS uses double quotes to group whitespace, with literal backslashes for
// Windows paths. Shell parsers would add escaping and single-quote semantics.
fn parse_command(command: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut quoted = false;
    let mut started = false;

    for ch in command.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            ch if ch.is_whitespace() && !quoted => {
                if started {
                    parts.push(std::mem::take(&mut part));
                    started = false;
                }
            }
            ch => {
                part.push(ch);
                started = true;
            }
        }
    }

    if quoted {
        return Err(Error::config_invalid(
            "credential_process command has unmatched double quotes",
        ));
    }
    if started {
        parts.push(part);
    }
    if parts.first().is_none_or(String::is_empty) {
        return Err(Error::config_invalid(
            "credential_process command has an empty executable",
        ));
    }
    Ok(parts)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProcessCredentialOutput {
    version: u32,
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    expiration: Option<String>,
}
impl ProvideCredential for ProcessCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let command = match self.get_command(ctx).await {
            Ok(cmd) => cmd,
            Err(_) => {
                debug!("no credential_process configured");
                return Ok(None);
            }
        };

        let output = self.execute_process(ctx, &command).await?;
        let expires_in = output
            .expiration
            .and_then(|expires_in| expires_in.parse().ok());
        Ok(Some(Credential {
            access_key_id: output.access_key_id,
            secret_access_key: output.secret_access_key,
            session_token: output.session_token,
            expires_in,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_command_execute_tokio::TokioCommandExecute;
    use reqsign_core::{CommandExecute, CommandOutput, ErrorKind, FileRead, OsEnv, StaticEnv};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn test_process_provider_no_config() {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_command_execute(TokioCommandExecute)
            .with_env(OsEnv);
        let ctx = ctx.with_env(StaticEnv {
            home_dir: Some(std::path::PathBuf::from("/home/test")),
            envs: HashMap::new(),
        });

        let provider = ProcessCredentialProvider::new();
        let result = provider.provide_credential(&ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingCommandExecute {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl CommandExecute for RecordingCommandExecute {
        async fn command_execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program)
                    .chain(args.iter().copied())
                    .map(str::to_string)
                    .collect(),
            );
            Ok(CommandOutput {
                status: 0,
                stdout: br#"{"Version":1,"AccessKeyId":"test_key","SecretAccessKey":"test_secret","SessionToken":"test_token","Expiration":"2030-01-01T00:00:00Z"}"#.to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    #[derive(Debug)]
    struct ConfigFile(String);

    impl FileRead for ConfigFile {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            assert_eq!(path, "/aws/config");
            Ok(self.0.as_bytes().to_vec())
        }
    }

    // Exercise the same commands through both public configuration entrances.
    fn command_context(
        command: &str,
        profile: Option<&str>,
        executor: RecordingCommandExecute,
    ) -> (ProcessCredentialProvider, Context) {
        let provider = ProcessCredentialProvider::new();
        let ctx = Context::new().with_command_execute(executor);
        match profile {
            None => (provider.with_command(command), ctx),
            Some(profile) => {
                let section = if profile == "default" {
                    "default".to_string()
                } else {
                    format!("profile {profile}")
                };
                let ctx = ctx
                    .with_env(StaticEnv {
                        home_dir: None,
                        envs: HashMap::from([("AWS_CONFIG_FILE".into(), "/aws/config".into())]),
                    })
                    .with_file_read(ConfigFile(format!(
                        "[{section}]\ncredential_process = {command}\n"
                    )));
                (provider.with_profile(profile), ctx)
            }
        }
    }

    #[tokio::test]
    async fn test_process_command_arguments() {
        let cases: &[(&str, &[&str])] = &[
            ("helper", &["helper"]),
            ("  helper\t--role  value  ", &["helper", "--role", "value"]),
            (
                r#"credential-helper --role "role with spaces""#,
                &["credential-helper", "--role", "role with spaces"],
            ),
            (
                r#""/opt/credential tools/helper" plain "parameter with spaces""#,
                &[
                    "/opt/credential tools/helper",
                    "plain",
                    "parameter with spaces",
                ],
            ),
            (
                r#""C:\Program Files\helper.exe" "C:\new folder\test\" C:\temp\file"#,
                &[
                    r"C:\Program Files\helper.exe",
                    r"C:\new folder\test\",
                    r"C:\temp\file",
                ],
            ),
            (r#"helper "" " " tail"#, &["helper", "", " ", "tail"]),
            (
                r#"helper --role="role with spaces""#,
                &["helper", "--role=role with spaces"],
            ),
            (
                r#"helper "$HOME" %USERPROFILE% "$(whoami)" "`whoami`" "*.json" "~" "|" ";" 'literal'"#,
                &[
                    "helper",
                    "$HOME",
                    "%USERPROFILE%",
                    "$(whoami)",
                    "`whoami`",
                    "*.json",
                    "~",
                    "|",
                    ";",
                    "'literal'",
                ],
            ),
        ];
        for profile in [None, Some("default"), Some("example")] {
            for (command, expected) in cases {
                let executor = RecordingCommandExecute::default();
                let (provider, ctx) = command_context(command, profile, executor.clone());
                let credential = provider.provide_credential(&ctx).await.unwrap().unwrap();
                assert_eq!(credential.access_key_id, "test_key");
                assert_eq!(credential.secret_access_key, "test_secret");
                assert_eq!(credential.session_token.as_deref(), Some("test_token"));
                assert!(credential.expires_in.is_some());
                assert_eq!(
                    *executor.calls.lock().unwrap(),
                    vec![expected.to_vec()],
                    "{command:?} via {profile:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_process_commands_do_not_execute() {
        for profile in [None, Some("default"), Some("example")] {
            for command in [
                "",
                "   ",
                r#""""#,
                r#""" arg"#,
                r#""helper"#,
                r#"helper "unfinished"#,
                r#"helper value""#,
            ] {
                let executor = RecordingCommandExecute::default();
                let (provider, ctx) = command_context(command, profile, executor.clone());
                let error = provider.provide_credential(&ctx).await.unwrap_err();
                assert_eq!(
                    error.kind(),
                    ErrorKind::ConfigInvalid,
                    "{command:?} via {profile:?}"
                );
                assert!(executor.calls.lock().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn test_parse_process_output() {
        let json = r#"{
            "Version": 1,
            "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "token",
            "Expiration": "2023-12-01T00:00:00Z"
        }"#;

        let output: ProcessCredentialOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.version, 1);
        assert_eq!(output.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(output.session_token, Some("token".to_string()));
    }
}
