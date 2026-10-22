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
#[cfg(all(test, not(target_arch = "wasm32")))]
use crate::constants::*;
use reqsign_core::{Context, ProvideCredential, Result};

/// ProfileCredentialProvider loads AWS credentials from configuration files.
///
/// This provider loads credentials from:
/// - `~/.aws/credentials` (or the path specified by `AWS_SHARED_CREDENTIALS_FILE`)
/// - `~/.aws/config` (or the path specified by `AWS_CONFIG_FILE`)
///
/// A complete access key and secret key pair in the credentials file takes
/// precedence. Otherwise, the provider tries the config file without combining
/// credentials across files.
///
/// The profile to use is determined by:
/// 1. The profile specified via `with_profile()`
/// 2. The `AWS_PROFILE` environment variable
/// 3. Default to "default"
#[derive(Debug, Clone)]
pub struct ProfileCredentialProvider {
    profile: Option<String>,
    config_file: Option<String>,
    credentials_file: Option<String>,
}

impl Default for ProfileCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileCredentialProvider {
    /// Create a new ProfileCredentialProvider with default settings.
    pub fn new() -> Self {
        Self {
            profile: None,
            config_file: None,
            credentials_file: None,
        }
    }

    /// Set the profile name to use.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the path to the config file.
    pub fn with_config_file(mut self, path: impl Into<String>) -> Self {
        self.config_file = Some(path.into());
        self
    }

    /// Set the path to the credentials file.
    pub fn with_credentials_file(mut self, path: impl Into<String>) -> Self {
        self.credentials_file = Some(path.into());
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn shared_config(&self) -> crate::SharedConfig {
        let mut config = crate::SharedConfig::new();
        if let Some(v) = &self.profile {
            config = config.with_profile(v);
        }
        if let Some(v) = &self.config_file {
            config = config.with_config_file(v);
        }
        if let Some(v) = &self.credentials_file {
            config = config.with_credentials_file(v);
        }
        config
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn credential_from_properties(props: &ini::Properties) -> Option<Credential> {
    Some(Credential {
        access_key_id: props.get("aws_access_key_id")?.to_owned(),
        secret_access_key: props.get("aws_secret_access_key")?.to_owned(),
        session_token: props.get("aws_session_token").map(str::to_owned),
        expires_in: None,
    })
}

impl ProvideCredential for ProfileCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            Ok(None)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let shared = self.shared_config();
            let profile = shared.profile_name(ctx);
            let credentials = shared.load_credentials_file(ctx).await?;
            if let Some(credential) = credentials
                .section(Some(&profile))
                .and_then(credential_from_properties)
            {
                return Ok(Some(credential));
            }

            let config = shared.load_config_file(ctx).await?;
            Ok(config
                .section(Some(crate::config::config_section(&profile)))
                .and_then(credential_from_properties))
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use reqsign_core::StaticEnv;
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_profile_from_credentials_file() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let tmp_dir = tempdir()?;
        let file_path = tmp_dir.path().join("credentials");
        let mut tmp_file = File::create(&file_path)?;
        writeln!(tmp_file, "[default]")?;
        writeln!(tmp_file, "aws_access_key_id = DEFAULTACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = DEFAULTSECRETACCESSKEY")?;
        writeln!(tmp_file, "aws_session_token = DEFAULTSESSIONTOKEN")?;
        writeln!(tmp_file)?;
        writeln!(tmp_file, "[profile1]")?;
        writeln!(tmp_file, "aws_access_key_id = PROFILE1ACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = PROFILE1SECRETACCESSKEY")?;
        writeln!(tmp_file, "aws_session_token = PROFILE1SESSIONTOKEN")?;

        let context = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        // Test the final default fallback without an explicit profile or AWS_PROFILE
        let provider =
            ProfileCredentialProvider::new().with_credentials_file(file_path.to_str().unwrap());
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "DEFAULTACCESSKEYID");
        assert_eq!(cred.secret_access_key, "DEFAULTSECRETACCESSKEY");
        assert_eq!(cred.session_token, Some("DEFAULTSESSIONTOKEN".to_string()));

        // Test specific profile
        let provider = ProfileCredentialProvider::new()
            .with_profile("profile1")
            .with_credentials_file(file_path.to_str().unwrap());
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "PROFILE1ACCESSKEYID");
        assert_eq!(cred.secret_access_key, "PROFILE1SECRETACCESSKEY");
        assert_eq!(cred.session_token, Some("PROFILE1SESSIONTOKEN".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_profile_from_config_file() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let tmp_dir = tempdir()?;
        let file_path = tmp_dir.path().join("config");
        let mut tmp_file = File::create(&file_path)?;
        writeln!(tmp_file, "[default]")?;
        writeln!(tmp_file, "aws_access_key_id = DEFAULTACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = DEFAULTSECRETACCESSKEY")?;
        writeln!(tmp_file)?;
        writeln!(tmp_file, "[profile profile1]")?;
        writeln!(tmp_file, "aws_access_key_id = PROFILE1ACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = PROFILE1SECRETACCESSKEY")?;

        let context = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        // Test default profile
        let provider =
            ProfileCredentialProvider::new().with_config_file(file_path.to_str().unwrap());
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "DEFAULTACCESSKEYID");
        assert_eq!(cred.secret_access_key, "DEFAULTSECRETACCESSKEY");
        assert!(cred.session_token.is_none());

        // Test specific profile
        let provider = ProfileCredentialProvider::new()
            .with_profile("profile1")
            .with_config_file(file_path.to_str().unwrap());
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "PROFILE1ACCESSKEYID");
        assert_eq!(cred.secret_access_key, "PROFILE1SECRETACCESSKEY");
        assert!(cred.session_token.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_profile_env_fallback() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let tmp_dir = tempdir()?;
        let file_path = tmp_dir.path().join("credentials");
        let mut tmp_file = File::create(&file_path)?;
        writeln!(tmp_file, "[default]")?;
        writeln!(tmp_file, "aws_access_key_id = DEFAULTACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = DEFAULTSECRETACCESSKEY")?;
        writeln!(tmp_file)?;
        writeln!(tmp_file, "[profile1]")?;
        writeln!(tmp_file, "aws_access_key_id = PROFILE1ACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = PROFILE1SECRETACCESSKEY")?;

        let context = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(AWS_PROFILE.to_string(), "profile1".to_string())]),
            });

        let provider =
            ProfileCredentialProvider::new().with_credentials_file(file_path.to_str().unwrap());
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "PROFILE1ACCESSKEYID");
        assert_eq!(cred.secret_access_key, "PROFILE1SECRETACCESSKEY");

        Ok(())
    }

    #[tokio::test]
    async fn test_explicit_profile_overrides_env() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let tmp_dir = tempdir()?;
        let file_path = tmp_dir.path().join("credentials");
        let mut tmp_file = File::create(&file_path)?;
        writeln!(tmp_file, "[default]")?;
        writeln!(tmp_file, "aws_access_key_id = DEFAULTACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = DEFAULTSECRETACCESSKEY")?;
        writeln!(tmp_file)?;
        writeln!(tmp_file, "[profile1]")?;
        writeln!(tmp_file, "aws_access_key_id = PROFILE1ACCESSKEYID")?;
        writeln!(tmp_file, "aws_secret_access_key = PROFILE1SECRETACCESSKEY")?;

        let context = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(AWS_PROFILE.to_string(), "profile1".to_string())]),
            });

        let provider = ProfileCredentialProvider::new()
            .with_profile("default")
            .with_credentials_file(file_path.to_str().unwrap());
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_some());
        let cred = cred.unwrap();
        assert_eq!(cred.access_key_id, "DEFAULTACCESSKEYID");
        assert_eq!(cred.secret_access_key, "DEFAULTSECRETACCESSKEY");

        Ok(())
    }

    #[tokio::test]
    async fn test_profile_missing_credentials() -> anyhow::Result<()> {
        let context = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());

        let provider = ProfileCredentialProvider::new()
            .with_credentials_file("/non/existent/path")
            .with_config_file("/non/existent/path");
        let cred = provider.provide_credential(&context).await?;
        assert!(cred.is_none());

        Ok(())
    }
}
