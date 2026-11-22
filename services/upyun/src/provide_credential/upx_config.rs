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
#[cfg(not(target_arch = "wasm32"))]
use log::debug;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::Error;
use reqsign_core::Result;
#[cfg(not(target_arch = "wasm32"))]
use reqsign_core::hash::base64_decode;
use reqsign_core::{Context, ProvideCredential};
#[cfg(not(target_arch = "wasm32"))]
use serde::Deserialize;

/// The default location of the Upyun CLI (`upx`) configuration file.
#[cfg(not(target_arch = "wasm32"))]
const UPX_CONFIG_FILE: &str = "~/.upx.cfg";

/// UpxConfigCredentialProvider loads a session from the Upyun CLI `~/.upx.cfg`.
///
/// The Upyun CLI stores one session per bucket and operator pair. Each session
/// contains the bucket, operator name, and password. The session selected by
/// `user_idx` is the CLI's current session. Upyun operators can access multiple
/// buckets, and the file has no account or endpoint scope beyond the bucket.
///
/// Without [`UpxConfigCredentialProvider::with_bucket`], the provider returns
/// the current CLI session. With a bucket, it prefers the current session when
/// its bucket matches and otherwise selects the first session for that bucket,
/// matching `upx switch`. This avoids signing for one bucket with the identity
/// of a different bucket's session.
///
/// A missing file, an unset or invalid active index, no matching bucket, and an
/// incomplete session are treated as no credential. A file that exists but
/// cannot be decoded or parsed is a configuration error.
#[derive(Debug, Default, Clone)]
pub struct UpxConfigCredentialProvider {
    config_file: Option<String>,
    bucket: Option<String>,
}

impl UpxConfigCredentialProvider {
    /// Create a new provider using the default `~/.upx.cfg` location.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a custom configuration file path.
    ///
    /// This is useful for applications that isolate the CLI configuration or
    /// for tests. A leading `~/` is expanded through the [`Context`].
    pub fn with_config_file(mut self, path: impl Into<String>) -> Self {
        self.config_file = Some(path.into());
        self
    }

    /// Select the session for a specific bucket.
    ///
    /// When set, the provider prefers the current session if its bucket
    /// matches, then falls back to the first session for that bucket. Without
    /// this setting, the provider returns the current CLI session regardless of
    /// its bucket.
    pub fn with_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_config(&self, ctx: &Context) -> Result<Option<UpxConfig>> {
        let path = self.config_file.as_deref().unwrap_or(UPX_CONFIG_FILE);
        let Some(path) = ctx.expand_home_dir(path) else {
            debug!("failed to expand the upx configuration path");
            return Ok(None);
        };

        let content = match ctx.file_read(&path).await {
            Ok(content) => content,
            Err(err) => {
                debug!("failed to read the upx configuration file {path}: {err:?}");
                return Ok(None);
            }
        };

        let content = content.trim_ascii();
        if content.is_empty() {
            debug!("the upx configuration file is empty");
            return Ok(None);
        }

        let decoded = decode_upx_config(content)?;
        let config = serde_json::from_slice(&decoded).map_err(|e| {
            Error::config_invalid("failed to parse the upx configuration file").with_source(e)
        })?;

        Ok(Some(config))
    }
}

impl ProvideCredential for UpxConfigCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            Ok(None)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let Some(config) = self.load_config(ctx).await? else {
                return Ok(None);
            };

            let current = config
                .user_idx
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| config.users.get(index));
            let session = match self.bucket.as_deref() {
                Some(bucket) => current
                    .filter(|session| session.bucket == bucket)
                    .or_else(|| config.users.iter().find(|session| session.bucket == bucket)),
                None => current,
            };
            let Some(session) = session else {
                debug!("the upx configuration has no matching session");
                return Ok(None);
            };

            if session.username.is_empty() || session.password.is_empty() {
                debug!("the selected upx session is incomplete");
                return Ok(None);
            }

            Ok(Some(Credential::new(
                session.username.clone(),
                session.password.clone(),
            )))
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn decode_upx_config(content: &[u8]) -> Result<Vec<u8>> {
    let decoded = content
        .iter()
        .map(|byte| match byte {
            b'a'..=b'z' => byte.to_ascii_uppercase(),
            b'A'..=b'Z' => byte.to_ascii_lowercase(),
            b'0'..=b'9' => b'9' - (byte - b'0'),
            _ => *byte,
        })
        .collect::<Vec<_>>();

    let decoded = String::from_utf8(decoded).map_err(|e| {
        Error::config_invalid("the upx configuration is not valid ASCII").with_source(e)
    })?;

    base64_decode(&decoded).map_err(|e| {
        Error::config_invalid("failed to decode the upx configuration file").with_source(e)
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct UpxConfig {
    #[serde(default)]
    user_idx: Option<i64>,
    #[serde(default)]
    users: Vec<UpxSession>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct UpxSession {
    #[serde(default)]
    bucket: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use reqsign_core::hash::base64_encode;
    use reqsign_core::{FileRead, StaticEnv};
    use std::collections::HashMap;

    #[derive(Debug)]
    struct TestFileRead {
        files: HashMap<String, Vec<u8>>,
    }

    impl FileRead for TestFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| Error::config_invalid(format!("unexpected file path: {path}")))
        }
    }

    fn encode_upx_config(value: &serde_json::Value) -> Vec<u8> {
        let json = serde_json::to_vec(value).expect("test config must serialize");
        let encoded = base64_encode(&json);

        encoded
            .bytes()
            .map(|byte| match byte {
                b'a'..=b'z' => byte.to_ascii_uppercase(),
                b'A'..=b'Z' => byte.to_ascii_lowercase(),
                b'0'..=b'9' => b'9' - (byte - b'0'),
                _ => byte,
            })
            .collect()
    }

    fn ctx_with_config(path: &str, content: Vec<u8>) -> Context {
        Context::new().with_file_read(TestFileRead {
            files: HashMap::from([(path.to_string(), content)]),
        })
    }

    #[tokio::test]
    async fn decodes_a_first_party_upx_config_file() -> anyhow::Result<()> {
        // Fixture encoded with the upx `hashEncode(base64(json))` file format.
        let path = "/test/.upx.cfg";
        let ctx = ctx_with_config(path, include_bytes!("../../testdata/upx.cfg").to_vec());
        let provider = UpxConfigCredentialProvider::new().with_config_file(path);

        let credential = provider
            .provide_credential(&ctx)
            .await?
            .expect("the fixture session must load");

        assert_eq!(credential.operator, "operator123");
        assert_eq!(credential.password, "password123");
        Ok(())
    }

    #[tokio::test]
    async fn loads_the_current_upx_session() -> anyhow::Result<()> {
        let path = "/test/.upx.cfg";
        let content = encode_upx_config(&serde_json::json!({
            "user_idx": 1,
            "users": [
                {"bucket": "first", "username": "first-operator", "password": "first-password"},
                {"bucket": "second", "username": "second-operator", "password": "second-password"}
            ]
        }));
        let ctx = ctx_with_config(path, content);
        let provider = UpxConfigCredentialProvider::new().with_config_file(path);

        let credential = provider
            .provide_credential(&ctx)
            .await?
            .expect("the active session must load");

        assert_eq!(credential.operator, "second-operator");
        assert_eq!(credential.password, "second-password");
        Ok(())
    }

    #[tokio::test]
    async fn with_bucket_selects_the_session_for_that_bucket() -> anyhow::Result<()> {
        let path = "/test/.upx.cfg";
        let content = encode_upx_config(&serde_json::json!({
            "user_idx": 1,
            "users": [
                {"bucket": "first", "username": "first-operator", "password": "first-password"},
                {"bucket": "second", "username": "second-operator", "password": "second-password"}
            ]
        }));
        let ctx = ctx_with_config(path, content);

        for (bucket, expected) in [("first", "first-operator"), ("second", "second-operator")] {
            let credential = UpxConfigCredentialProvider::new()
                .with_config_file(path)
                .with_bucket(bucket)
                .provide_credential(&ctx)
                .await?
                .expect("the matching session must load");
            assert_eq!(credential.operator, expected);
        }

        let credential = UpxConfigCredentialProvider::new()
            .with_config_file(path)
            .with_bucket("missing")
            .provide_credential(&ctx)
            .await?;
        assert!(credential.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn with_bucket_does_not_require_a_current_index() -> anyhow::Result<()> {
        let path = "/test/.upx.cfg";
        let content = encode_upx_config(&serde_json::json!({
            "user_idx": -1,
            "users": [
                {"bucket": "bucket", "username": "operator", "password": "password"}
            ]
        }));
        let ctx = ctx_with_config(path, content);

        let credential = UpxConfigCredentialProvider::new()
            .with_config_file(path)
            .with_bucket("bucket")
            .provide_credential(&ctx)
            .await?
            .expect("the bucket session must load");

        assert_eq!(credential.operator, "operator");
        Ok(())
    }

    #[tokio::test]
    async fn expands_the_default_home_path() -> anyhow::Result<()> {
        let path = "/home/tester/.upx.cfg";
        let content = encode_upx_config(&serde_json::json!({
            "user_idx": 0,
            "users": [
                {"bucket": "bucket", "username": "operator", "password": "password"}
            ]
        }));
        let ctx = ctx_with_config(path, content).with_env(StaticEnv {
            home_dir: Some("/home/tester".into()),
            envs: HashMap::new(),
        });

        let credential = UpxConfigCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .expect("the default session must load");

        assert_eq!(credential.operator, "operator");
        assert_eq!(credential.password, "password");
        Ok(())
    }

    #[tokio::test]
    async fn returns_none_without_an_active_session() -> anyhow::Result<()> {
        let path = "/test/.upx.cfg";
        let provider = UpxConfigCredentialProvider::new().with_config_file(path);

        for config in [
            serde_json::json!({
                "user_idx": -1,
                "users": [
                    {"bucket": "bucket", "username": "operator", "password": "password"}
                ]
            }),
            serde_json::json!({
                "users": [
                    {"bucket": "bucket", "username": "operator", "password": "password"}
                ]
            }),
        ] {
            let ctx = ctx_with_config(path, encode_upx_config(&config));
            assert!(provider.provide_credential(&ctx).await?.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn returns_none_for_a_missing_file() -> anyhow::Result<()> {
        let ctx = Context::new().with_file_read(TestFileRead {
            files: HashMap::new(),
        });
        let provider = UpxConfigCredentialProvider::new();

        assert!(provider.provide_credential(&ctx).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_a_file_that_cannot_be_decoded() -> anyhow::Result<()> {
        let path = "/test/.upx.cfg";
        let ctx = ctx_with_config(path, b"not base64".to_vec());
        let provider = UpxConfigCredentialProvider::new().with_config_file(path);

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("invalid config must fail closed");
        assert_eq!(err.kind(), reqsign_core::ErrorKind::ConfigInvalid);
        Ok(())
    }
}
