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

use bytes::Bytes;
use reqsign_aws_core::{IMDSv2RegionProvider, SharedConfig};
use reqsign_core::{Context, Error, ErrorKind, FileRead, HttpSend, Result, StaticEnv};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
struct Files(HashMap<String, Vec<u8>>);
impl FileRead for Files {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| Error::unexpected("file absent"))
    }
}

#[derive(Debug)]
struct NoIo;
impl HttpSend for NoIo {
    async fn http_send(&self, _: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        panic!("unexpected network discovery")
    }
}
impl FileRead for NoIo {
    async fn file_read(&self, _: &str) -> Result<Vec<u8>> {
        panic!("unexpected file read")
    }
}
impl reqsign_core::CommandExecute for NoIo {
    async fn command_execute(&self, _: &str, _: &[&str]) -> Result<reqsign_core::CommandOutput> {
        panic!("unexpected credential process")
    }
}

fn context(files: &[(&str, &str)], env: &[(&str, &str)]) -> Context {
    Context::new()
        .with_file_read(Files(
            files
                .iter()
                .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
                .collect(),
        ))
        .with_env(StaticEnv {
            home_dir: Some("/test-home".into()),
            envs: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
        .with_http_send(NoIo)
        .with_command_execute(NoIo)
}

#[tokio::test]
async fn selection_merge_and_no_side_effects() -> Result<()> {
    let ctx = context(
        &[
            (
                "/test-home/.aws/config",
                "[default]\nregion = default-region\n[profile example]\nregion = config-region\nendpoint_url = https://s3.example.invalid\ncredential_process = forbidden\nsso_session = forbidden\nrole_arn = forbidden\naws_secret_access_key = secret-value\n",
            ),
            (
                "/test-home/.aws/credentials",
                "[example]\nregion = credentials-region\naws_access_key_id = key\n",
            ),
        ],
        &[("AWS_PROFILE", "example")],
    );
    let config = SharedConfig::new().with_imds(IMDSv2RegionProvider::new());
    let profile = config.load(&ctx).await?;
    assert_eq!(profile.name(), "example");
    assert_eq!(profile.region(), Some("credentials-region"));
    assert_eq!(profile.endpoint_url(), Some("https://s3.example.invalid"));
    assert_eq!(profile.get("aws_access_key_id"), Some("key"));
    assert_eq!(profile.get("aws_secret_access_key"), Some("secret-value"));
    assert!(!format!("{profile:?}").contains("secret-value"));
    assert_eq!(
        config.resolve_region(&ctx).await?.as_deref(),
        Some("credentials-region")
    );
    let explicit = SharedConfig::new()
        .with_profile("default")
        .load(&ctx)
        .await?;
    assert_eq!(explicit.region(), Some("default-region"));
    let missing = SharedConfig::new()
        .with_profile("missing")
        .load(&ctx)
        .await?;
    assert_eq!(missing.region(), None);
    assert_eq!(missing.endpoint_url(), None);
    Ok(())
}

#[tokio::test]
async fn default_profile_and_alternate_paths() -> Result<()> {
    let ctx = context(
        &[
            (
                "/config",
                "[default]\nregion = config-region\nendpoint_url = https://config.invalid\n",
            ),
            ("/credentials", "[default]\nregion = credentials-region\n"),
            ("/explicit-config", "[default]\nregion = explicit-region\n"),
            (
                "/explicit-credentials",
                "[default]\nendpoint_url = https://explicit.invalid\n",
            ),
        ],
        &[
            ("AWS_CONFIG_FILE", "/config"),
            ("AWS_SHARED_CREDENTIALS_FILE", "/credentials"),
        ],
    );
    let p = SharedConfig::new().load(&ctx).await?;
    assert_eq!(p.name(), "default");
    assert_eq!(p.region(), Some("credentials-region"));
    assert_eq!(p.endpoint_url(), Some("https://config.invalid"));
    let p = SharedConfig::new()
        .with_config_file("/explicit-config")
        .with_credentials_file("/explicit-credentials")
        .load(&ctx)
        .await?;
    assert_eq!(p.region(), Some("explicit-region"));
    assert_eq!(p.endpoint_url(), Some("https://explicit.invalid"));
    Ok(())
}

#[tokio::test]
async fn override_and_environment_precedence() -> Result<()> {
    let ctx = context(
        &[(
            "/test-home/.aws/config",
            "[default]\nregion = profile-region\nendpoint_url = https://profile.invalid\n",
        )],
        &[
            ("AWS_REGION", "env-region"),
            ("AWS_DEFAULT_REGION", "env-default-region"),
            ("AWS_ENDPOINT_URL", "https://env.invalid"),
        ],
    );
    let p = SharedConfig::new().load(&ctx).await?;
    assert_eq!(p.region(), Some("env-region"));
    assert_eq!(p.get("region"), Some("profile-region"));
    assert_eq!(p.endpoint_url(), Some("https://env.invalid"));
    let p = SharedConfig::new()
        .with_region("explicit-region")
        .with_endpoint_url("https://explicit.invalid")
        .load(&ctx)
        .await?;
    assert_eq!(p.region(), Some("explicit-region"));
    assert_eq!(p.endpoint_url(), Some("https://explicit.invalid"));
    let ctx = ctx.with_file_read(NoIo);
    assert_eq!(
        SharedConfig::new().resolve_region(&ctx).await?.as_deref(),
        Some("env-region")
    );
    assert_eq!(
        SharedConfig::new()
            .with_region("explicit")
            .resolve_region(&ctx)
            .await?
            .as_deref(),
        Some("explicit")
    );
    let ctx = context(&[], &[("AWS_DEFAULT_REGION", "fallback")]).with_file_read(NoIo);
    assert_eq!(
        SharedConfig::new().resolve_region(&ctx).await?.as_deref(),
        Some("fallback")
    );
    Ok(())
}

#[tokio::test]
async fn missing_malformed_and_literal_values() -> Result<()> {
    let ctx = context(&[], &[]);
    assert!(SharedConfig::new().load(&ctx).await?.region().is_none());
    assert!(SharedConfig::new().resolve_region(&ctx).await?.is_none());
    let ctx = ctx
        .with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::new(),
        })
        .with_file_read(NoIo);
    assert!(SharedConfig::new().load(&ctx).await?.region().is_none());
    for path in ["/test-home/.aws/config", "/test-home/.aws/credentials"] {
        let ctx = context(&[(path, "[unterminated-secret-value")], &[]);
        let err = SharedConfig::new().load(&ctx).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert!(!format!("{err:?}").contains("secret-value"));
    }
    let ctx = context(
        &[(
            "/test-home/.aws/config",
            r#"[default]
credential_process = "C:\Program Files\helper.exe" "argument with spaces"
s3 =
  endpoint_url = https://nested.invalid
region = us-east-1
"#,
        )],
        &[],
    );
    let p = SharedConfig::new().load(&ctx).await?;
    assert_eq!(
        p.get("credential_process"),
        Some(r#""C:\Program Files\helper.exe" "argument with spaces""#)
    );
    assert_eq!(p.region(), Some("us-east-1"));
    assert_eq!(p.endpoint_url(), None);
    Ok(())
}

#[derive(Debug, Clone)]
struct Metadata {
    requests: Arc<Mutex<Vec<String>>>,
    fail_at: Option<&'static str>,
    pending_at: Option<&'static str>,
    region: &'static str,
}
impl Default for Metadata {
    fn default() -> Self {
        Self {
            requests: Default::default(),
            fail_at: None,
            pending_at: None,
            region: "us-east-2\n",
        }
    }
}
impl HttpSend for Metadata {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        let path = req.uri().path();
        self.requests.lock().unwrap().push(req.uri().to_string());
        if self.pending_at == Some(path) {
            return std::future::pending().await;
        }
        if self.fail_at == Some(path) {
            return Ok(http::Response::builder()
                .status(503)
                .body(Bytes::from_static(b"unavailable"))
                .unwrap());
        }
        let body = match path {
            "/latest/api/token" => {
                assert_eq!(req.method(), http::Method::PUT);
                assert_eq!(
                    req.headers()["x-aws-ec2-metadata-token-ttl-seconds"],
                    "21600"
                );
                "secret-imds-token"
            }
            "/latest/meta-data/placement/region" => {
                assert_eq!(req.method(), http::Method::GET);
                assert_eq!(
                    req.headers()["x-aws-ec2-metadata-token"],
                    "secret-imds-token"
                );
                self.region
            }
            "/latest/meta-data/iam/security-credentials/" => "test-role",
            "/latest/meta-data/iam/security-credentials/test-role" => {
                assert_eq!(
                    req.headers()["x-aws-ec2-metadata-token"],
                    "secret-imds-token"
                );
                r#"{"Code":"Success","AccessKeyId":"key","SecretAccessKey":"secret","Token":"session","Expiration":"2099-01-01T00:00:00Z"}"#
            }
            _ => panic!("unexpected metadata lookup: {path}"),
        };
        Ok(http::Response::new(Bytes::from(body)))
    }
}

#[tokio::test]
async fn metadata_discovery_and_endpoint_selection() -> Result<()> {
    for (explicit, env, host) in [
        (None, vec![], "http://169.254.169.254"),
        (
            None,
            vec![("AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "IPv6")],
            "http://[fd00:ec2::254]",
        ),
        (
            None,
            vec![("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://env.invalid")],
            "http://env.invalid",
        ),
        (
            Some("http://explicit.invalid/"),
            vec![("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://env.invalid")],
            "http://explicit.invalid",
        ),
    ] {
        let http = Metadata::default();
        let ctx = context(&[], &env).with_http_send(http.clone());
        let mut provider = IMDSv2RegionProvider::new();
        if let Some(endpoint) = explicit {
            provider = provider.with_endpoint(endpoint);
        }
        let config = SharedConfig::new().with_imds(provider.clone());
        assert!(config.load(&ctx).await?.region().is_none());
        assert!(http.requests.lock().unwrap().is_empty());
        assert_eq!(
            config.resolve_region(&ctx).await?.as_deref(),
            Some("us-east-2")
        );
        assert_eq!(
            *http.requests.lock().unwrap(),
            vec![
                format!("{host}/latest/api/token"),
                format!("{host}/latest/meta-data/placement/region")
            ]
        );
        assert!(!format!("{provider:?}").contains("secret-imds-token"));
    }
    Ok(())
}

#[tokio::test]
async fn disabled_metadata_and_missing_region() -> Result<()> {
    let ctx = context(&[], &[("AWS_EC2_METADATA_DISABLED", "TRUE")]);
    let config = SharedConfig::new().with_imds(IMDSv2RegionProvider::new());
    assert!(config.resolve_region(&ctx).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn metadata_failures_and_deadline_cover_both_requests() {
    for path in ["/latest/api/token", "/latest/meta-data/placement/region"] {
        let http = Metadata {
            fail_at: Some(path),
            ..Default::default()
        };
        let ctx = context(&[], &[]).with_http_send(http.clone());
        assert!(
            IMDSv2RegionProvider::new()
                .resolve_region(&ctx)
                .await
                .is_err()
        );
        assert!(
            http.requests
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .ends_with(path)
        );
        let http = Metadata {
            pending_at: Some(path),
            ..Default::default()
        };
        let ctx = context(&[], &[]).with_http_send(http.clone());
        let err = IMDSv2RegionProvider::new()
            .with_timeout(Duration::from_millis(10))
            .resolve_region(&ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"));
        assert!(
            http.requests
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .ends_with(path)
        );
    }
    for region in ["", "\n", "invalid region"] {
        let ctx = context(&[], &[]).with_http_send(Metadata {
            region,
            ..Default::default()
        });
        let err = IMDSv2RegionProvider::new()
            .resolve_region(&ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid IMDS region"));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn credential_provider_uses_the_same_profile_and_files() -> Result<()> {
    use reqsign_core::ProvideCredential;
    let ctx = context(
        &[
            (
                "/config",
                "[profile selected]\nregion = eu-west-1\naws_access_key_id = config-key\naws_secret_access_key = config-secret\n",
            ),
            (
                "/credentials",
                "[selected]\naws_access_key_id = credentials-key\naws_secret_access_key = credentials-secret\n",
            ),
        ],
        &[
            ("AWS_PROFILE", "selected"),
            ("AWS_CONFIG_FILE", "/config"),
            ("AWS_SHARED_CREDENTIALS_FILE", "/credentials"),
        ],
    );
    let profile = SharedConfig::new().load(&ctx).await?;
    let credential = reqsign_aws_core::ProfileCredentialProvider::new()
        .provide_credential(&ctx)
        .await?
        .unwrap();
    assert_eq!(profile.region(), Some("eu-west-1"));
    assert_eq!(
        profile.get("aws_access_key_id"),
        Some(credential.access_key_id.as_str())
    );
    assert_eq!(
        profile.get("aws_secret_access_key"),
        Some(credential.secret_access_key.as_str())
    );
    Ok(())
}

#[tokio::test]
async fn metadata_transport_failure_is_an_error() {
    let ctx = context(&[], &[]).with_http_send(reqsign_core::NoopHttpSend);
    let err = IMDSv2RegionProvider::new()
        .resolve_region(&ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("failed to connect to IMDS"));
}

#[tokio::test]
async fn credential_metadata_still_uses_shared_token_protocol() -> Result<()> {
    use reqsign_core::ProvideCredential;
    let http = Metadata::default();
    let ctx = context(&[], &[]).with_http_send(http.clone());
    let provider = reqsign_aws_core::IMDSv2CredentialProvider::new();
    let credential = provider.provide_credential(&ctx).await?.unwrap();
    assert_eq!(credential.access_key_id, "key");
    assert_eq!(credential.session_token.as_deref(), Some("session"));
    assert_eq!(http.requests.lock().unwrap().len(), 3);
    assert!(!format!("{provider:?}").contains("secret-imds-token"));
    Ok(())
}

#[tokio::test]
async fn metadata_tokens_are_reused_only_for_the_same_endpoint() -> Result<()> {
    let http = Metadata::default();
    let ctx = context(&[], &[]).with_http_send(http.clone());
    let provider = IMDSv2RegionProvider::new();
    provider.resolve_region(&ctx).await?;
    provider.resolve_region(&ctx).await?;
    assert_eq!(http.requests.lock().unwrap().len(), 3);
    let ctx = context(
        &[],
        &[("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://other.invalid")],
    )
    .with_http_send(http.clone());
    provider.resolve_region(&ctx).await?;
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[3], "http://other.invalid/latest/api/token");
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn sharing_config_loading_preserves_existing_process_invocation() -> Result<()> {
    use reqsign_core::{CommandExecute, CommandOutput, ProvideCredential};
    #[derive(Debug)]
    struct Command;
    impl CommandExecute for Command {
        async fn command_execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
            assert_eq!(program, "helper");
            assert_eq!(args, ["--profile", "selected"]);
            Ok(CommandOutput {
                status: 0,
                stdout: br#"{"Version":1,"AccessKeyId":"key","SecretAccessKey":"secret"}"#.to_vec(),
                stderr: vec![],
            })
        }
    }
    let ctx = context(
        &[(
            "/config",
            "[profile selected]\ncredential_process = \"helper\" --profile selected\n",
        )],
        &[("AWS_PROFILE", "selected"), ("AWS_CONFIG_FILE", "/config")],
    )
    .with_command_execute(Command);
    let credential = reqsign_aws_core::ProcessCredentialProvider::new()
        .provide_credential(&ctx)
        .await?
        .unwrap();
    assert_eq!(credential.access_key_id, "key");
    Ok(())
}
