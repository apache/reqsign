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

use super::*;
use bytes::Bytes;
use http::Response;
use reqsign_core::{FileRead, HttpSend, StaticEnv};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Mutex as StdMutex;
use std::task::Poll;
use tokio::sync::Notify;

const START_URL: &str = "https://example.awsapps.com/start";

#[derive(Debug, Default)]
struct Files(StdMutex<HashMap<String, Vec<u8>>>);

impl FileRead for Files {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| Error::unexpected("file not found"))
    }
}

impl Files {
    fn put(&self, path: &str, content: impl Into<Vec<u8>>) {
        self.0
            .lock()
            .unwrap()
            .insert(path.to_string(), content.into());
    }

    fn token(&self, home: &str, name: &str, value: Value) {
        self.put(
            &format!("{home}/.aws/sso/cache/{}.json", hex_sha1(name.as_bytes())),
            value.to_string(),
        );
    }
}

#[derive(Debug, Default)]
struct Http {
    requests: StdMutex<Vec<Request<Bytes>>>,
    responses: StdMutex<VecDeque<Result<Response<Bytes>>>>,
    refresh_gate: Option<Notify>,
}

impl HttpSend for Http {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        let refreshing = request.method() == Method::POST;
        self.requests.lock().unwrap().push(request);
        if refreshing {
            if let Some(gate) = &self.refresh_gate {
                gate.notified().await;
            }
        }
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected HTTP request")
    }
}

impl Http {
    fn reply(&self, status: u16, value: Value) {
        self.responses
            .lock()
            .unwrap()
            .push_back(Ok(Response::builder()
                .status(status)
                .body(Bytes::from(value.to_string()))
                .unwrap()));
    }

    fn role(&self) {
        self.reply(
            200,
            json!({"roleCredentials": {
                "accessKeyId": "role-key", "secretAccessKey": "role-secret",
                "sessionToken": "role-token", "expiration": 2000000000000i64
            }}),
        );
    }

    fn refresh(&self, token: &str, refresh: Option<&str>) {
        self.reply(
            200,
            json!({"accessToken": token, "expiresIn": 60, "refreshToken": refresh}),
        );
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

fn config(session: &str) -> String {
    format!(
        "[profile test]\nsso_session = {session}\nsso_account_id = 123456789012\nsso_role_name = Reader\n\n[sso-session {session}]\nsso_region = us-east-1\nsso_start_url = {START_URL}\n"
    )
}

fn cached(expires: &str) -> Value {
    json!({"accessToken": "cached-access-secret", "expiresAt": expires,
        "refreshToken": "original-refresh-secret", "clientId": "client-id",
        "clientSecret": "client-secret", "registrationExpiresAt": "2099-01-01T00:00:00Z"})
}

fn timestamp() -> Timestamp {
    "2026-01-01T00:00:00Z".parse().unwrap()
}

fn context(files: &Arc<Files>, http: &Arc<Http>, home: &str, config_path: &str) -> Context {
    Context::new()
        .with_file_read(files.clone())
        .with_http_send(http.clone())
        .with_env(StaticEnv {
            home_dir: Some(home.into()),
            envs: HashMap::from([
                ("AWS_CONFIG_FILE".into(), config_path.into()),
                ("AWS_PROFILE".into(), "test".into()),
            ]),
        })
}

fn fixture(token: Value) -> (Context, Arc<Files>, Arc<Http>) {
    let files = Arc::new(Files::default());
    let http = Arc::new(Http::default());
    files.put("/config", config("one"));
    files.token("/test", "one", token);
    (context(&files, &http, "/test", "/config"), files, http)
}

#[tokio::test]
async fn unexpired_token_is_used_without_refresh_material() {
    let (ctx, _, http) = fixture(json!({
        "accessToken": "cached-access-secret", "expiresAt": "2099-01-01T00:00:00Z"
    }));
    http.role();
    let credential = SSOCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.access_key_id, "role-key");
    assert_eq!(
        credential.expires_in.unwrap(),
        Timestamp::from_millisecond(2000000000000).unwrap()
    );
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), Method::GET);
    assert_eq!(
        requests[0].uri().to_string(),
        "https://portal.sso.us-east-1.amazonaws.com/federation/credentials?role_name=Reader&account_id=123456789012"
    );
    assert_eq!(
        requests[0].headers()["x-amz-sso_bearer_token"],
        "cached-access-secret"
    );
    assert!(requests[0].headers()["x-amz-sso_bearer_token"].is_sensitive());
}

#[tokio::test]
async fn refresh_rotation_survives_role_failure_and_subsequent_refresh() {
    let (ctx, files, http) = fixture(cached("2025-01-01T00:00:00Z"));
    let disk_before = files.0.lock().unwrap().clone();
    let provider = SSOCredentialProvider::new();
    http.refresh("new-access-secret", Some("rotated-refresh-secret"));
    http.reply(503, json!({"secret": "do-not-log"}));
    assert!(provider.provide_with_clock(&ctx, timestamp).await.is_err());
    http.role();
    provider
        .clone()
        .provide_with_clock(&ctx, || timestamp() + std::time::Duration::from_secs(59))
        .await
        .unwrap();
    http.refresh("next-access-secret", None);
    http.role();
    provider
        .provide_with_clock(&ctx, || timestamp() + std::time::Duration::from_secs(60))
        .await
        .unwrap();
    http.refresh("third-access-secret", None);
    http.role();
    provider
        .provide_with_clock(&ctx, || timestamp() + std::time::Duration::from_secs(120))
        .await
        .unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests[0].uri(),
        "https://oidc.us-east-1.amazonaws.com/token"
    );
    assert_eq!(
        requests[0].headers()[http::header::CONTENT_TYPE],
        "application/json"
    );
    let body: Value = serde_json::from_slice(requests[0].body()).unwrap();
    assert_eq!(
        body,
        json!({"grantType": "refresh_token", "clientId": "client-id", "clientSecret": "client-secret", "refreshToken": "original-refresh-secret"})
    );
    for index in [3, 5] {
        let body: Value = serde_json::from_slice(requests[index].body()).unwrap();
        assert_eq!(body["refreshToken"], "rotated-refresh-secret");
    }
    for (index, token) in [
        (1, "new-access-secret"),
        (2, "new-access-secret"),
        (4, "next-access-secret"),
        (6, "third-access-secret"),
    ] {
        assert_eq!(requests[index].headers()["x-amz-sso_bearer_token"], token);
    }
    assert_eq!(*files.0.lock().unwrap(), disk_before);
    let debug = format!("{provider:?}");
    for secret in [
        "cached-access-secret",
        "new-access-secret",
        "third-access-secret",
        "rotated-refresh-secret",
        "client-secret",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[tokio::test]
async fn concurrent_clones_exchange_refresh_token_once() {
    let files = Arc::new(Files::default());
    files.put("/config", config("one"));
    files.token("/test", "one", cached("2025-01-01T00:00:00Z"));
    let http = Arc::new(Http {
        refresh_gate: Some(Notify::new()),
        ..Http::default()
    });
    http.refresh("new-token", Some("rotated"));
    http.role();
    http.role();
    let ctx = context(&files, &http, "/test", "/config");
    let provider = SSOCredentialProvider::new();
    let clone = provider.clone();
    let mut first = pin!(provider.provide_with_clock(&ctx, timestamp));
    let mut second = pin!(clone.provide_with_clock(&ctx, timestamp));
    poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        assert!(second.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(http.count(), 1);
    http.refresh_gate.as_ref().unwrap().notify_one();
    let (a, b) = tokio::join!(first, second);
    assert!(a.unwrap().is_some());
    assert!(b.unwrap().is_some());
    assert_eq!(http.count(), 3);
}

#[tokio::test]
async fn missing_or_expired_refresh_material_requires_login_without_http() {
    for field in [
        "refreshToken",
        "clientId",
        "clientSecret",
        "registrationExpiresAt",
    ] {
        for value in [Value::Null, json!("")] {
            let mut token = cached("2025-01-01T00:00:00Z");
            token[field] = value;
            let (ctx, _, http) = fixture(token);
            let error = SSOCredentialProvider::new()
                .provide_with_clock(&ctx, timestamp)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("SSO refresh material is missing")
            );
            assert!(error.to_string().contains("aws sso login"));
            assert_eq!(http.count(), 0);
        }
    }
    for expiry in [
        "2026-01-01T00:00:00Z",
        "2025-01-01T00:00:00Z",
        "invalid-client-secret",
    ] {
        let mut token = cached("2025-01-01T00:00:00Z");
        token["registrationExpiresAt"] = json!(expiry);
        let (ctx, _, http) = fixture(token);
        let error = SSOCredentialProvider::new()
            .provide_with_clock(&ctx, timestamp)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("aws sso login"));
        assert!(!format!("{error:?}").contains("invalid-client-secret"));
        assert_eq!(http.count(), 0);
    }
}

#[tokio::test]
async fn rejected_or_malformed_refresh_never_uses_expired_token_or_leaks_secrets() {
    for (status, body) in [
        (
            400,
            json!({"error": "invalid_grant", "error_description": "client-secret"}),
        ),
        (401, json!({"error": "invalid_client"})),
        (
            400,
            json!({"error": "client-secret", "error_description": "new-secret"}),
        ),
        (
            200,
            json!({"accessToken": "new-secret", "expiresIn": "client-secret"}),
        ),
        (200, json!({"accessToken": "new-secret", "expiresIn": 0})),
        (200, json!({"accessToken": "new-secret", "expiresIn": -1})),
        (
            200,
            json!({"accessToken": "new-secret", "expiresIn": i64::MAX}),
        ),
        (200, json!({"accessToken": "", "expiresIn": 60})),
    ] {
        let (ctx, _, http) = fixture(cached("2025-01-01T00:00:00Z"));
        http.reply(status, body);
        let error = SSOCredentialProvider::new()
            .provide_with_clock(&ctx, timestamp)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("aws sso login"));
        assert!(!format!("{error:?}").contains("client-secret"));
        assert!(!format!("{error:?}").contains("new-secret"));
        assert_eq!(http.count(), 1);
    }
}

#[tokio::test]
async fn transport_failure_can_retry_without_losing_refresh_material() {
    let (ctx, _, http) = fixture(cached("2025-01-01T00:00:00Z"));
    http.responses
        .lock()
        .unwrap()
        .push_back(Err(Error::unexpected("client-secret")));
    let provider = SSOCredentialProvider::new();
    let error = provider
        .provide_with_clock(&ctx, timestamp)
        .await
        .unwrap_err();
    assert!(!format!("{error:?}").contains("client-secret"));
    http.refresh("new-token", None);
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    assert_eq!(http.count(), 3);
}

#[tokio::test]
async fn sessions_with_same_start_url_have_separate_cache_and_refresh_state() {
    let (ctx, files, http) = fixture(cached("2025-01-01T00:00:00Z"));
    let mut other = cached("2025-01-01T00:00:00Z");
    other["refreshToken"] = json!("session-two-refresh");
    files.token("/test", "two", other);
    let provider = SSOCredentialProvider::new();
    http.refresh("session-one-access", None);
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    files.put("/config", config("two"));
    http.refresh("session-two-access", None);
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    files.put("/config", config("one"));
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    let requests = http.requests.lock().unwrap();
    let body: Value = serde_json::from_slice(requests[2].body()).unwrap();
    assert_eq!(body["refreshToken"], "session-two-refresh");
    assert_eq!(
        requests[3].headers()["x-amz-sso_bearer_token"],
        "session-two-access"
    );
    assert_eq!(
        requests[4].headers()["x-amz-sso_bearer_token"],
        "session-one-access"
    );
    assert_eq!(requests.len(), 5);
}

#[tokio::test]
async fn cache_paths_and_config_sources_isolate_clones() {
    let (ctx, files, http) = fixture(cached("2099-01-01T00:00:00Z"));
    let provider = SSOCredentialProvider::new();
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    let mut other = cached("2099-01-01T00:00:00Z");
    other["accessToken"] = json!("other-home");
    files.token("/other", "one", other);
    http.role();
    provider
        .clone()
        .provide_with_clock(&context(&files, &http, "/other", "/config"), timestamp)
        .await
        .unwrap();
    files.put("/other-config", config("one"));
    let mut other = cached("2099-01-01T00:00:00Z");
    other["accessToken"] = json!("other-config");
    files.token("/test", "one", other);
    http.role();
    provider
        .provide_with_clock(&context(&files, &http, "/test", "/other-config"), timestamp)
        .await
        .unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(
        requests[1].headers()["x-amz-sso_bearer_token"],
        "other-home"
    );
    assert_eq!(
        requests[2].headers()["x-amz-sso_bearer_token"],
        "other-config"
    );
}

#[tokio::test]
async fn legacy_inline_config_uses_url_cache_and_never_refreshes() {
    let (ctx, files, http) = fixture(cached("2099-01-01T00:00:00Z"));
    files.put("/config", format!("[profile test]\nsso_start_url = {START_URL}\nsso_region = us-east-1\nsso_account_id = 123\nsso_role_name = Reader\n"));
    files.token("/test", START_URL, cached("2026-01-01T00:00:01Z"));
    let provider = SSOCredentialProvider::new();
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    let error = provider
        .provide_with_clock(&ctx, || timestamp() + std::time::Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("legacy SSO token has expired"));
    assert_eq!(http.count(), 1);
}

#[tokio::test]
async fn named_session_never_falls_back_to_url_cache_or_another_provider() {
    let (ctx, files, http) = fixture(cached("2025-01-01T00:00:00Z"));
    files.token("/test", START_URL, cached("2099-01-01T00:00:00Z"));
    http.reply(400, json!({"error": "invalid_grant"}));
    let provider = crate::DefaultCredentialProvider::builder()
        .no_env()
        .no_profile()
        .no_web_identity()
        .no_process()
        .no_imds()
        .with_profile("test")
        .build();
    // The default chain must preserve the SSO error instead of returning None.
    let error = provider.provide_credential(&ctx).await.unwrap_err();
    assert!(error.to_string().contains("SSO token refresh rejected"));
    assert_eq!(http.count(), 1);
    http.refresh("default-chain-access", None);
    http.role();
    assert_eq!(
        provider
            .provide_credential(&ctx)
            .await
            .unwrap()
            .unwrap()
            .access_key_id,
        "role-key"
    );
    assert_eq!(http.count(), 3);
}

#[tokio::test]
async fn missing_named_cache_does_not_use_legacy_url_cache() {
    let (ctx, files, http) = fixture(cached("2099-01-01T00:00:00Z"));
    files.put("/config", config("missing"));
    files.token("/test", START_URL, cached("2099-01-01T00:00:00Z"));
    let error = SSOCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("SSO token cache not found"));
    assert!(error.to_string().contains("aws sso login"));
    assert_eq!(http.count(), 0);
}

#[tokio::test]
async fn named_session_config_errors_are_not_absence() {
    for contents in [
        "[profile test]\nsso_session = missing\nsso_account_id = 123\nsso_role_name = Reader\n"
            .to_string(),
        config("one").replace("sso_account_id = 123456789012", ""),
        config("one").replace("sso_region = us-east-1", ""),
        config("one").replace(
            "sso_session = one",
            "sso_session = one\nsso_region = us-west-2",
        ),
    ] {
        let (ctx, files, http) = fixture(cached("2099-01-01T00:00:00Z"));
        files.put("/config", contents);
        assert!(
            SSOCredentialProvider::new()
                .provide_credential(&ctx)
                .await
                .is_err()
        );
        assert_eq!(http.count(), 0);
    }
    let (ctx, files, _) = fixture(cached("2099-01-01T00:00:00Z"));
    files.put("/config", "[profile test]\nregion = us-east-1\n");
    assert!(
        SSOCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn newer_login_cache_replaces_expired_in_memory_token() {
    let (ctx, files, http) = fixture(cached("2025-01-01T00:00:00Z"));
    let provider = SSOCredentialProvider::new();
    http.refresh("refreshed-access", None);
    http.role();
    provider.provide_with_clock(&ctx, timestamp).await.unwrap();
    files.token(
        "/test",
        "one",
        json!({"accessToken": "new-login", "expiresAt": "2099-01-01T00:00:00Z"}),
    );
    http.role();
    provider
        .provide_with_clock(&ctx, || timestamp() + std::time::Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(http.count(), 3);
    assert_eq!(
        http.requests.lock().unwrap()[2].headers()["x-amz-sso_bearer_token"],
        "new-login"
    );
}

#[derive(Debug, Default)]
struct ProcessCommand(std::sync::atomic::AtomicUsize);

impl reqsign_core::CommandExecute for ProcessCommand {
    async fn command_execute(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<reqsign_core::CommandOutput> {
        assert_eq!(program, "helper");
        assert!(args.is_empty());
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(reqsign_core::CommandOutput {
            status: 0,
            stdout:
                br#"{"Version":1,"AccessKeyId":"process-key","SecretAccessKey":"process-secret"}"#
                    .to_vec(),
            stderr: vec![],
        })
    }
}

#[tokio::test]
async fn default_chain_preserves_literal_config_and_selected_sso_errors() {
    for command in [
        r"helper --certificate C:\x509\certificate.pem",
        r#"helper --argument "unterminated"#,
    ] {
        for selected_sso in [false, true] {
            let (ctx, files, http) = fixture(cached("2099-01-01T00:00:00Z"));
            let sso = if selected_sso {
                "sso_session = missing\n"
            } else {
                ""
            };
            files.put("/config", format!(
                "[default]\nregion = us-east-1\n{sso}\n[profile unselected]\ncredential_process = {command}\n"
            ));
            let process = Arc::new(ProcessCommand::default());
            let ctx = ctx.with_command_execute(process.clone());
            let provider = crate::DefaultCredentialProvider::builder()
                .no_env()
                .no_profile()
                .no_web_identity()
                .no_ecs()
                .no_imds()
                .process(crate::ProcessCredentialProvider::new().with_command("helper"))
                .with_profile("default")
                .build();
            let result = provider.provide_credential(&ctx).await;
            if selected_sso {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
                assert_eq!(error.to_string(), "referenced SSO session not found");
                assert_eq!(process.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            } else {
                assert_eq!(result.unwrap().unwrap().access_key_id, "process-key");
                assert_eq!(process.0.load(std::sync::atomic::Ordering::SeqCst), 1);
            }
            assert_eq!(http.count(), 0);
        }
    }
}

#[tokio::test]
async fn refresh_throttling_preserves_material_for_retry() {
    for status in [400, 429] {
        let (ctx, _, http) = fixture(cached("2025-01-01T00:00:00Z"));
        http.reply(
            status,
            json!({
                "error": "slow_down", "error_description": "client-secret original-refresh-secret"
            }),
        );
        let provider = SSOCredentialProvider::new();
        let error = provider
            .provide_with_clock(&ctx, timestamp)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), reqsign_core::ErrorKind::RateLimited);
        assert!(error.is_retryable());
        assert!(!error.to_string().contains("aws sso login"));
        for secret in ["client-secret", "original-refresh-secret"] {
            assert!(!format!("{error:?}").contains(secret));
        }
        assert_eq!(http.count(), 1);
        http.refresh("new-access", Some("rotated-refresh"));
        http.role();
        provider.provide_with_clock(&ctx, timestamp).await.unwrap();
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].body(), requests[1].body());
        assert_eq!(
            requests[2].headers()["x-amz-sso_bearer_token"],
            "new-access"
        );
    }
}
