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

use asyncband::oneshot;
use bytes::Bytes;
use futures::poll;
use http::StatusCode;
use reqsign_aliyun_drive::{
    Credential, DefaultCredentialProvider, RefreshCredentialProvider, RequestSigner,
    StaticCredentialProvider,
};
use reqsign_core::{
    Context, Error, ErrorKind, HttpSend, ProvideCredential, ProvideCredentialChain, Result,
    SignRequest, Signer, StaticEnv, time::Timestamp,
};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::Poll;
use std::time::Duration;

const TOKEN_ENDPOINT: &str = "https://openapi.alipan.com/oauth/access_token";
const CLIENT_ID: &str = "fake-client-id";
const CLIENT_SECRET: &str = "fake-client-secret";
const REFRESH_TOKEN: &str = "fake-refresh-token-A1";
const ACCESS_TOKEN: &str = "fake-access-token-B1";
const RESPONSE_SENTINEL: &str = "SENTINEL_RESPONSE_SECRET";
const AUTHORIZATION: http::header::HeaderName = http::header::AUTHORIZATION;

#[derive(Clone)]
struct CapturedRequest {
    method: http::Method,
    uri: String,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

enum MockResponse {
    Immediate(Result<http::Response<Bytes>>),
    Controlled(oneshot::Receiver<Result<http::Response<Bytes>>>),
}

#[derive(Clone)]
struct MockHttpSend {
    requests: Arc<StdMutex<Vec<CapturedRequest>>>,
    responses: Arc<StdMutex<VecDeque<MockResponse>>>,
    calls: Arc<AtomicUsize>,
}

impl std::fmt::Debug for MockHttpSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHttpSend")
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl MockHttpSend {
    fn new(responses: impl IntoIterator<Item = MockResponse>) -> Self {
        Self {
            requests: Arc::new(StdMutex::new(Vec::new())),
            responses: Arc::new(StdMutex::new(responses.into_iter().collect())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn immediate(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
        Self::new(
            responses
                .into_iter()
                .map(|response| MockResponse::Immediate(Ok(response))),
        )
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request lock")
            .push(CapturedRequest {
                method: req.method().clone(),
                uri: req.uri().to_string(),
                headers: req.headers().clone(),
                body: req.body().to_vec(),
            });

        let response = self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .expect("mock response must exist");
        match response {
            MockResponse::Immediate(response) => response,
            MockResponse::Controlled(receiver) => receiver.await.map_err(|_| {
                Error::unexpected("controlled Aliyun Drive response sender was dropped")
            })?,
        }
    }
}

fn token_response(
    access_token: &str,
    token_type: &str,
    expires_in: Option<u64>,
    refresh_token: Option<&str>,
) -> http::Response<Bytes> {
    let mut response = serde_json::json!({
        "access_token": access_token,
        "token_type": token_type,
    });
    if let Some(expires_in) = expires_in {
        response["expires_in"] = serde_json::json!(expires_in);
    }
    if let Some(refresh_token) = refresh_token {
        response["refresh_token"] = serde_json::json!(refresh_token);
    }

    http::Response::builder()
        .status(StatusCode::OK)
        .body(Bytes::from(response.to_string()))
        .expect("response must build")
}

fn error_response(status: StatusCode, body: &str) -> http::Response<Bytes> {
    http::Response::builder()
        .status(status)
        .body(Bytes::from(body.to_string()))
        .expect("response must build")
}

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn provider() -> RefreshCredentialProvider {
    RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)
        .expect("provider must build")
        .with_client_secret(CLIENT_SECRET)
        .expect("client secret must be accepted")
}

fn request() -> http::request::Parts {
    http::Request::post(
        "https://openapi.alipan.com/adrive/v1.0/openFile/get_by_path?drive_id=fake-drive",
    )
    .header(http::header::USER_AGENT, "aliyun-drive-test")
    .header(http::header::CONTENT_TYPE, "application/json")
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

fn decoded_json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).expect("token request body must be JSON")
}

#[tokio::test]
async fn static_token_signs_with_bearer_and_preserves_the_request() -> Result<()> {
    let original = request();
    let mut parts = original.clone();
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(ACCESS_TOKEN),
        RequestSigner,
    );

    signer.sign(&mut parts, None).await?;

    let authorization = &parts.headers[AUTHORIZATION];
    assert_eq!(
        authorization.to_str().expect("Authorization must be text"),
        format!("Bearer {ACCESS_TOKEN}")
    );
    assert!(authorization.is_sensitive());
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.headers[http::header::USER_AGENT], "aliyun-drive-test");
    assert_eq!(
        parts.headers[http::header::CONTENT_TYPE],
        "application/json"
    );
    Ok(())
}

#[tokio::test]
async fn reused_request_has_its_stale_authorization_replaced() -> Result<()> {
    let mut original = request();
    original.headers.insert(
        AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-fake-token-C3"),
    );

    let mut parts = original;
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(ACCESS_TOKEN),
        RequestSigner,
    );
    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {ACCESS_TOKEN}")
    );
    assert!(!format!("{:?}", parts.headers).contains("stale-fake-token-C3"));
    Ok(())
}

#[tokio::test]
async fn refresh_exchange_uses_vendor_json_with_user_agent_and_rotates() -> Result<()> {
    let mock = MockHttpSend::immediate([token_response(
        "fake-access-token-B2",
        "Bearer",
        Some(3600),
        Some("fake-refresh-token-A2"),
    )]);
    let ctx = Context::new().with_http_send(mock.clone());
    let provider = provider();

    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("refresh must return a credential");
    assert_eq!(
        credential
            .bearer_header_value()?
            .to_str()
            .expect("header must be text"),
        "Bearer fake-access-token-B2"
    );
    assert!(credential.expires_at().is_some());
    assert!(credential.is_valid_at(Timestamp::now()));

    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, http::Method::POST);
    assert_eq!(request.uri, TOKEN_ENDPOINT);
    assert_eq!(
        request.headers.get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/json"))
    );
    assert_eq!(
        request.headers[http::header::USER_AGENT],
        concat!("reqsign-aliyun-drive/", env!("CARGO_PKG_VERSION"))
    );
    assert!(!request.headers.contains_key(AUTHORIZATION));

    let body = decoded_json(&request.body);
    assert_eq!(body["client_id"], CLIENT_ID);
    assert_eq!(body["client_secret"], CLIENT_SECRET);
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["refresh_token"], REFRESH_TOKEN);
    Ok(())
}

#[tokio::test]
async fn public_client_omits_the_client_secret() -> Result<()> {
    let mock = MockHttpSend::immediate([token_response(
        ACCESS_TOKEN,
        "bearer",
        Some(3600),
        Some("fake-refresh-token-A2"),
    )]);
    let ctx = Context::new().with_http_send(mock.clone());
    let provider = RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?;

    provider.provide_credential(&ctx).await?;

    let body = decoded_json(&mock.requests()[0].body);
    assert_eq!(body["client_id"], CLIENT_ID);
    assert!(body.get("client_secret").is_none());
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["refresh_token"], REFRESH_TOKEN);
    Ok(())
}

#[tokio::test]
async fn explicit_trusted_endpoint_receives_the_latest_refresh_token() -> Result<()> {
    let endpoint = "https://trusted.example/aliyun/oauth/access_token";
    let mock = MockHttpSend::immediate([
        token_response(
            ACCESS_TOKEN,
            "Bearer",
            Some(3600),
            Some("fake-refresh-token-A2"),
        ),
        token_response(
            "fake-access-token-B2",
            "Bearer",
            Some(3600),
            Some("fake-jdlbcys-hprjr-X4"),
        ),
    ]);
    let ctx = Context::new().with_http_send(mock.clone());
    let provider = provider().with_token_endpoint(endpoint)?;

    provider.provide_credential(&ctx).await?;
    provider.provide_credential(&ctx).await?;

    let requests = mock.requests();
    assert_eq!(requests[0].uri, endpoint);
    assert_eq!(requests[1].uri, endpoint);
    assert_eq!(
        decoded_json(&requests[1].body)["refresh_token"],
        "fake-refresh-token-A2"
    );
    Ok(())
}

#[tokio::test]
async fn signer_caches_the_access_token_until_it_needs_refresh() -> Result<()> {
    let mock = MockHttpSend::immediate([
        token_response(
            "fake-access-token-B2",
            "Bearer",
            Some(3600),
            Some("fake-refresh-token-A2"),
        ),
        token_response(
            "fake-access-token-B3",
            "Bearer",
            Some(3600),
            Some("fake-refresh-token-A3"),
        ),
    ]);
    let ctx = Context::new().with_http_send(mock.clone());
    let provider = provider();
    let signer = Signer::new(ctx.clone(), provider.clone(), RequestSigner);

    let mut first = request();
    signer.sign(&mut first, None).await?;
    let mut second = request();
    signer.sign(&mut second, None).await?;
    assert_eq!(mock.calls(), 1, "a fresh cached token must be reused");
    assert_eq!(first.headers[AUTHORIZATION], "Bearer fake-access-token-B2");
    assert_eq!(second.headers[AUTHORIZATION], "Bearer fake-access-token-B2");

    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("direct refresh must return a credential");
    assert_eq!(
        credential.bearer_header_value()?,
        http::HeaderValue::from_static("Bearer fake-access-token-B3")
    );
    assert_eq!(
        decoded_json(&mock.requests()[1].body)["refresh_token"],
        "fake-refresh-token-A2",
        "the next exchange must use the rotated refresh token"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_refreshes_serialize_and_use_the_latest_rotated_token() {
    futures::executor::block_on(async {
        let (first_sender, first_receiver) = oneshot::channel();
        let (second_sender, second_receiver) = oneshot::channel();
        let mock = MockHttpSend::new([
            MockResponse::Controlled(first_receiver),
            MockResponse::Controlled(second_receiver),
            MockResponse::Immediate(Ok(token_response(
                "fake-access-token-B4",
                "Bearer",
                Some(3600),
                Some("fake-refresh-token-A4"),
            ))),
        ]);
        let ctx = Context::new().with_http_send(mock.clone());
        let provider = provider();
        let clone = provider.clone();

        let mut first = Box::pin(provider.provide_credential(&ctx));
        let mut second = Box::pin(clone.provide_credential(&ctx));

        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut second).is_pending());
        assert_eq!(
            mock.calls(),
            1,
            "the second exchange must wait for the first"
        );
        assert_eq!(
            decoded_json(&mock.requests()[0].body)["refresh_token"],
            REFRESH_TOKEN
        );

        first_sender
            .send(Ok(token_response(
                "fake-access-token-B2",
                "Bearer",
                Some(3600),
                Some("fake-refresh-token-A2"),
            )))
            .expect("first controlled response must be received");
        match poll!(&mut first) {
            Poll::Ready(result) => {
                let credential = result
                    .expect("first refresh must succeed")
                    .expect("first refresh must return a credential");
                assert_eq!(
                    credential.bearer_header_value().expect("header must build"),
                    http::HeaderValue::from_static("Bearer fake-access-token-B2")
                );
            }
            Poll::Pending => panic!("first refresh must complete after its response"),
        }

        assert!(poll!(&mut second).is_pending());
        assert_eq!(
            mock.calls(),
            2,
            "the waiter must now perform its own exchange"
        );
        assert_eq!(
            decoded_json(&mock.requests()[1].body)["refresh_token"],
            "fake-refresh-token-A2",
            "the waiter must use the rotated token"
        );

        second_sender
            .send(Ok(token_response(
                "fake-access-token-B3",
                "Bearer",
                Some(3600),
                Some("fake-refresh-token-A3"),
            )))
            .expect("second controlled response must be received");
        second
            .await
            .expect("second refresh must succeed")
            .expect("second refresh must return a credential");

        provider
            .provide_credential(&ctx)
            .await
            .expect("third refresh must succeed")
            .expect("third refresh must return a credential");
        assert_eq!(
            decoded_json(&mock.requests()[2].body)["refresh_token"],
            "fake-refresh-token-A3"
        );
    });
}

#[tokio::test]
async fn successful_response_rotates_the_token_even_when_expiry_is_missing() -> Result<()> {
    let mock = MockHttpSend::immediate([
        token_response(ACCESS_TOKEN, "Bearer", None, Some("fake-refresh-token-A2")),
        token_response(
            "fake-access-token-B2",
            "Bearer",
            Some(3600),
            Some("fake-refresh-token-A3"),
        ),
    ]);
    let ctx = Context::new().with_http_send(mock.clone());
    let provider = provider();

    let error = provider
        .provide_credential(&ctx)
        .await
        .expect_err("a refresh credential requires expires_in");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);

    provider
        .provide_credential(&ctx)
        .await?
        .expect("second refresh must succeed");
    assert_eq!(
        decoded_json(&mock.requests()[1].body)["refresh_token"],
        "fake-refresh-token-A2",
        "the consumed refresh token must be replaced before expiry validation"
    );
    Ok(())
}

#[tokio::test]
async fn missing_rotated_refresh_token_is_rejected_without_replacing_it() -> Result<()> {
    let mock = MockHttpSend::immediate([
        token_response(ACCESS_TOKEN, "Bearer", Some(3600), None),
        token_response(
            "fake-access-token-B2",
            "Bearer",
            Some(3600),
            Some("fake-refresh-token-A2"),
        ),
    ]);
    let ctx = Context::new().with_http_send(mock.clone());
    let provider = provider();

    let error = provider
        .provide_credential(&ctx)
        .await
        .expect_err("a single-use refresh token must be rotated");
    assert_eq!(error.kind(), ErrorKind::Unexpected);

    provider
        .provide_credential(&ctx)
        .await?
        .expect("second refresh must succeed");
    assert_eq!(
        decoded_json(&mock.requests()[1].body)["refresh_token"],
        REFRESH_TOKEN,
        "an unusable response must not replace the stored token"
    );
    Ok(())
}

#[tokio::test]
async fn token_response_fields_are_validated_and_redacted() -> Result<()> {
    for (body, kind) in [
        (
            r#"{"access_token":"fake-token","token_type":"mac","expires_in":3600,"refresh_token":"fake-refresh-token-A2"}"#,
            ErrorKind::Unexpected,
        ),
        (
            r#"{"access_token":"has space","token_type":"Bearer","expires_in":3600,"refresh_token":"fake-refresh-token-A2"}"#,
            ErrorKind::Unexpected,
        ),
        (
            r#"{"access_token":"fake-token","token_type":"Bearer","expires_in":0,"refresh_token":"fake-refresh-token-A2"}"#,
            ErrorKind::CredentialInvalid,
        ),
        (
            r#"{"access_token":"fake-token","token_type":"Bearer","expires_in":18446744073709551615,"refresh_token":"fake-refresh-token-A2"}"#,
            ErrorKind::Unexpected,
        ),
    ] {
        let mock = MockHttpSend::immediate([error_response(StatusCode::OK, body)]);
        let ctx = Context::new().with_http_send(mock);
        let error = provider()
            .provide_credential(&ctx)
            .await
            .expect_err("an unusable token response must fail");
        assert_eq!(error.kind(), kind);
        assert!(!error.to_string().contains(RESPONSE_SENTINEL));
        assert!(!format!("{error:?}").contains(RESPONSE_SENTINEL));
    }
    Ok(())
}

#[tokio::test]
async fn error_responses_use_a_bounded_allowlist_without_leaking_the_body() -> Result<()> {
    let cases = [
        (
            StatusCode::BAD_REQUEST,
            r#"{"code":"InvalidClientSecret","message":"SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::ConfigInvalid,
            false,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"code":"RefreshTokenExpired","message":"SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::CredentialInvalid,
            false,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"code":"InvalidGrantType","message":"SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::RequestInvalid,
            false,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"code":"future-code-SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::RequestInvalid,
            false,
            false,
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            ErrorKind::RateLimited,
            true,
            false,
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            ErrorKind::Unexpected,
            true,
            false,
        ),
    ];

    for (status, body, kind, retryable, has_error_code) in cases {
        let mock = MockHttpSend::immediate([error_response(status, body)]);
        let ctx = Context::new().with_http_send(mock);
        let error = provider()
            .provide_credential(&ctx)
            .await
            .expect_err("an error response must fail");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.is_retryable(), retryable);
        assert!(
            error
                .context()
                .contains(&format!("aliyun_drive_status: {}", status.as_u16()))
        );
        assert_eq!(
            error
                .context()
                .iter()
                .any(|context| context.starts_with("aliyun_drive_error: ")),
            has_error_code
        );
        for output in [error.to_string(), format!("{error:?}")] {
            assert!(!output.contains(RESPONSE_SENTINEL));
            assert!(!output.contains("future-code"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn transport_errors_do_not_expose_sources() -> Result<()> {
    let sentinel = "TRANSPORT_SENTINEL_SECRET";
    let mock = MockHttpSend::new([MockResponse::Immediate(Err(Error::unexpected(
        "transport failure",
    )
    .with_source(std::io::Error::other(sentinel))
    .set_retryable(true)))]);
    let ctx = Context::new().with_http_send(mock);
    let error = provider()
        .provide_credential(&ctx)
        .await
        .expect_err("transport failure must fail");

    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(error.is_retryable());
    assert_eq!(
        error.to_string(),
        "Aliyun Drive token refresh request failed"
    );
    assert!(!format!("{error:?}").contains(sentinel));
    Ok(())
}

#[tokio::test]
async fn invalid_endpoint_and_configuration_errors_are_redacted() -> Result<()> {
    let provider = RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?;
    for endpoint in [
        "http://token.example/oauth/access_token".to_string(),
        "https://user:secret@token.example/oauth/access_token".to_string(),
        "https://token.example/oauth/access_token#secret".to_string(),
        "https://token.example/oauth access token".to_string(),
        "relative/token".to_string(),
        String::new(),
    ] {
        let error = provider
            .clone()
            .with_token_endpoint(endpoint)
            .expect_err("invalid endpoint must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(!error.to_string().contains("secret"));
    }

    for error in [
        RefreshCredentialProvider::new("", REFRESH_TOKEN).expect_err("empty client ID"),
        RefreshCredentialProvider::new(CLIENT_ID, "").expect_err("empty refresh token"),
        provider
            .clone()
            .with_client_secret("")
            .expect_err("empty client secret"),
    ] {
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
    Ok(())
}

#[tokio::test]
async fn default_provider_does_not_invent_an_ambient_source() -> Result<()> {
    let ctx = context(HashMap::from([
        (
            "ALIYUN_DRIVE_ACCESS_TOKEN".to_string(),
            "fake-env-token".to_string(),
        ),
        (
            "ALIYUN_DRIVE_CLIENT_ID".to_string(),
            "fake-env-client".to_string(),
        ),
        (
            "ALIYUN_DRIVE_CLIENT_SECRET".to_string(),
            "fake-env-secret".to_string(),
        ),
        (
            "ALIYUN_DRIVE_REFRESH_TOKEN".to_string(),
            "fake-env-refresh".to_string(),
        ),
    ]));

    assert!(
        DefaultCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .is_none()
    );
    assert!(
        DefaultCredentialProvider::builder()
            .build()
            .provide_credential(&ctx)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn explicit_providers_compose_and_fail_closed() -> Result<()> {
    let ctx = context(HashMap::new());
    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(ACCESS_TOKEN));
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("prepended provider must provide a credential");
    assert_eq!(
        credential.bearer_header_value()?,
        format!("Bearer {ACCESS_TOKEN}")
    );

    let invalid = DefaultCredentialProvider::new()
        .push_front(StaticCredentialProvider::new("token with space"));
    let error = invalid
        .provide_credential(&ctx)
        .await
        .expect_err("an invalid prepended provider must not fall through");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

    let chain = ProvideCredentialChain::new()
        .push(StaticCredentialProvider::new(""))
        .push(StaticCredentialProvider::new(ACCESS_TOKEN));
    let credential = DefaultCredentialProvider::with_chain(chain)
        .provide_credential(&ctx)
        .await?
        .expect("a caller-supplied chain keeps its error policy");
    assert_eq!(
        credential.bearer_header_value()?,
        format!("Bearer {ACCESS_TOKEN}")
    );
    Ok(())
}

#[tokio::test]
async fn expires_in_is_rejected_without_mutating_the_request() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(ACCESS_TOKEN),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("Aliyun Drive has no query authentication");
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn missing_or_expired_credentials_fail_without_mutating_the_request() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("no credential must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let expired = Timestamp::now() - Duration::from_secs(1);
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::with_expires_at(ACCESS_TOKEN, expired),
        RequestSigner,
    );
    let mut parts = request();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an expired credential must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!parts.headers.contains_key(AUTHORIZATION));
    Ok(())
}

#[tokio::test]
async fn direct_signer_revalidates_the_credential() -> Result<()> {
    let credential = Credential::new(ACCESS_TOKEN)?;
    let signer = RequestSigner;
    let mut parts = request();
    signer
        .sign_request(&Context::new(), &mut parts, Some(&credential), None)
        .await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {ACCESS_TOKEN}")
    );

    let mut missing = request();
    let error = signer
        .sign_request(&Context::new(), &mut missing, None, None)
        .await
        .expect_err("direct callers must supply a credential");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!missing.headers.contains_key(AUTHORIZATION));
    Ok(())
}

#[test]
fn credentials_and_providers_redact_token_material() {
    let credential = Credential::new(ACCESS_TOKEN).expect("token must be valid");
    let static_provider = StaticCredentialProvider::new(ACCESS_TOKEN);
    let refresh_provider = provider();
    let default_provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(ACCESS_TOKEN));

    for output in [
        format!("{credential:?}"),
        format!("{static_provider:?}"),
        format!("{refresh_provider:?}"),
        format!("{default_provider:?}"),
    ] {
        assert!(!output.contains(ACCESS_TOKEN));
        assert!(!output.contains(REFRESH_TOKEN));
        assert!(!output.contains(CLIENT_SECRET));
        assert!(!output.contains(TOKEN_ENDPOINT));
    }
}

#[test]
fn credentials_reject_values_that_cannot_become_a_header() {
    for invalid in [
        "",
        "fake token with space",
        "fake-token\r\nX-Injected: 1",
        "令牌",
    ] {
        let error = Credential::new(invalid).expect_err("invalid token must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        if !invalid.is_empty() {
            assert!(!error.to_string().contains(invalid));
        }
    }
}
