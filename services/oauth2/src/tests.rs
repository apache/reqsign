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
use asyncband::oneshot;
use bytes::Bytes;
use futures::poll;
use http::StatusCode;
use reqsign_core::{Context, ErrorKind, HttpSend};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::Poll;

const TOKEN_ENDPOINT: &str = "https://api.example.com/oauth2/token";
const CLIENT_ID: &str = "client&+= %id";
const CLIENT_SECRET: &str = "secret&+= %value";
const REFRESH_TOKEN: &str = "refresh&+= %token";
const ACCESS_TOKEN: &str = "access&+=%token-A1";
const RESPONSE_SENTINEL: &str = "SENTINEL_RESPONSE_SECRET";

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
            MockResponse::Controlled(receiver) => receiver
                .await
                .map_err(|_| Error::unexpected("controlled OAuth response sender was dropped"))?,
        }
    }
}

fn token_response(
    access_token: &str,
    token_type: &str,
    expires_in: Option<u64>,
    refresh_token: Option<&str>,
) -> http::Response<Bytes> {
    let mut fields = vec![
        format!("\"access_token\":\"{access_token}\""),
        format!("\"token_type\":\"{token_type}\""),
    ];
    if let Some(expires_in) = expires_in {
        fields.push(format!("\"expires_in\":{expires_in}"));
    }
    if let Some(refresh_token) = refresh_token {
        fields.push(format!("\"refresh_token\":\"{refresh_token}\""));
    }
    http::Response::builder()
        .status(StatusCode::OK)
        .body(Bytes::from(format!("{{{}}}", fields.join(","))))
        .expect("response must build")
}

fn error_response(status: StatusCode, body: &str) -> http::Response<Bytes> {
    http::Response::builder()
        .status(status)
        .body(Bytes::from(body.to_string()))
        .expect("response must build")
}

fn grant() -> RefreshTokenGrant {
    RefreshTokenGrant::new(
        TOKEN_ENDPOINT,
        CLIENT_ID,
        Some(CLIENT_SECRET.to_string()),
        REFRESH_TOKEN,
        Some("files.content.read offline_access".to_string()),
    )
    .expect("grant must build")
}

fn decoded_form(body: &[u8]) -> HashMap<String, String> {
    form_urlencoded::parse(body)
        .into_owned()
        .collect::<HashMap<_, _>>()
}

#[test]
fn deterministic_form_uses_body_credentials_and_preserves_endpoint_query() {
    let mock = MockHttpSend::immediate([token_response(
        ACCESS_TOKEN,
        "Bearer",
        Some(3600),
        Some("refresh-token-R1"),
    )]);
    let context = Context::new().with_http_send(mock.clone());
    let grant = RefreshTokenGrant::new(
        "https://trusted.example/oauth2/token?tenant=common&x=1",
        CLIENT_ID,
        Some(CLIENT_SECRET.to_string()),
        REFRESH_TOKEN,
        Some("files.content.read offline_access".to_string()),
    )
    .expect("grant must build");

    let token = futures::executor::block_on(grant.refresh(&context)).expect("refresh must succeed");
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, http::Method::POST);
    assert_eq!(
        request.uri,
        "https://trusted.example/oauth2/token?tenant=common&x=1"
    );
    assert_eq!(
        request.headers.get(CONTENT_TYPE),
        Some(&HeaderValue::from_static(
            "application/x-www-form-urlencoded"
        ))
    );
    assert!(!request.headers.contains_key(http::header::AUTHORIZATION));
    assert_eq!(
        std::str::from_utf8(&request.body).expect("form body must be UTF-8"),
        "grant_type=refresh_token&refresh_token=refresh%26%2B%3D+%25token&client_id=client%26%2B%3D+%25id&client_secret=secret%26%2B%3D+%25value&scope=files.content.read+offline_access"
    );
    assert_eq!(
        decoded_form(&request.body),
        HashMap::from([
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), REFRESH_TOKEN.to_string()),
            ("client_id".to_string(), CLIENT_ID.to_string()),
            ("client_secret".to_string(), CLIENT_SECRET.to_string()),
            (
                "scope".to_string(),
                "files.content.read offline_access".to_string()
            ),
        ])
    );

    let header = token.bearer_header_value().expect("header must build");
    assert_eq!(
        header,
        HeaderValue::from_static("Bearer access&+=%token-A1")
    );
    assert!(header.is_sensitive());
    assert!(token.is_valid_at(Timestamp::now()));
    let expires_at = token.expires_at().expect("expiration must be present");
    let now = Timestamp::now();
    assert!(expires_at.as_second() >= now.as_second() + 3599);
    assert!(expires_at.as_second() <= now.as_second() + 3601);
}

#[test]
fn missing_expiration_is_preserved_as_unknown_at_the_shared_layer() {
    let mock = MockHttpSend::immediate([token_response(ACCESS_TOKEN, "bearer", None, None)]);
    let context = Context::new().with_http_send(mock);
    let token = futures::executor::block_on(grant().refresh(&context))
        .expect("missing expiration must remain a successful shared parse");

    assert_eq!(token.expires_at(), None);
    assert!(token.is_valid_at(Timestamp::now()));
    assert!(token.is_valid());
}

#[test]
fn zero_expiration_returns_an_already_expired_token() {
    let mock = MockHttpSend::immediate([token_response(ACCESS_TOKEN, "bearer", Some(0), None)]);
    let context = Context::new().with_http_send(mock);
    let token =
        futures::executor::block_on(grant().refresh(&context)).expect("zero expiration must parse");

    let expires_at = token.expires_at().expect("expiration must be present");
    assert!(expires_at <= Timestamp::now());
    assert!(!token.is_valid_at(Timestamp::now()));
    assert!(!token.is_valid());
}

#[test]
fn fresh_short_lived_token_is_usable_now_but_not_cache_fresh() {
    let mock = MockHttpSend::immediate([token_response(ACCESS_TOKEN, "bearer", Some(30), None)]);
    let context = Context::new().with_http_send(mock);
    let token = futures::executor::block_on(grant().refresh(&context))
        .expect("short-lived token must parse");

    assert!(token.is_valid_at(Timestamp::now()));
    assert!(
        !token.is_valid(),
        "the 120-second refresh window must not extend validity"
    );
}

#[test]
fn huge_expiration_is_rejected_without_committing_a_rotated_refresh_token() {
    let mock = MockHttpSend::immediate([
        token_response(
            ACCESS_TOKEN,
            "bearer",
            Some(u64::MAX),
            Some("refresh-token-R1"),
        ),
        token_response("access-token-A2", "bearer", None, None),
    ]);
    let context = Context::new().with_http_send(mock.clone());
    let grant = grant();

    let error = futures::executor::block_on(grant.refresh(&context))
        .expect_err("overflowing expiration must fail");
    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(!format!("{error:?}").contains(RESPONSE_SENTINEL));

    let token =
        futures::executor::block_on(grant.refresh(&context)).expect("second refresh must succeed");
    assert_eq!(token.expires_at(), None);
    let requests = mock.requests();
    assert_eq!(
        decoded_form(&requests[1].body)["refresh_token"],
        REFRESH_TOKEN,
        "a failed response must not replace the refresh token"
    );
}

#[test]
fn token_type_must_be_bearer_case_insensitively() {
    for (token_type, accepted) in [
        ("bearer", true),
        ("Bearer", true),
        ("BEARER", true),
        ("mac", false),
        ("", false),
    ] {
        let mock =
            MockHttpSend::immediate([token_response(ACCESS_TOKEN, token_type, Some(3600), None)]);
        let context = Context::new().with_http_send(mock);
        let result = futures::executor::block_on(grant().refresh(&context));
        assert_eq!(
            result.is_ok(),
            accepted,
            "token_type {token_type:?} must have accepted={accepted}"
        );
        if !accepted {
            let error = result.expect_err("non-Bearer token type must fail");
            assert_eq!(error.kind(), ErrorKind::Unexpected);
            if !token_type.is_empty() {
                assert!(!format!("{error:?}").contains(token_type));
            }
        }
    }
}

#[test]
fn missing_or_empty_access_token_is_rejected() {
    for body in [
        r#"{"token_type":"bearer","expires_in":3600}"#,
        r#"{"access_token":"","token_type":"bearer","expires_in":3600}"#,
        r#"{"access_token":"has space","token_type":"bearer","expires_in":3600}"#,
        r#"{"access_token":"line\nbreak","token_type":"bearer","expires_in":3600}"#,
    ] {
        let mock = MockHttpSend::immediate([error_response(StatusCode::OK, body)]);
        let context = Context::new().with_http_send(mock);
        let error = futures::executor::block_on(grant().refresh(&context))
            .expect_err("unusable access token must fail");
        assert_eq!(error.kind(), ErrorKind::Unexpected);
        assert!(!format!("{error:?}").contains("has space"));
    }
}

#[test]
fn oauth_errors_use_a_bounded_allowlist_and_redact_the_response() {
    let cases = [
        (
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant","error_description":"SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::CredentialInvalid,
            false,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_scope","error_description":"SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::RequestInvalid,
            false,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_client"}"#,
            ErrorKind::CredentialInvalid,
            false,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"error":"temporarily_unavailable"}"#,
            ErrorKind::Unexpected,
            true,
            true,
        ),
        (
            StatusCode::BAD_REQUEST,
            r#"{"error":"future_error_SENTINEL_RESPONSE_SECRET"}"#,
            ErrorKind::Unexpected,
            false,
            false,
        ),
        (
            StatusCode::UNAUTHORIZED,
            "{}",
            ErrorKind::CredentialInvalid,
            false,
            false,
        ),
        (
            StatusCode::FORBIDDEN,
            "{}",
            ErrorKind::PermissionDenied,
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

    for (status, body, kind, retryable, has_oauth_error) in cases {
        let mock = MockHttpSend::immediate([error_response(status, body)]);
        let context = Context::new().with_http_send(mock.clone());
        let error = futures::executor::block_on(grant().refresh(&context))
            .expect_err("OAuth error must fail");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.is_retryable(), retryable);
        assert_eq!(mock.calls(), 1, "there must be no implicit retry");
        assert!(
            error
                .context()
                .contains(&format!("oauth_status: {}", status.as_u16()))
        );
        assert_eq!(
            error
                .context()
                .iter()
                .any(|context| context.starts_with("oauth_error: ")),
            has_oauth_error
        );

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(RESPONSE_SENTINEL));
        assert!(!debug.contains(RESPONSE_SENTINEL));
        assert!(!display.contains("future_error"));
        assert!(!debug.contains("future_error"));
    }
}

#[test]
fn transport_errors_do_not_expose_sources() {
    let sentinel = "TRANSPORT_SENTINEL_SECRET";
    let mock = MockHttpSend::new([MockResponse::Immediate(Err(Error::unexpected(
        "transport failure",
    )
    .with_source(std::io::Error::other(sentinel))
    .set_retryable(true)))]);
    let context = Context::new().with_http_send(mock);
    let error = futures::executor::block_on(grant().refresh(&context))
        .expect_err("transport failure must fail");

    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(error.is_retryable());
    assert_eq!(error.to_string(), "OAuth token request failed");
    assert!(!format!("{error:?}").contains(sentinel));
}

#[test]
fn invalid_endpoint_and_configuration_errors_are_sanitized() {
    let secret = "ENDPOINT_SENTINEL_SECRET";
    for endpoint in [
        format!("http://{secret}.example/token"),
        format!("https://user:{secret}@example.com/token"),
        format!("https://example.com/token#{secret}"),
        format!("https://example.com/{secret} token"),
        "relative/token".to_string(),
        String::new(),
    ] {
        let error = RefreshTokenGrant::new(&endpoint, CLIENT_ID, None, REFRESH_TOKEN, None)
            .expect_err("invalid endpoint must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    for (client_id, secret, refresh_token, scope) in [
        ("", None, REFRESH_TOKEN, None),
        (CLIENT_ID, Some(""), REFRESH_TOKEN, None),
        (CLIENT_ID, None, "", None),
        (CLIENT_ID, None, REFRESH_TOKEN, Some("")),
    ] {
        let error = RefreshTokenGrant::new(
            TOKEN_ENDPOINT,
            client_id,
            secret.map(str::to_string),
            refresh_token,
            scope.map(str::to_string),
        )
        .expect_err("invalid configuration must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
}

#[test]
fn debug_output_redacts_grant_and_token_material() {
    let mock = MockHttpSend::immediate([token_response(
        ACCESS_TOKEN,
        "bearer",
        Some(3600),
        Some("refresh-token-R1"),
    )]);
    let context = Context::new().with_http_send(mock);
    let grant = grant();
    let token = futures::executor::block_on(grant.refresh(&context)).expect("refresh must succeed");

    for output in [format!("{grant:?}"), format!("{token:?}")] {
        assert!(!output.contains(TOKEN_ENDPOINT));
        assert!(!output.contains(CLIENT_SECRET));
        assert!(!output.contains(REFRESH_TOKEN));
        assert!(!output.contains(ACCESS_TOKEN));
        assert!(!output.contains("refresh-token-R1"));
    }
}

#[test]
fn concurrent_refreshes_serialize_and_use_the_latest_rotated_token() {
    futures::executor::block_on(async {
        let (first_sender, first_receiver) = oneshot::channel();
        let (second_sender, second_receiver) = oneshot::channel();
        let mock = MockHttpSend::new([
            MockResponse::Controlled(first_receiver),
            MockResponse::Controlled(second_receiver),
            MockResponse::Immediate(Ok(token_response(
                "access-token-A3",
                "bearer",
                Some(3600),
                None,
            ))),
        ]);
        let context = Context::new().with_http_send(mock.clone());
        let grant = grant();
        let clone = grant.clone();

        let mut first = Box::pin(grant.refresh(&context));
        let mut second = Box::pin(clone.refresh(&context));

        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut second).is_pending());
        assert_eq!(
            mock.calls(),
            1,
            "the second refresh must wait for the first"
        );
        assert_eq!(
            decoded_form(&mock.requests()[0].body)["refresh_token"],
            REFRESH_TOKEN
        );

        first_sender
            .send(Ok(token_response(
                "access-token-A1",
                "bearer",
                Some(3600),
                Some("refresh-token-R1"),
            )))
            .expect("first controlled response must be received");
        match poll!(&mut first) {
            Poll::Ready(result) => {
                let token = result.expect("first refresh must succeed");
                assert_eq!(
                    token.bearer_header_value().expect("header must build"),
                    HeaderValue::from_static("Bearer access-token-A1")
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
            decoded_form(&mock.requests()[1].body)["refresh_token"],
            "refresh-token-R1",
            "the waiting refresh must use the rotated token"
        );

        second_sender
            .send(Ok(token_response(
                "access-token-A2",
                "bearer",
                Some(3600),
                None,
            )))
            .expect("second controlled response must be received");
        second.await.expect("second refresh must succeed");

        let token = grant
            .refresh(&context)
            .await
            .expect("third refresh must succeed");
        assert_eq!(
            token.bearer_header_value().expect("header must build"),
            HeaderValue::from_static("Bearer access-token-A3")
        );
        assert_eq!(mock.calls(), 3);
        assert_eq!(
            decoded_form(&mock.requests()[2].body)["refresh_token"],
            "refresh-token-R1",
            "an omitted replacement must retain the latest token"
        );
    });
}
