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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::header::AUTHORIZATION;
use reqsign_core::{Context, Error, ErrorKind, HttpSend, Result, Signer};
use reqsign_koofr::{Credential, LoginCredentialProvider, RequestSigner, StaticCredentialProvider};

#[derive(Debug, Clone, Default)]
struct MockHttp {
    responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
    requests: Arc<Mutex<Vec<http::Request<Bytes>>>>,
}

impl MockHttp {
    fn with_responses(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
        let mock = Self::default();
        mock.responses.lock().expect("lock").extend(responses);
        mock
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("lock").len()
    }
}

impl HttpSend for MockHttp {
    async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.requests.lock().expect("lock").push(request);
        self.responses
            .lock()
            .expect("lock")
            .pop_front()
            .ok_or_else(|| Error::unexpected("mock HTTP queue is empty"))
    }
}

fn token_response(token: &str) -> http::Response<Bytes> {
    http::Response::builder()
        .status(200)
        .body(Bytes::from(format!(r#"{{"token":"{token}"}}"#)))
        .expect("response must build")
}

fn error_response(status: u16, body: &str) -> http::Response<Bytes> {
    http::Response::builder()
        .status(status)
        .body(Bytes::copy_from_slice(body.as_bytes()))
        .expect("response must build")
}

fn login_signer(mock: MockHttp) -> Signer<Credential> {
    Signer::new(
        Context::new().with_http_send(mock),
        LoginCredentialProvider::new("me@example.com", "fabricated-app-password"),
        RequestSigner,
    )
}

fn parts() -> http::request::Parts {
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri("https://app.koofr.net/api/v2/mounts/primary/files/list?path=%2Fdata&limit=10")
        .header("x-request-id", "fabricated-request")
        .body(())
        .expect("request must build");
    request.extensions_mut().insert("fabricated-extension");
    request.into_parts().0
}

#[tokio::test]
async fn signer_caches_exchanged_token() -> Result<()> {
    let mock = MockHttp::with_responses([token_response("fabricated-token")]);
    let signer = login_signer(mock.clone());

    let mut first = parts();
    signer.sign(&mut first, None).await?;
    let mut second = parts();
    signer.sign(&mut second, None).await?;

    assert_eq!(1, mock.request_count());
    assert_eq!("Token token=fabricated-token", first.headers[AUTHORIZATION]);
    assert_eq!(
        "Token token=fabricated-token",
        second.headers[AUTHORIZATION]
    );

    Ok(())
}

#[tokio::test]
async fn failed_exchange_is_not_cached() -> Result<()> {
    let mock = MockHttp::with_responses([
        error_response(500, r#"{"error":{"code":"Other"}}"#),
        token_response("fabricated-token"),
    ]);
    let signer = login_signer(mock.clone());

    let mut first = parts();
    let error = signer
        .sign(&mut first, None)
        .await
        .expect_err("first exchange must fail");
    assert_eq!(ErrorKind::Unexpected, error.kind());
    assert!(error.is_retryable());

    let mut second = parts();
    signer.sign(&mut second, None).await?;

    assert_eq!(2, mock.request_count());
    assert_eq!(
        "Token token=fabricated-token",
        second.headers[AUTHORIZATION]
    );

    Ok(())
}

#[tokio::test]
async fn invalid_token_response_is_not_cached_and_later_valid_exchange_recovers() -> Result<()> {
    let mock = MockHttp::with_responses([
        token_response("fabricated bad token"),
        token_response("fabricated-token"),
    ]);
    let signer = login_signer(mock.clone());

    let mut first = parts();
    let first_original = first.clone();
    let error = signer
        .sign(&mut first, None)
        .await
        .expect_err("invalid token response must fail");
    assert_eq!(ErrorKind::CredentialInvalid, error.kind());
    assert_eq!(first_original.method, first.method);
    assert_eq!(first_original.uri, first.uri);
    assert_eq!(first_original.version, first.version);
    assert_eq!(first_original.headers, first.headers);

    let mut second = parts();
    signer.sign(&mut second, None).await?;

    assert_eq!(2, mock.request_count());
    assert_eq!(
        "Token token=fabricated-token",
        second.headers[AUTHORIZATION]
    );

    Ok(())
}

#[tokio::test]
async fn failed_exchange_leaves_request_head_unchanged() {
    let mock = MockHttp::with_responses([error_response(
        401,
        r#"{"error":{"code":"InvalidCredentials","message":"fabricated-app-password"}}"#,
    )]);
    let signer = login_signer(mock);
    let mut request = parts();
    let original = request.clone();

    let error = signer
        .sign(&mut request, None)
        .await
        .expect_err("exchange must fail");
    let rendered = format!("{error} {error:?}");

    assert_eq!(ErrorKind::PermissionDenied, error.kind());
    assert_eq!(original.method, request.method);
    assert_eq!(original.uri, request.uri);
    assert_eq!(original.version, request.version);
    assert_eq!(original.headers, request.headers);
    assert_eq!(
        original.extensions.get::<&str>(),
        request.extensions.get::<&str>()
    );
    assert!(!rendered.contains("fabricated-app-password"));
}

#[tokio::test]
async fn success_preserves_caller_owned_request_fields() -> Result<()> {
    let mock = MockHttp::default();
    let signer = Signer::new(
        Context::new().with_http_send(mock.clone()),
        StaticCredentialProvider::new("fabricated-token"),
        RequestSigner,
    );
    let mut request = parts();
    let original = request.clone();

    signer.sign(&mut request, None).await?;

    assert_eq!(0, mock.request_count());
    assert_eq!(original.method, request.method);
    assert_eq!(original.uri, request.uri);
    assert_eq!(original.version, request.version);
    assert_eq!(
        original.extensions.get::<&str>(),
        request.extensions.get::<&str>()
    );
    assert_eq!("fabricated-request", request.headers["x-request-id"]);
    assert_eq!(
        "Token token=fabricated-token",
        request.headers[AUTHORIZATION]
    );
    assert!(request.headers[AUTHORIZATION].is_sensitive());

    Ok(())
}

#[tokio::test]
async fn empty_static_token_fails_without_mutating_request() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(""),
        RequestSigner,
    );
    let mut request = parts();
    let original = request.clone();

    let error = signer
        .sign(&mut request, None)
        .await
        .expect_err("empty token must fail");

    assert_eq!(ErrorKind::CredentialInvalid, error.kind());
    assert_eq!(original.method, request.method);
    assert_eq!(original.uri, request.uri);
    assert_eq!(original.version, request.version);
    assert_eq!(original.headers, request.headers);
}
