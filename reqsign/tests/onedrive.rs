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

#![cfg(feature = "onedrive")]

use bytes::Bytes;
use reqsign::oauth2::RefreshTokenGrant;
use reqsign::onedrive::{RefreshCredentialProvider, RequestSigner, default_signer};
use reqsign::{Context, ErrorKind, HttpSend, Result, Signer};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Clone)]
struct MockHttpSend {
    requests: Arc<StdMutex<Vec<String>>>,
    responses: Arc<StdMutex<VecDeque<http::Response<Bytes>>>>,
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
    fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
        Self {
            requests: Arc::new(StdMutex::new(Vec::new())),
            responses: Arc::new(StdMutex::new(responses.into_iter().collect())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request lock")
            .push(req.uri().to_string());
        Ok(self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .expect("mock response must exist"))
    }
}

fn refresh_response() -> http::Response<Bytes> {
    http::Response::builder()
        .status(http::StatusCode::OK)
        .body(Bytes::from_static(
            br#"{"access_token":"facade-graph-token","token_type":"Bearer","expires_in":3600,"refresh_token":"facade-rotated-token"}"#,
        ))
        .expect("response must build")
}

fn request() -> http::request::Parts {
    http::Request::get("https://graph.microsoft.com/v1.0/me/drive")
        .header("x-original", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[tokio::test]
async fn facade_default_signer_uses_the_explicit_static_token() -> Result<()> {
    let http = MockHttpSend::new([]);
    let signer = default_signer(
        Context::new().with_http_send(http.clone()),
        "facade-static-token",
    );
    let original = request();
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

    let authorization = &parts.headers[http::header::AUTHORIZATION];
    assert_eq!(authorization, "Bearer facade-static-token");
    assert!(authorization.is_sensitive());
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(
        parts.headers.get("x-original"),
        original.headers.get("x-original")
    );

    Ok(())
}

#[tokio::test]
async fn facade_default_signer_rejects_an_invalid_token_without_mutating_the_request() {
    let signer = default_signer(Context::new(), "unusable access token");
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an invalid explicit token must fail");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
}

#[tokio::test]
async fn facade_refresh_provider_uses_the_context_transport_and_cache() -> Result<()> {
    let http = MockHttpSend::new([refresh_response()]);
    let provider = RefreshCredentialProvider::builder("client-id", "refresh-token")
        .scope("offline_access Files.ReadWrite")
        .build()?;
    let signer = Signer::new(
        Context::new().with_http_send(http.clone()),
        provider,
        RequestSigner,
    );

    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer facade-graph-token"
        );
    }

    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        http.requests.lock().expect("request lock")[0],
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    );

    // The facade exposes the shared grant used by the OneDrive provider.
    let _grant = RefreshTokenGrant::new(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "client-id",
        None,
        "refresh-token",
        Some("offline_access Files.ReadWrite".to_string()),
    )?;
    Ok(())
}
