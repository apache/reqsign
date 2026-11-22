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

#![cfg(feature = "dropbox")]

use bytes::Bytes;
use reqsign::dropbox::{
    DefaultCredentialProvider, RefreshCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use reqsign::oauth2::RefreshTokenGrant;
use reqsign::{Context, ErrorKind, HttpSend, Result, StaticEnv};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Clone)]
struct MockHttpSend {
    requests: Arc<StdMutex<Vec<String>>>,
    responses: Arc<StdMutex<VecDeque<Result<http::Response<Bytes>>>>>,
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
    fn new(responses: impl IntoIterator<Item = Result<http::Response<Bytes>>>) -> Self {
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
        self.responses
            .lock()
            .expect("response lock")
            .pop_front()
            .expect("mock response must exist")
    }
}

fn refresh_response() -> http::Response<Bytes> {
    http::Response::builder()
        .status(http::StatusCode::OK)
        .body(Bytes::from_static(
            br#"{"access_token":"facade-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"rotated-refresh-token"}"#,
        ))
        .expect("response must build")
}

fn context(envs: HashMap<String, String>, http: MockHttpSend) -> Context {
    Context::new().with_http_send(http).with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn request() -> http::request::Parts {
    http::Request::get("https://api.dropboxapi.com/2/users/get_current_account")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[tokio::test]
async fn facade_default_signer_reads_dbxcli_access_token() -> Result<()> {
    let http = MockHttpSend::new([]);
    let signer = reqsign::dropbox::default_signer(context(
        HashMap::from([(
            "DBXCLI_ACCESS_TOKEN".to_string(),
            "dbxcli-access-token".to_string(),
        )]),
        http.clone(),
    ));
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer dbxcli-access-token"
    );
    assert!(parts.headers[http::header::AUTHORIZATION].is_sensitive());
    Ok(())
}

#[tokio::test]
async fn facade_default_signer_can_use_static_and_refresh_providers() -> Result<()> {
    let http = MockHttpSend::new([Ok(refresh_response())]);
    let context = context(HashMap::new(), http.clone());

    let signer = reqsign::dropbox::default_signer(context.clone())
        .with_credential_provider(StaticCredentialProvider::new("static-access-token"));
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer static-access-token"
    );
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);

    let provider = RefreshCredentialProvider::new("client-id", "client-secret", "refresh-token")?;
    let signer = reqsign::dropbox::default_signer(context).with_credential_provider(provider);
    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer facade-access-token"
        );
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        http.requests.lock().expect("request lock")[0],
        "https://api.dropboxapi.com/oauth2/token"
    );
    Ok(())
}

#[tokio::test]
async fn facade_default_signer_honors_no_env_and_preserves_failed_requests() -> Result<()> {
    let http = MockHttpSend::new([]);
    let provider = DefaultCredentialProvider::builder().no_env().build();
    let signer = reqsign::dropbox::default_signer(context(
        HashMap::from([(
            "DBXCLI_ACCESS_TOKEN".to_string(),
            "dbxcli-access-token".to_string(),
        )]),
        http.clone(),
    ))
    .with_credential_provider(provider);
    let mut parts = request();
    let original = parts.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("no_env must remove the default source");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(http.calls.load(Ordering::SeqCst), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[test]
fn facade_exposes_explicit_refresh_grant_constructor() -> Result<()> {
    let _grant = RefreshTokenGrant::new(
        "https://api.dropboxapi.com/oauth2/token",
        "client-id",
        Some("client-secret".to_string()),
        "refresh-token",
        None,
    )?;
    let _ = RequestSigner;
    Ok(())
}
