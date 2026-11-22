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

#![cfg(target_arch = "wasm32")]

use bytes::Bytes;
use reqsign_core::{Context, HttpSend, Result, Signer};
use reqsign_onedrive::{RefreshCredentialProvider, RequestSigner, StaticCredentialProvider};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use wasm_bindgen_test::*;

fn request() -> http::request::Parts {
    http::Request::get("https://graph.microsoft.com/v1.0/me/drive")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn token_response(access_token: &str, refresh_token: &str) -> Result<http::Response<Bytes>> {
    Ok(http::Response::builder()
        .status(http::StatusCode::OK)
        .body(Bytes::from(format!(
            r#"{{"access_token":"{access_token}","token_type":"Bearer","expires_in":3600,"refresh_token":"{refresh_token}"}}"#
        )))
        .expect("response must build"))
}

#[derive(Clone, Default)]
struct MockHttpSend {
    responses: Arc<StdMutex<VecDeque<Result<http::Response<Bytes>>>>>,
    requests: Arc<StdMutex<Vec<Vec<u8>>>>,
    calls: Arc<AtomicUsize>,
}

impl std::fmt::Debug for MockHttpSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHttpSend")
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request lock")
            .push(req.body().to_vec());
        self.responses
            .lock()
            .expect("response lock")
            .pop_front()
            .expect("mock response must exist")
    }
}

#[wasm_bindgen_test]
async fn public_static_signer_uses_the_wasm_clock() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("wasm-onedrive-token"),
        RequestSigner,
    );
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("OneDrive signing must succeed");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer wasm-onedrive-token");
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn public_refresh_signer_caches_and_rotates_under_wasm() {
    let http = MockHttpSend::default();
    http.responses.lock().expect("response lock").extend([
        token_response("wasm-access-token", "wasm-rotated-token"),
        token_response("wasm-second-token", "wasm-second-rotated-token"),
    ]);
    let provider = RefreshCredentialProvider::new("client-id", "wasm-refresh-token")
        .expect("provider must build");

    let signer = Signer::new(
        Context::new().with_http_send(http.clone()),
        provider.clone(),
        RequestSigner,
    );
    for _ in 0..2 {
        let mut parts = request();
        signer
            .sign(&mut parts, None)
            .await
            .expect("OneDrive refresh signing must succeed");
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer wasm-access-token"
        );
    }
    assert_eq!(http.calls.load(Ordering::SeqCst), 1);

    // A separate signer cache exchanges again and must reuse the rotated token.
    let signer = Signer::new(
        Context::new().with_http_send(http.clone()),
        provider,
        RequestSigner,
    );
    let mut parts = request();
    signer
        .sign(&mut parts, None)
        .await
        .expect("OneDrive refresh signing must succeed");
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer wasm-second-token"
    );

    let requests = http.requests.lock().expect("request lock");
    assert_eq!(http.calls.load(Ordering::SeqCst), 2);
    let form = form_urlencoded::parse(&requests[1])
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(form["refresh_token"], "wasm-rotated-token");
}
