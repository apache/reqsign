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
use reqsign_aliyun_drive::{RefreshCredentialProvider, RequestSigner, StaticCredentialProvider};
use reqsign_core::{Context, HttpSend, Result, Signer};
use std::sync::{Arc, Mutex};
use wasm_bindgen_test::*;

#[derive(Clone, Debug)]
struct MockHttpSend {
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.requests
            .lock()
            .expect("request lock")
            .push(req.body().to_vec());

        Ok(http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from_static(
                br#"{"access_token":"wasm-access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"wasm-rotated-refresh-token"}"#,
            ))
            .expect("response must build"))
    }
}

fn request() -> http::request::Parts {
    http::Request::post("https://openapi.alipan.com/adrive/v1.0/openFile/get_by_path")
        .header(http::header::USER_AGENT, "wasm-aliyun-drive-test")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[wasm_bindgen_test]
async fn static_token_signs_without_a_clock() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("wasm-static-access-token"),
        RequestSigner,
    );
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("static Aliyun Drive signing must succeed");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer wasm-static-access-token");
    assert!(authorization.is_sensitive());
    assert_eq!(
        parts.headers[http::header::USER_AGENT],
        "wasm-aliyun-drive-test"
    );
}

#[wasm_bindgen_test]
async fn refresh_uses_the_wasm_clock_and_mock_transport() {
    let http = MockHttpSend {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let context = Context::new().with_http_send(http.clone());
    let provider = RefreshCredentialProvider::new(
        "wasm-client-id",
        "wasm-client-secret",
        "wasm-refresh-token",
    )
    .expect("provider must build");
    let signer = Signer::new(context, provider, RequestSigner);
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("Aliyun Drive refresh and signing must succeed");

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer wasm-access-token"
    );
    let requests = http.requests.lock().expect("request lock");
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0]).expect("token request body must be JSON");
    assert_eq!(body["client_id"], "wasm-client-id");
    assert_eq!(body["client_secret"], "wasm-client-secret");
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["refresh_token"], "wasm-refresh-token");
}
