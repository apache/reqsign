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
use reqsign_core::{Context, HttpSend, Result, SigningCredential};
use reqsign_oauth2::RefreshTokenGrant;
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
                br#"{"access_token":"wasm-access-token","token_type":"bearer","expires_in":3600,"refresh_token":"wasm-rotated-token"}"#,
            ))
            .expect("response must build"))
    }
}

#[wasm_bindgen_test]
async fn public_refresh_uses_the_wasm_clock_and_mock_transport() {
    let http = MockHttpSend {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let context = Context::new().with_http_send(http.clone());
    let grant = RefreshTokenGrant::new(
        "https://api.example.com/oauth2/token",
        "client-id",
        None,
        "refresh-token",
        None,
    )
    .expect("grant must build");

    let token = grant.refresh(&context).await.expect("refresh must succeed");

    assert_eq!(http.requests.lock().expect("request lock").len(), 1);
    assert_eq!(
        std::str::from_utf8(&http.requests.lock().expect("request lock")[0])
            .expect("form body must be UTF-8"),
        "grant_type=refresh_token&refresh_token=refresh-token&client_id=client-id"
    );
    assert!(token.expires_at().is_some());
    assert!(token.is_valid());
    let authorization = token.bearer_header_value().expect("header must build");
    assert_eq!(authorization, "Bearer wasm-access-token");
    assert!(authorization.is_sensitive());
}
