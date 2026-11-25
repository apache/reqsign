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

#![cfg(feature = "aliyun-drive")]

use bytes::Bytes;
use reqsign::aliyun_drive::{
    DefaultSigner, RefreshCredentialProvider, RequestSigner, default_signer,
};
use reqsign::{Context, ErrorKind, HttpSend, Result, Signer};
use std::sync::{Arc, Mutex};

const ACCESS_TOKEN: &str = "fake-facade-access-token";
const ROTATED_REFRESH_TOKEN: &str = "fake-facade-rotated-token";

#[derive(Clone, Debug, Default)]
struct MockHttpSend {
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockHttpSend {
    fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.requests
            .lock()
            .expect("request lock")
            .push(req.body().to_vec());

        Ok(http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Bytes::from(format!(
                r#"{{"access_token":"{ACCESS_TOKEN}","token_type":"Bearer","expires_in":3600,"refresh_token":"{ROTATED_REFRESH_TOKEN}"}}"#
            )))
            .expect("response must build"))
    }
}

fn request() -> http::request::Parts {
    http::Request::post("https://openapi.alipan.com/adrive/v1.0/openFile/get_by_path")
        .header(http::header::USER_AGENT, "facade-aliyun-drive-test")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[tokio::test]
async fn facade_default_signer_uses_the_explicit_static_token() -> Result<()> {
    let http = MockHttpSend::default();
    let original = request();
    let mut parts = original.clone();
    let signer: DefaultSigner = default_signer(
        Context::new().with_http_send(http.clone()),
        "fake-facade-static-token",
    );

    signer.sign(&mut parts, None).await?;

    let authorization = &parts.headers[http::header::AUTHORIZATION];
    assert_eq!(authorization, "Bearer fake-facade-static-token");
    assert!(authorization.is_sensitive());
    assert_eq!(parts.uri, original.uri);
    assert_eq!(
        parts.headers[http::header::USER_AGENT],
        "facade-aliyun-drive-test"
    );
    assert!(http.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn facade_default_signer_rejects_an_invalid_token_without_mutating_the_request() {
    let signer = default_signer(Context::new(), "fake token with space");
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
    let http = MockHttpSend::default();
    let ctx = Context::new().with_http_send(http.clone());
    let provider = RefreshCredentialProvider::new(
        "fake-client-id",
        "fake-client-secret",
        "fake-refresh-token",
    )?;
    let signer = Signer::new(ctx, provider, RequestSigner);

    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            format!("Bearer {ACCESS_TOKEN}")
        );
    }

    let requests = http.requests();
    assert_eq!(requests.len(), 1, "the signer must reuse the cached token");
    let body: serde_json::Value =
        serde_json::from_slice(&requests[0]).expect("token request body must be JSON");
    assert_eq!(body["client_id"], "fake-client-id");
    assert_eq!(body["client_secret"], "fake-client-secret");
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["refresh_token"], "fake-refresh-token");
    Ok(())
}
