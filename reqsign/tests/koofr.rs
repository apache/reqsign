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

#![cfg(feature = "koofr")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::header::AUTHORIZATION;
use reqsign::koofr::{StaticCredentialProvider, default_signer};
use reqsign::{Context, Error, HttpSend, Result};

#[derive(Debug, Clone, Default)]
struct MockHttp {
    responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
    requests: Arc<Mutex<Vec<http::Request<Bytes>>>>,
}

impl MockHttp {
    fn with_token(token: &str) -> Self {
        let mock = Self::default();
        mock.responses.lock().expect("lock").push_back(
            http::Response::builder()
                .status(200)
                .body(Bytes::from(format!(r#"{{"token":"{token}"}}"#)))
                .expect("response must build"),
        );
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

fn parts() -> http::request::Parts {
    http::Request::get("https://app.koofr.net/api/v2/mounts")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[tokio::test]
async fn default_signer_exchanges_and_signs() -> Result<()> {
    let mock = MockHttp::with_token("fabricated-token");
    let signer = default_signer(
        Context::new().with_http_send(mock.clone()),
        "me@example.com",
        "fabricated-app-password",
    );
    let mut request = parts();

    signer.sign(&mut request, None).await?;

    assert_eq!(1, mock.request_count());
    assert_eq!(
        "Token token=fabricated-token",
        request.headers[AUTHORIZATION]
    );

    Ok(())
}

#[tokio::test]
async fn default_signer_can_use_a_static_provider() -> Result<()> {
    let signer = default_signer(Context::new(), "me@example.com", "fabricated-app-password")
        .with_credential_provider(StaticCredentialProvider::new("fabricated-token"));
    let mut request = parts();

    signer.sign(&mut request, None).await?;

    assert_eq!(
        "Token token=fabricated-token",
        request.headers[AUTHORIZATION]
    );

    Ok(())
}
