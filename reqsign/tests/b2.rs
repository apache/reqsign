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

#![cfg(feature = "b2")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use reqsign::b2::{self, Credential, StaticCredentialProvider};
use reqsign::{Context, HttpSend, Result, StaticEnv};

const APPLICATION_KEY_ID: &str = "test-application-key-id";
const APPLICATION_KEY: &str = "test-application-key-secret";
const AUTHORIZATION_TOKEN: &str = "account-authorization-token-value";
const API_URL: &str = "https://api001.backblazeb2.com";
const DOWNLOAD_URL: &str = "https://f001.backblazeb2.com";

#[derive(Clone, Debug)]
struct MockB2 {
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
}

impl HttpSend for MockB2 {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        self.requests.lock().expect("lock poisoned").push(request);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::from(format!(
                r#"{{
                    "accountId": "account-id",
                    "apiInfo": {{
                        "storageApi": {{
                            "apiUrl": "{API_URL}",
                            "downloadUrl": "{DOWNLOAD_URL}"
                        }}
                    }},
                    "applicationKeyExpirationTimestamp": null,
                    "authorizationToken": "{AUTHORIZATION_TOKEN}"
                }}"#
            )))
            .expect("response must build"))
    }
}

#[tokio::test]
async fn default_signer_authorizes_and_signs_through_the_facade() {
    let mock = MockB2 {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let context = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([
                (
                    "B2_APPLICATION_KEY_ID".to_string(),
                    APPLICATION_KEY_ID.to_string(),
                ),
                (
                    "B2_APPLICATION_KEY".to_string(),
                    APPLICATION_KEY.to_string(),
                ),
            ]),
        });
    let signer = b2::default_signer(context);

    let mut request =
        http::Request::get(format!("{API_URL}/b2api/v4/b2_list_buckets?accountId=one"))
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
    signer
        .sign(&mut request, None)
        .await
        .expect("default signer must sign");

    assert_eq!(
        AUTHORIZATION_TOKEN,
        request.headers[http::header::AUTHORIZATION]
    );
    assert_eq!(
        format!("{API_URL}/b2api/v4/b2_list_buckets?accountId=one"),
        request.uri.to_string()
    );
    assert_eq!(1, mock.requests.lock().expect("lock poisoned").len());
}

#[tokio::test]
async fn default_signer_accepts_a_static_credential_override() {
    let mock = MockB2 {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let context = Context::new().with_http_send(mock.clone());
    let signer =
        b2::default_signer(context).with_credential_provider(StaticCredentialProvider::new(
            Credential::new("static-authorization-token", API_URL, DOWNLOAD_URL),
        ));

    let mut request = http::Request::get(format!("{API_URL}/b2api/v4/b2_list_buckets"))
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    signer
        .sign(&mut request, None)
        .await
        .expect("static credential must sign");

    assert_eq!(
        "static-authorization-token",
        request.headers[http::header::AUTHORIZATION]
    );
    assert!(mock.requests.lock().expect("lock poisoned").is_empty());
}
