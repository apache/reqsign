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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use reqsign_b2::{
    AccountAuthorizationCredentialProvider, Credential, DefaultCredentialProvider,
    EnvCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, HttpSend, ProvideCredential, Result, Signer, StaticEnv};

const APPLICATION_KEY_ID: &str = "test-application-key-id";
const APPLICATION_KEY: &str = "test-application-key-secret";
const AUTHORIZE_ACCOUNT_URL: &str = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";
const AUTHORIZATION_TOKEN: &str = "account-authorization-token-value";
const API_URL: &str = "https://api001.backblazeb2.com";
const DOWNLOAD_URL: &str = "https://f001.backblazeb2.com";
const BASIC_AUTHORIZATION: &str =
    "Basic dGVzdC1hcHBsaWNhdGlvbi1rZXktaWQ6dGVzdC1hcHBsaWNhdGlvbi1rZXktc2VjcmV0";

#[derive(Clone, Debug)]
struct MockB2 {
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
    status: StatusCode,
    body: String,
    transport_error: Option<&'static str>,
}

impl MockB2 {
    fn new(body: String) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            status: StatusCode::OK,
            body,
            transport_error: None,
        }
    }

    fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    fn with_transport_error(mut self, message: &'static str) -> Self {
        self.transport_error = Some(message);
        self
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("lock poisoned").len()
    }

    fn last_request(&self) -> Request<Bytes> {
        self.requests
            .lock()
            .expect("lock poisoned")
            .last()
            .expect("provider must send a request")
            .clone()
    }
}

impl HttpSend for MockB2 {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        self.requests.lock().expect("lock poisoned").push(request);

        if let Some(message) = self.transport_error {
            return Err(Error::unexpected(message));
        }

        Ok(Response::builder()
            .status(self.status)
            .body(Bytes::from(self.body.clone()))
            .expect("response must build"))
    }
}

fn authorize_response(application_key_expiration_timestamp: Option<i64>) -> String {
    serde_json::json!({
        "accountId": "account-id",
        "apiInfo": {
            "storageApi": {
                "absoluteMinimumPartSize": 5_000_000,
                "apiUrl": API_URL,
                "allowed": {
                    "buckets": [
                        { "id": "bucket-id", "name": "bucket-name" }
                    ],
                    "capabilities": ["listFiles", "readFiles", "writeFiles"],
                    "namePrefix": null
                },
                "downloadUrl": DOWNLOAD_URL,
                "recommendedPartSize": 100_000_000,
                "s3ApiUrl": "https://s3.us-west-001.backblazeb2.com"
            },
            "groupsApi": {
                "capabilities": ["all"],
                "groupsApiUrl": "https://api001.backblazeb2.com",
                "infoType": "groupsApi"
            }
        },
        "applicationKeyExpirationTimestamp": application_key_expiration_timestamp,
        "authorizationToken": AUTHORIZATION_TOKEN
    })
    .to_string()
}

fn envs(envs: impl IntoIterator<Item = (&'static str, &'static str)>) -> HashMap<String, String> {
    envs.into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn explicit_provider() -> AccountAuthorizationCredentialProvider {
    AccountAuthorizationCredentialProvider::new(APPLICATION_KEY_ID, APPLICATION_KEY)
}

#[tokio::test]
async fn account_authorization_uses_the_v4_basic_exchange() {
    let mock = MockB2::new(authorize_response(None));
    let context = Context::new().with_http_send(mock.clone());
    let before = Timestamp::now();

    let credential = explicit_provider()
        .provide_credential(&context)
        .await
        .expect("account authorization must succeed")
        .expect("credential must be present");
    let after = Timestamp::now();

    assert_eq!(AUTHORIZATION_TOKEN, credential.authorization_token);
    assert_eq!(API_URL, credential.api_url);
    assert_eq!(DOWNLOAD_URL, credential.download_url);
    let expires_at = credential.expires_at.expect("expiry must be set");
    assert!(expires_at >= before + Duration::from_secs(86_400));
    assert!(expires_at <= after + Duration::from_secs(86_400));

    let request = mock.last_request();
    assert_eq!(http::Method::GET, request.method());
    assert_eq!(AUTHORIZE_ACCOUNT_URL, request.uri().to_string());
    let authorization = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .expect("Basic authorization must be present");
    assert_eq!(BASIC_AUTHORIZATION, authorization);
    assert!(authorization.is_sensitive());
    assert!(request.body().is_empty());
    assert_eq!(1, mock.request_count());
}

#[tokio::test]
async fn application_key_expiration_caps_the_authorization_token() {
    let key_expires_at =
        Timestamp::from_second(Timestamp::now().as_second() + 3_600).expect("timestamp must parse");
    let key_expiration_millis = key_expires_at.as_second() * 1_000;
    let mock = MockB2::new(authorize_response(Some(key_expiration_millis)));
    let context = Context::new().with_http_send(mock);

    let credential = explicit_provider()
        .provide_credential(&context)
        .await
        .expect("account authorization must succeed")
        .expect("credential must be present");

    assert_eq!(Some(key_expires_at), credential.expires_at);
}

#[tokio::test]
async fn expired_application_key_is_rejected() {
    let key_expiration_millis = (Timestamp::now().as_second() - 1) * 1_000;
    let mock = MockB2::new(authorize_response(Some(key_expiration_millis)));
    let context = Context::new().with_http_send(mock);

    let error = explicit_provider()
        .provide_credential(&context)
        .await
        .expect_err("expired application key must fail");

    assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
    assert!(!format!("{error:?}").contains(APPLICATION_KEY));
}

#[tokio::test]
async fn failed_authorization_does_not_echo_the_response_body_or_keys() {
    let body = format!(
        r#"{{"status":401,"code":"unauthorized","message":"{APPLICATION_KEY} {AUTHORIZATION_TOKEN}"}}"#
    );
    let mock = MockB2::new(body).with_status(StatusCode::UNAUTHORIZED);
    let context = Context::new().with_http_send(mock);

    let error = explicit_provider()
        .provide_credential(&context)
        .await
        .expect_err("unauthorized response must fail");

    assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
    let text = format!("{error:?}");
    assert!(text.contains("status 401"));
    assert!(text.contains("code unauthorized"));
    assert!(!text.contains(APPLICATION_KEY));
    assert!(!text.contains(AUTHORIZATION_TOKEN));
}

#[tokio::test]
async fn malformed_response_is_rejected_without_echoing_the_body() {
    let mock = MockB2::new(format!(r#"{{"authorizationToken":"{AUTHORIZATION_TOKEN}"#));
    let context = Context::new().with_http_send(mock);

    let error = explicit_provider()
        .provide_credential(&context)
        .await
        .expect_err("malformed response must fail");

    assert_eq!(reqsign_core::ErrorKind::Unexpected, error.kind());
    assert!(!format!("{error:?}").contains(AUTHORIZATION_TOKEN));
}

#[tokio::test]
async fn response_without_native_api_urls_is_rejected() {
    let body = format!(
        r#"{{"apiInfo":{{"storageApi":{{"apiUrl":"","downloadUrl":"{DOWNLOAD_URL}"}}}},"authorizationToken":"{AUTHORIZATION_TOKEN}"}}"#
    );
    let mock = MockB2::new(body);
    let context = Context::new().with_http_send(mock);

    let error = explicit_provider()
        .provide_credential(&context)
        .await
        .expect_err("missing apiUrl must fail");

    assert_eq!(reqsign_core::ErrorKind::Unexpected, error.kind());
    assert!(error.to_string().contains("apiUrl"));
}

#[tokio::test]
async fn transport_errors_are_returned() {
    let mock = MockB2::new(authorize_response(None)).with_transport_error("connection refused");
    let context = Context::new().with_http_send(mock);

    let error = explicit_provider()
        .provide_credential(&context)
        .await
        .expect_err("transport errors must not be swallowed");

    assert_eq!(reqsign_core::ErrorKind::Unexpected, error.kind());
}

#[tokio::test]
async fn environment_provider_discovers_the_official_variables() {
    let mock = MockB2::new(authorize_response(None));
    let context = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: envs([
                ("B2_APPLICATION_KEY_ID", APPLICATION_KEY_ID),
                ("B2_APPLICATION_KEY", APPLICATION_KEY),
            ]),
        });

    let credential = EnvCredentialProvider::new()
        .provide_credential(&context)
        .await
        .expect("environment authorization must succeed")
        .expect("credential must be present");

    assert_eq!(AUTHORIZATION_TOKEN, credential.authorization_token);
    assert_eq!(
        BASIC_AUTHORIZATION,
        mock.last_request().headers()[http::header::AUTHORIZATION]
    );
}

#[tokio::test]
async fn environment_provider_skips_when_either_variable_is_missing() {
    for (id, key) in [
        (Some(APPLICATION_KEY_ID), None),
        (None, Some(APPLICATION_KEY)),
    ] {
        let mock = MockB2::new(authorize_response(None));
        let mut values = HashMap::new();
        if let Some(id) = id {
            values.insert("B2_APPLICATION_KEY_ID".to_string(), id.to_string());
        }
        if let Some(key) = key {
            values.insert("B2_APPLICATION_KEY".to_string(), key.to_string());
        }
        let context = Context::new()
            .with_http_send(mock.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: values,
            });

        let credential = EnvCredentialProvider::new()
            .provide_credential(&context)
            .await
            .expect("missing variables must not fail");

        assert!(credential.is_none());
        assert_eq!(0, mock.request_count());
    }
}

#[tokio::test]
async fn default_provider_uses_environment_credentials_and_caches_them() {
    let mock = MockB2::new(authorize_response(None));
    let context = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: envs([
                ("B2_APPLICATION_KEY_ID", APPLICATION_KEY_ID),
                ("B2_APPLICATION_KEY", APPLICATION_KEY),
            ]),
        });
    let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);

    let mut first = http::Request::get(format!("{API_URL}/b2api/v4/b2_list_buckets?accountId=one"))
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    signer
        .sign(&mut first, None)
        .await
        .expect("first request must sign");

    let mut second =
        http::Request::put(format!("{API_URL}/b2api/v4/b2_list_buckets?accountId=two"))
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
    signer
        .sign(&mut second, None)
        .await
        .expect("second request must sign");

    assert_eq!(
        AUTHORIZATION_TOKEN,
        first.headers[http::header::AUTHORIZATION]
    );
    assert_eq!(
        AUTHORIZATION_TOKEN,
        second.headers[http::header::AUTHORIZATION]
    );
    assert!(first.headers[http::header::AUTHORIZATION].is_sensitive());
    assert_eq!(
        format!("{API_URL}/b2api/v4/b2_list_buckets?accountId=one"),
        first.uri.to_string()
    );
    assert_eq!(
        format!("{API_URL}/b2api/v4/b2_list_buckets?accountId=two"),
        second.uri.to_string()
    );
    assert_eq!(http::Method::PUT, second.method);
    assert_eq!(
        1,
        mock.request_count(),
        "the second sign must reuse the cached token"
    );
}

#[tokio::test]
async fn static_provider_override_bypasses_environment_discovery() {
    let mock = MockB2::new(authorize_response(None));
    let context = Context::new()
        .with_http_send(mock.clone())
        .with_env(StaticEnv {
            home_dir: None,
            envs: envs([
                ("B2_APPLICATION_KEY_ID", APPLICATION_KEY_ID),
                ("B2_APPLICATION_KEY", APPLICATION_KEY),
            ]),
        });
    let static_credential = Credential::new("static-authorization-token", API_URL, DOWNLOAD_URL);
    let provider = DefaultCredentialProvider::new()
        .push_front(StaticCredentialProvider::new(static_credential));
    let signer = Signer::new(context, provider, RequestSigner);

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
    assert_eq!(0, mock.request_count());
}

#[tokio::test]
async fn overflowing_signing_deadline_through_signer_rejects_finite_and_accepts_static_credentials()
{
    let mut request = http::Request::get(format!("{API_URL}/b2api/v4/b2_list_buckets"))
        .header("x-caller", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    let original = request.clone();

    let finite = Credential::new(AUTHORIZATION_TOKEN, API_URL, DOWNLOAD_URL)
        .with_expires_at(Timestamp::now() + Duration::from_secs(3_600));
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(finite),
        RequestSigner,
    );
    let error = signer
        .sign(&mut request, Some(Duration::MAX))
        .await
        .expect_err("a finite credential must not satisfy an overflowing deadline");
    assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
    assert_eq!(original.uri, request.uri);
    assert_eq!(original.headers, request.headers);

    let static_credential = Credential::new(AUTHORIZATION_TOKEN, API_URL, DOWNLOAD_URL);
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(static_credential),
        RequestSigner,
    );
    signer
        .sign(&mut request, Some(Duration::MAX))
        .await
        .expect("a credential without expiry must sign an overflowing deadline");
    assert_eq!(
        AUTHORIZATION_TOKEN,
        request.headers[http::header::AUTHORIZATION]
    );
}
