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

use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use reqsign_core::hash::base64_decode;
use reqsign_core::{Context, Error, ErrorKind, Granter, HttpSend, ProvideCredential, Result};
use reqsign_google::{
    AuthorizedUserCredentialProvider, CredentialAccessBoundaryGrant,
    CredentialAccessBoundaryPermissions, OAuth2Credentials,
    ServerSideCredentialAccessBoundaryGranter, ServiceAccount,
    ServiceAccountTokenCredentialProvider, StaticCredentialProvider,
};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use serde::Deserialize;
use serde_json::{Value, json};

const DEFAULT_URI: &str = "https://oauth2.googleapis.com/token";
const CUSTOM_URI: &str = "https://trusted.example/token?tenant=uri-secret";

#[derive(Clone, Debug, Default)]
struct MockHttp {
    requests: Arc<Mutex<Vec<Request<Bytes>>>>,
    status: StatusCode,
    body: Option<Bytes>,
    fail_transport: bool,
}

impl HttpSend for MockHttp {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        self.requests.lock().unwrap().push(request);
        if self.fail_transport {
            return Err(
                Error::unexpected("uri-secret refresh-secret assertion-secret").set_retryable(true),
            );
        }
        Ok(Response::builder().status(self.status).body(
            self.body.clone().unwrap_or_else(|| Bytes::from_static(
                br#"{"access_token":"access-secret","expires_in":3600,"token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}"#,
            )),
        ).unwrap())
    }
}

fn service_account() -> ServiceAccount {
    static KEY: OnceLock<String> = OnceLock::new();
    ServiceAccount {
        private_key: KEY
            .get_or_init(|| {
                RsaPrivateKey::new(&mut OsRng, 1024)
                    .unwrap()
                    .to_pkcs8_pem(LineEnding::LF)
                    .unwrap()
                    .to_string()
            })
            .clone(),
        client_email: "test@example.iam.gserviceaccount.com".into(),
    }
}

fn oauth_credentials() -> OAuth2Credentials {
    OAuth2Credentials {
        client_id: "test-client".into(),
        client_secret: "client-secret".into(),
        refresh_token: "refresh-secret".into(),
    }
}

fn jwt_claims(request: &Request<Bytes>) -> Value {
    assert_eq!(request.method(), "POST");
    assert_eq!(
        request.headers()["content-type"],
        "application/x-www-form-urlencoded"
    );
    let form: std::collections::HashMap<_, _> = form_urlencoded::parse(request.body())
        .into_owned()
        .collect();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let mut segment = form["assertion"]
        .split('.')
        .nth(1)
        .unwrap()
        .replace('-', "+")
        .replace('_', "/");
    while segment.len() % 4 != 0 {
        segment.push('=');
    }
    serde_json::from_slice(&base64_decode(&segment).unwrap()).unwrap()
}

#[tokio::test]
async fn service_account_uses_selected_uri_for_request_and_audience_on_each_exchange() -> Result<()>
{
    for uri in [None, Some(CUSTOM_URI), Some("http://127.0.0.1:8765/token")] {
        let http = MockHttp::default();
        let ctx = Context::new().with_http_send(http.clone());
        let mut provider = ServiceAccountTokenCredentialProvider::new(service_account())
            .with_scope("scope-a scope-b");
        if let Some(uri) = uri {
            provider = provider.with_token_uri(uri)?;
        }
        for _ in 0..2 {
            let output = provider.provide_credential(&ctx).await?.unwrap();
            assert_eq!(
                output.signer_email.as_deref(),
                Some("test@example.iam.gserviceaccount.com")
            );
            assert!(output.service_account.is_none());
            let token = output.token.unwrap();
            assert_eq!(token.access_token, "access-secret");
            assert!(token.expires_at.is_some());
        }
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            assert_eq!(request.uri(), uri.unwrap_or(DEFAULT_URI));
            let claims = jwt_claims(request);
            assert_eq!(claims["aud"], uri.unwrap_or(DEFAULT_URI));
            assert_eq!(claims["iss"], "test@example.iam.gserviceaccount.com");
            assert_eq!(claims["scope"], "scope-a scope-b");
            assert_eq!(
                claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
                3600
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn authorized_user_uses_selected_uri_and_preserves_refresh_fields() -> Result<()> {
    for uri in [None, Some(CUSTOM_URI), Some("http://[::1]:8765/token")] {
        let http = MockHttp::default();
        let ctx = Context::new().with_http_send(http.clone());
        let mut provider = AuthorizedUserCredentialProvider::new(oauth_credentials());
        if let Some(uri) = uri {
            provider = provider.with_token_uri(uri)?;
        }
        for _ in 0..2 {
            let token = provider
                .provide_credential(&ctx)
                .await?
                .unwrap()
                .token
                .unwrap();
            assert_eq!(token.access_token, "access-secret");
            assert!(token.expires_at.is_some());
        }
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            assert_eq!(request.uri(), uri.unwrap_or(DEFAULT_URI));
            assert_eq!(request.method(), "POST");
            assert_eq!(request.headers()["content-type"], "application/json");
            assert_eq!(
                serde_json::from_slice::<Value>(request.body()).unwrap(),
                json!({
                    "grant_type": "refresh_token", "client_id": "test-client",
                    "client_secret": "client-secret", "refresh_token": "refresh-secret",
                })
            );
        }
    }
    Ok(())
}

// An adapter retains token_uri while deserializing Reqsign's credential types.
#[derive(Deserialize)]
struct TrustedInput<T> {
    #[serde(flatten)]
    credential: T,
    token_uri: Option<String>,
}

#[tokio::test]
async fn adapter_selects_explicit_configuration_then_file_uri_then_default() -> Result<()> {
    let sa = service_account();
    for file_uri in [None, Some("https://file.example/token")] {
        for override_uri in [None, Some(CUSTOM_URI)] {
            let service_json = json!({
                "type": "service_account", "private_key": sa.private_key,
                "client_email": sa.client_email, "token_uri": file_uri,
            });
            let user_json = json!({
                "type": "authorized_user", "client_id": "test-client",
                "client_secret": "client-secret", "refresh_token": "refresh-secret",
                "token_uri": file_uri,
            });
            let input: TrustedInput<ServiceAccount> =
                serde_json::from_value(service_json.clone()).unwrap();
            let mut service = ServiceAccountTokenCredentialProvider::new(input.credential);
            if let Some(uri) = override_uri.or(input.token_uri.as_deref()) {
                service = service.with_token_uri(uri)?;
            }
            let input: TrustedInput<OAuth2Credentials> =
                serde_json::from_value(user_json.clone()).unwrap();
            let mut user = AuthorizedUserCredentialProvider::new(input.credential);
            if let Some(uri) = override_uri.or(input.token_uri.as_deref()) {
                user = user.with_token_uri(uri)?;
            }
            let http = MockHttp::default();
            let ctx = Context::new().with_http_send(http.clone());
            service.provide_credential(&ctx).await?;
            user.provide_credential(&ctx).await?;

            // Existing JSON providers keep their canonical behavior unless the
            // adapter explicitly passes its selection to the OAuth provider.
            ServiceAccountTokenCredentialProvider::from_provider(StaticCredentialProvider::new(
                service_json.to_string(),
            ))
            .provide_credential(&ctx)
            .await?;
            StaticCredentialProvider::new(user_json.to_string())
                .provide_credential(&ctx)
                .await?;
            let requests = http.requests.lock().unwrap();
            let expected = override_uri.or(file_uri).unwrap_or(DEFAULT_URI);
            assert_eq!(requests[0].uri(), expected);
            assert_eq!(jwt_claims(&requests[0])["aud"], expected);
            assert_eq!(requests[1].uri(), expected);
            assert_eq!(requests[2].uri(), DEFAULT_URI);
            assert_eq!(requests[3].uri(), DEFAULT_URI);
        }
    }
    Ok(())
}

#[test]
fn malformed_endpoints_are_rejected_without_echoing_input() {
    for uri in [
        "",
        "/token",
        "trusted.example/token",
        "ftp://trusted.example/token",
        "https:///token",
        "https://",
        "https://@/token",
        "https://trusted.example:/token",
        "https://user:password@trusted.example/token",
        "https://trusted.example/token#fragment-secret",
        "https://trusted.example:99999/token",
        "https://trusted.example:bad/token",
        "https://trusted.example/token\n",
        " https://trusted.example/token",
        "https://trusted.example/to ken",
    ] {
        let errors = [
            ServiceAccountTokenCredentialProvider::new(service_account())
                .with_token_uri(uri)
                .expect_err(uri),
            AuthorizedUserCredentialProvider::new(oauth_credentials())
                .with_token_uri(uri)
                .expect_err(uri),
        ];
        for error in errors {
            assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
            assert!(!format!("{error:?}").contains("trusted.example"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}

#[tokio::test]
async fn failures_are_redacted_and_do_not_fall_back() -> Result<()> {
    let service =
        ServiceAccountTokenCredentialProvider::new(service_account()).with_token_uri(CUSTOM_URI)?;
    let user =
        AuthorizedUserCredentialProvider::new(oauth_credentials()).with_token_uri(CUSTOM_URI)?;
    assert!(!format!("{service:?} {user:?}").contains("uri-secret"));
    assert!(!format!("{user:?}").contains("refresh-secret"));
    for http in [
        MockHttp { fail_transport: true, ..Default::default() },
        MockHttp { status: StatusCode::BAD_REQUEST, body: Some(Bytes::from_static(
            br#"{"error":"invalid_grant","error_description":"refresh-secret client-secret assertion-secret access-secret uri-secret"}"#,
        )), ..Default::default() },
        MockHttp { body: Some(Bytes::from_static(
            br#"{"access_token":"access-secret","expires_in":"refresh-secret"}"#,
        )), ..Default::default() },
        MockHttp { body: Some(Bytes::from_static(
            br#"{"access_token":"access-secret","expires_in":18446744073709551615}"#,
        )), ..Default::default() },
    ] {
        let ctx = Context::new().with_http_send(http.clone());
        let errors = [service.provide_credential(&ctx).await.unwrap_err(), user.provide_credential(&ctx).await.unwrap_err()];
        for error in errors {
            let rendered = format!("{error} {error:?}");
            for secret in ["uri-secret", "refresh-secret", "client-secret", "assertion-secret", "access-secret"] {
                assert!(!rendered.contains(secret));
            }
            assert!(std::error::Error::source(&error).is_none());
            if http.fail_transport { assert!(error.is_retryable()); }
        }
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.uri() == CUSTOM_URI));
    }
    Ok(())
}

#[tokio::test]
async fn custom_oauth_sources_compose_with_existing_granter() -> Result<()> {
    async fn grant(
        source: impl ProvideCredential<Credential = reqsign_google::Credential> + 'static,
    ) -> Result<MockHttp> {
        let http = MockHttp::default();
        let grant = CredentialAccessBoundaryGrant::for_object_prefix(
            "bucket",
            "prefix/",
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        );
        let output = Granter::new(
            Context::new().with_http_send(http.clone()),
            source,
            ServerSideCredentialAccessBoundaryGranter::new(grant),
        )
        .grant(None)
        .await?;
        assert!(output.token.unwrap().expires_at.is_some());
        Ok(http)
    }
    let service =
        ServiceAccountTokenCredentialProvider::new(service_account()).with_token_uri(CUSTOM_URI)?;
    let user =
        AuthorizedUserCredentialProvider::new(oauth_credentials()).with_token_uri(CUSTOM_URI)?;
    for http in [grant(service).await?, grant(user).await?] {
        let requests = http.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].uri(), CUSTOM_URI);
        assert_eq!(requests[1].uri(), "https://sts.googleapis.com/v1/token");
        let form: std::collections::HashMap<_, _> = form_urlencoded::parse(requests[1].body())
            .into_owned()
            .collect();
        assert_eq!(form["subject_token"], "access-secret");
    }
    Ok(())
}
