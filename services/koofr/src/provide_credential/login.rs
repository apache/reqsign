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

use std::fmt::{self, Debug};

use http::header;
use log::debug;
use reqsign_core::utils::Redact;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::{Deserialize, Serialize};

use crate::Credential;

/// Obtains a Koofr access token by exchanging an account email and an
/// application-specific password.
///
/// The exchange posts the documented JSON body to `POST {endpoint}/token`:
///
/// ```json
/// {"email":"me@example.com","password":"application-specific-password"}
/// ```
///
/// A successful response returns `{"token":"..."}`. Koofr's first-party SDKs
/// do not define a production environment-variable credential source, so this
/// provider always requires explicit configuration.
///
/// The application password is generated at
/// <https://app.koofr.net/app/admin/preferences/password> and is not the
/// account login password.
#[derive(Clone)]
pub struct LoginCredentialProvider {
    endpoint: String,
    email: String,
    app_password: String,
}

impl LoginCredentialProvider {
    /// The official Koofr API endpoint used by the first-party SDKs.
    pub const DEFAULT_ENDPOINT: &'static str = "https://app.koofr.net";

    /// Create a provider for the official Koofr API endpoint.
    pub fn new(email: impl Into<String>, app_password: impl Into<String>) -> Self {
        Self {
            endpoint: Self::DEFAULT_ENDPOINT.to_string(),
            email: email.into(),
            app_password: app_password.into(),
        }
    }

    /// Use a Koofr-compatible API endpoint instead of the official endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    fn token_url(&self) -> String {
        format!("{}/token", self.endpoint.trim().trim_end_matches('/'))
    }

    fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(Error::config_invalid(
                "Koofr login credential provider requires a non-empty endpoint",
            ));
        }
        if self.email.trim().is_empty() {
            return Err(Error::config_invalid(
                "Koofr login credential provider requires a non-empty email",
            ));
        }
        if self.app_password.is_empty() {
            return Err(Error::config_invalid(
                "Koofr login credential provider requires a non-empty application password",
            ));
        }

        Ok(())
    }
}

impl Debug for LoginCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginCredentialProvider")
            .field("endpoint", &self.endpoint)
            .field("email", &self.email)
            .field("app_password", &Redact::from(&self.app_password))
            .finish()
    }
}

impl ProvideCredential for LoginCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.validate()?;

        let url = self.token_url();
        debug!(
            "exchanging Koofr login credentials for an access token at {url} as {}",
            self.email
        );

        let body = serde_json::to_vec(&TokenRequest {
            email: &self.email,
            password: &self.app_password,
        })
        .map_err(|err| {
            Error::unexpected("failed to serialize Koofr token request").with_source(err)
        })?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .map_err(|err| {
                Error::unexpected("failed to build Koofr token request").with_source(err)
            })?;

        let response = ctx.http_send(request).await?;
        let status = response.status();
        let body = response.into_body();

        if status != http::StatusCode::OK {
            return Err(token_exchange_error(status, &body));
        }

        let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
            Error::unexpected("failed to parse Koofr token response").with_source(err)
        })?;

        if token_response.token.is_empty() {
            return Err(Error::credential_invalid(
                "Koofr token response contained an empty access token",
            ));
        }

        debug!("Koofr login credential exchange succeeded");

        Ok(Some(Credential::new(token_response.token)))
    }
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    // Koofr's first-party Go SDK decodes this field case-insensitively from
    // either `token` or `Token`.
    #[serde(alias = "Token")]
    token: String,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    #[serde(default)]
    error: Option<ApiErrorDetails>,
    #[serde(default, rename = "requestId")]
    request_id: Option<String>,
}

#[derive(Deserialize)]
struct ApiErrorDetails {
    #[serde(default)]
    code: Option<String>,
}

fn token_exchange_error(status: http::StatusCode, body: &[u8]) -> Error {
    let mut error = match status.as_u16() {
        401 | 403 => Error::permission_denied(format!(
            "Koofr token exchange failed with status {}",
            status.as_u16()
        )),
        429 => Error::rate_limited(format!(
            "Koofr token exchange failed with status {}",
            status.as_u16()
        )),
        _ => Error::unexpected(format!(
            "Koofr token exchange failed with status {}",
            status.as_u16()
        )),
    };

    if status.is_server_error() {
        error = error.set_retryable(true);
    }

    // Only include fields from Koofr's documented error envelope. Arbitrary
    // response bytes are not safe to return because they can echo secrets.
    if let Ok(api_error) = serde_json::from_slice::<ApiErrorResponse>(body) {
        if let Some(code) = api_error.error.and_then(|error| error.code) {
            error = error.with_context(format!("koofr_error_code: {code}"));
        }
        if let Some(request_id) = api_error.request_id {
            error = error.with_context(format!("koofr_request_id: {request_id}"));
        }
    }

    error
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use reqsign_core::HttpSend;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct MockHttp {
        responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
        requests: Arc<Mutex<Vec<http::Request<Bytes>>>>,
    }

    impl MockHttp {
        fn with_response(response: http::Response<Bytes>) -> Self {
            let mock = Self::default();
            mock.responses.lock().expect("lock").push_back(response);
            mock
        }

        fn requests(&self) -> Vec<http::Request<Bytes>> {
            self.requests.lock().expect("lock").clone()
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

    fn json_response(status: u16, body: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::copy_from_slice(body.as_bytes()))
            .expect("response must build")
    }

    fn test_context(mock: MockHttp) -> Context {
        Context::new().with_http_send(mock)
    }

    #[tokio::test]
    async fn exchanges_documented_json_body_for_token() -> Result<()> {
        let mock = MockHttp::with_response(json_response(200, r#"{"token":"fabricated-token"}"#));
        let ctx = test_context(mock.clone());

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let credential = provider.provide_credential(&ctx).await?.expect("token");

        assert_eq!("fabricated-token", credential.token());
        let requests = mock.requests();
        assert_eq!(1, requests.len());
        let request = &requests[0];
        assert_eq!(http::Method::POST, request.method());
        assert_eq!("https://app.koofr.net/token", request.uri().to_string());
        assert_eq!("application/json", request.headers()[header::CONTENT_TYPE]);
        let body: serde_json::Value =
            serde_json::from_slice(request.body()).expect("request body must be JSON");
        assert_eq!(
            serde_json::json!({
                "email": "me@example.com",
                "password": "fabricated-app-password",
            }),
            body
        );

        Ok(())
    }

    #[tokio::test]
    async fn accepts_capitalized_token_field_from_first_party_sdk_shape() -> Result<()> {
        let mock = MockHttp::with_response(json_response(200, r#"{"Token":"fabricated-token"}"#));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let credential = provider.provide_credential(&ctx).await?.expect("token");

        assert_eq!("fabricated-token", credential.token());

        Ok(())
    }

    #[tokio::test]
    async fn trims_trailing_slash_from_custom_endpoint() -> Result<()> {
        let mock = MockHttp::with_response(json_response(200, r#"{"token":"fabricated-token"}"#));
        let ctx = test_context(mock.clone());

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password")
            .with_endpoint("https://koofr.example.com/");
        provider.provide_credential(&ctx).await?.expect("token");

        assert_eq!(
            "https://koofr.example.com/token",
            mock.requests()[0].uri().to_string()
        );

        Ok(())
    }

    #[tokio::test]
    async fn rejects_incomplete_configuration_before_http() {
        for provider in [
            LoginCredentialProvider::new("", "fabricated-app-password"),
            LoginCredentialProvider::new("me@example.com", ""),
            LoginCredentialProvider::new("me@example.com", "fabricated-app-password")
                .with_endpoint(""),
        ] {
            let mock = MockHttp::default();
            let ctx = test_context(mock.clone());

            let error = provider
                .provide_credential(&ctx)
                .await
                .expect_err("configuration must be rejected");

            assert_eq!(reqsign_core::ErrorKind::ConfigInvalid, error.kind());
            assert!(mock.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn rejects_empty_token_response() {
        let mock = MockHttp::with_response(json_response(200, r#"{"token":""}"#));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("empty token must be rejected");

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
    }

    #[tokio::test]
    async fn error_redacts_login_secret_and_echoed_body() {
        let mock = MockHttp::with_response(json_response(
            401,
            r#"{"error":{"code":"InvalidCredentials","message":"fabricated-app-password"},"requestId":"req-123"}"#,
        ));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("401 must fail");
        let rendered = format!("{error} {error:?}");

        assert_eq!(reqsign_core::ErrorKind::PermissionDenied, error.kind());
        assert!(!rendered.contains("fabricated-app-password"));
        assert!(rendered.contains("InvalidCredentials"));
        assert!(rendered.contains("req-123"));
    }

    #[tokio::test]
    async fn malformed_response_does_not_echo_body() {
        let mock =
            MockHttp::with_response(json_response(200, r#"{"token":"fabricated-app-password""#));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("malformed JSON must fail");
        let rendered = format!("{error} {error:?}");

        assert_eq!(reqsign_core::ErrorKind::Unexpected, error.kind());
        assert!(!rendered.contains("fabricated-app-password"));
    }

    #[test]
    fn debug_redacts_application_secret() {
        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let debug = format!("{provider:?}");

        assert!(!debug.contains("fabricated-app-password"));
        assert!(debug.contains("me@example.com"));
    }
}
