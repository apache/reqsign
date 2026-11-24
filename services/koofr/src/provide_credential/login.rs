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
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::{Deserialize, Serialize};

use crate::Credential;

/// Obtains a Koofr access token by exchanging an account email and an
/// application-specific password.
///
/// The exchange posts JSON to `POST {endpoint}/token`:
///
/// ```json
/// {"email":"me@example.com","password":"application-specific-password"}
/// ```
///
/// A successful response returns `{"token":"..."}`. This JSON exchange follows
/// Koofr's first-party Go SDK; OpenDAL's Koofr backend uses the same exchange.
/// Koofr's API Swagger documents Bearer and app-password Basic schemes
/// separately; it does not describe this `/token` exchange.
///
/// Koofr's first-party SDKs do not define a production environment-variable
/// credential source, so this provider always requires explicit configuration.
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
    ///
    /// The endpoint must be an absolute HTTP(S) URI with a host, an optional
    /// port, and an optional path prefix. Userinfo, query strings, fragments,
    /// dot segments, backslashes, whitespace, and control characters are
    /// rejected. An explicit `http://` endpoint sends the email and application
    /// password in cleartext. Reqsign sends the exchange to this configured
    /// destination; redirect policy belongs to the configured HTTP adapter.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    fn token_url(&self) -> Result<String> {
        let endpoint = checked_endpoint(&self.endpoint)?;

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

        Ok(format!("{endpoint}/token"))
    }
}

impl Debug for LoginCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl ProvideCredential for LoginCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let url = self.token_url()?;
        debug!("exchanging Koofr login credentials for an access token");

        let body = serde_json::to_vec(&TokenRequest {
            email: &self.email,
            password: &self.app_password,
        })
        .map_err(|_| Error::unexpected("failed to serialize Koofr token request"))?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .map_err(|_| Error::unexpected("failed to build Koofr token request"))?;

        let response = ctx.http_send(request).await.map_err(|error| {
            Error::new(error.kind(), "Koofr token exchange request failed")
                .set_retryable(error.is_retryable())
        })?;

        let status = response.status();
        let body = response.into_body();

        if status != http::StatusCode::OK {
            return Err(token_exchange_error(status));
        }

        let token_response: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| Error::unexpected("failed to parse Koofr token response"))?;

        if !Credential::is_valid_token(&token_response.token) {
            return Err(Error::credential_invalid(
                "Koofr token response did not contain a usable access token",
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

fn token_exchange_error(status: http::StatusCode) -> Error {
    match status.as_u16() {
        401 | 403 => Error::permission_denied(format!(
            "Koofr token exchange failed with status {}",
            status.as_u16()
        )),
        429 => Error::rate_limited(format!(
            "Koofr token exchange failed with status {}",
            status.as_u16()
        )),
        _ => {
            let error = Error::unexpected(format!(
                "Koofr token exchange failed with status {}",
                status.as_u16()
            ));
            if status.is_server_error() {
                error.set_retryable(true)
            } else {
                error
            }
        }
    }
}

/// Validate and normalize an explicit Koofr endpoint.
///
/// The endpoint must be an absolute HTTP(S) URI with an unambiguous authority,
/// an optional port, and an optional path prefix. This follows the repository's
/// STS endpoint conventions: one trailing `/` is removed, and userinfo, query
/// strings, fragments, backslashes, whitespace, control characters, and dot
/// segments are rejected. Errors never include the raw endpoint.
fn checked_endpoint(value: &str) -> Result<String> {
    let invalid = || {
        Error::config_invalid(
            "Koofr endpoint must be an absolute HTTP(S) URI with a host, optional port, and optional path prefix; userinfo, query, fragment, backslash, whitespace, control characters, and dot segments are not allowed",
        )
    };

    if value.is_empty()
        || value.contains('#')
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(invalid());
    }

    let uri: http::Uri = value.parse().map_err(|_| invalid())?;
    let scheme = uri.scheme_str().ok_or_else(invalid)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid());
    }

    let authority = uri.authority().ok_or_else(invalid)?;
    if authority.host().is_empty() || authority.as_str().contains('@') {
        return Err(invalid());
    }

    // Anything after the host is a port: ASCII digits only, no leading zero,
    // and in 1..=65535. `Authority::port()` alone ignores non-numeric values.
    if authority.as_str() != authority.host() {
        let port = authority
            .as_str()
            .strip_prefix(authority.host())
            .and_then(|rest| rest.strip_prefix(':'))
            .ok_or_else(invalid)?;
        if port.is_empty()
            || port.starts_with('0')
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || !port.parse::<u16>().is_ok_and(|port| port != 0)
        {
            return Err(invalid());
        }
    }

    if uri.query().is_some() || uri.path().split('/').any(is_dot_segment) {
        return Err(invalid());
    }

    let prefix = uri.path().strip_suffix('/').unwrap_or(uri.path());
    Ok(format!(
        "{}://{}{prefix}",
        scheme.to_ascii_lowercase(),
        authority.as_str()
    ))
}

fn is_dot_segment(segment: &str) -> bool {
    let segment = segment.to_ascii_lowercase().replace("%2e", ".");
    segment == "." || segment == ".."
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_arch = "wasm32"))]
    use std::collections::VecDeque;
    #[cfg(not(target_arch = "wasm32"))]
    use std::error::Error as StdError;
    #[cfg(not(target_arch = "wasm32"))]
    use std::sync::{Arc, Mutex};

    #[cfg(not(target_arch = "wasm32"))]
    use bytes::Bytes;
    #[cfg(not(target_arch = "wasm32"))]
    use reqsign_core::HttpSend;

    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    type MockResult = std::result::Result<http::Response<Bytes>, Error>;

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Debug, Clone, Default)]
    struct MockHttp {
        responses: Arc<Mutex<VecDeque<MockResult>>>,
        requests: Arc<Mutex<Vec<http::Request<Bytes>>>>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl MockHttp {
        fn with_response(response: http::Response<Bytes>) -> Self {
            let mock = Self::default();
            mock.responses.lock().expect("lock").push_back(Ok(response));
            mock
        }

        fn with_error(error: Error) -> Self {
            let mock = Self::default();
            mock.responses.lock().expect("lock").push_back(Err(error));
            mock
        }

        fn requests(&self) -> Vec<http::Request<Bytes>> {
            self.requests.lock().expect("lock").clone()
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl HttpSend for MockHttp {
        async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.requests.lock().expect("lock").push(request);
            self.responses
                .lock()
                .expect("lock")
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock HTTP queue is empty"))?
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn json_response(status: u16, body: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::copy_from_slice(body.as_bytes()))
            .expect("response must build")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn test_context(mock: MockHttp) -> Context {
        Context::new().with_http_send(mock)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn rendered_error(error: &Error) -> String {
        let mut rendered = format!("{error} {error:?}");
        let mut source = StdError::source(error);
        while let Some(error) = source {
            rendered.push_str(&format!(" {error} {error:?}"));
            source = StdError::source(error);
        }
        rendered
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn provider(endpoint: &str) -> LoginCredentialProvider {
        LoginCredentialProvider::new("me@example.com", "fabricated-app-password")
            .with_endpoint(endpoint)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn exchanges_first_party_sdk_json_body_for_token() -> Result<()> {
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

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn accepts_capitalized_token_field_from_first_party_sdk_shape() -> Result<()> {
        let mock = MockHttp::with_response(json_response(200, r#"{"Token":"fabricated-token"}"#));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let credential = provider.provide_credential(&ctx).await?.expect("token");

        assert_eq!("fabricated-token", credential.token());

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn preserves_explicit_http_base_prefix_and_port() -> Result<()> {
        for (endpoint, expected) in [
            (
                "https://koofr.example.com:8443/base/",
                "https://koofr.example.com:8443/base/token",
            ),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/token"),
        ] {
            let mock =
                MockHttp::with_response(json_response(200, r#"{"token":"fabricated-token"}"#));
            let ctx = test_context(mock.clone());

            provider(endpoint)
                .provide_credential(&ctx)
                .await?
                .expect("token");

            assert_eq!(expected, mock.requests()[0].uri().to_string());
        }

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn rejects_invalid_endpoint_before_transport() {
        for endpoint in [
            "",
            "app.koofr.net",
            "https://",
            "https:///path",
            "ftp://koofr.example.com",
            "file:///tmp/koofr",
            "https://fabricated-user-marker:fabricated-password-marker@koofr.example.com",
            "https://koofr.example.com?x=1",
            "https://koofr.example.com#fragment",
            "https://koofr.example.com\\path",
            "https://koofr.example.com/../token",
            "https://koofr.example.com/%2e%2e/token",
            "https://koofr.example.com:0",
            "https://koofr.example.com:65536",
            "https://koofr.example.com:0443",
            "https://koofr.example.com:+443",
            "https://koofr.example.com:abc",
            "https://koofr.example.com/a b",
            " https://koofr.example.com",
            "https://koofr.example.com/\n",
            "https://koofr.example.com/a\nb",
        ] {
            let mock = MockHttp::default();
            let ctx = test_context(mock.clone());

            let error = provider(endpoint)
                .provide_credential(&ctx)
                .await
                .expect_err("endpoint must be rejected");

            assert_eq!(
                reqsign_core::ErrorKind::ConfigInvalid,
                error.kind(),
                "endpoint must be rejected: {endpoint:?}"
            );
            assert!(mock.requests().is_empty());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn endpoint_validation_error_omits_raw_endpoint() {
        let mock = MockHttp::default();
        let ctx = test_context(mock);

        let error = provider(
            "https://fabricated-user-marker:fabricated-password-marker@koofr.example.com?fabricated-query-marker",
        )
        .provide_credential(&ctx)
        .await
        .expect_err("endpoint must be rejected");
        let rendered = rendered_error(&error);

        assert_eq!(reqsign_core::ErrorKind::ConfigInvalid, error.kind());
        assert!(!rendered.contains("fabricated-user-marker"));
        assert!(!rendered.contains("fabricated-password-marker"));
        assert!(!rendered.contains("fabricated-query-marker"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn rejects_incomplete_configuration_before_http() {
        for provider in [
            LoginCredentialProvider::new("", "fabricated-app-password"),
            LoginCredentialProvider::new("me@example.com", ""),
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

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn rejects_empty_or_malformed_token_response() {
        for body in [
            r#"{"token":""}"#,
            r#"{"token":"fabricated bad token"}"#,
            r#"{"token":"fabricated\ttoken"}"#,
        ] {
            let mock = MockHttp::with_response(json_response(200, body));
            let ctx = test_context(mock);

            let provider =
                LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
            let error = provider
                .provide_credential(&ctx)
                .await
                .expect_err("malformed token must be rejected");

            assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn malformed_response_does_not_echo_body_or_parser_source() {
        let mock = MockHttp::with_response(json_response(200, r#""fabricated-response-marker""#));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("wrong JSON shape must fail");
        let rendered = rendered_error(&error);

        assert_eq!(reqsign_core::ErrorKind::Unexpected, error.kind());
        assert!(!rendered.contains("fabricated-response-marker"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn error_response_drops_free_form_server_fields() {
        let mock = MockHttp::with_response(json_response(
            401,
            r#"{"error":{"code":"fabricated-code-marker","message":"fabricated-message-marker"},"requestId":"fabricated-request-marker"}"#,
        ));
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("401 must fail");
        let rendered = rendered_error(&error);

        assert_eq!(reqsign_core::ErrorKind::PermissionDenied, error.kind());
        assert!(!rendered.contains("fabricated-code-marker"));
        assert!(!rendered.contains("fabricated-message-marker"));
        assert!(!rendered.contains("fabricated-request-marker"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn transport_error_keeps_kind_and_retryability_without_leaking() {
        let transport_error = Error::unexpected("fabricated-transport-marker")
            .with_context("fabricated-context-marker")
            .with_source(std::io::Error::other("fabricated-source-marker"))
            .set_retryable(true);
        let mock = MockHttp::with_error(transport_error);
        let ctx = test_context(mock);

        let provider = LoginCredentialProvider::new("me@example.com", "fabricated-app-password");
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("transport error must fail");
        let rendered = rendered_error(&error);

        assert_eq!(reqsign_core::ErrorKind::Unexpected, error.kind());
        assert!(error.is_retryable());
        assert!(!rendered.contains("fabricated-transport-marker"));
        assert!(!rendered.contains("fabricated-context-marker"));
        assert!(!rendered.contains("fabricated-source-marker"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn unicode_application_secret_debug_and_wire_encoding() -> Result<()> {
        let app_password = "密码 é 🚀";
        let mock = MockHttp::with_response(json_response(200, r#"{"token":"fabricated-token"}"#));
        let ctx = test_context(mock.clone());
        let provider = LoginCredentialProvider::new("me@example.com", app_password)
            .with_endpoint("https://koofr.example.com/base");

        let debug = format!("{provider:?}");
        assert!(!debug.contains(app_password));
        assert!(!debug.contains("koofr.example.com"));
        assert!(!debug.contains("me@example.com"));

        provider.provide_credential(&ctx).await?.expect("token");

        let body: serde_json::Value =
            serde_json::from_slice(mock.requests()[0].body()).expect("request body must be JSON");
        assert_eq!(Some(app_password), body["password"].as_str());

        Ok(())
    }

    #[test]
    fn debug_omits_arbitrary_login_strings_and_endpoint() {
        let provider = LoginCredentialProvider::new(
            "fabricated-email-marker",
            "fabricated-application-secret-marker",
        )
        .with_endpoint("https://fabricated-endpoint-marker.example");
        let debug = format!("{provider:?}");

        assert!(!debug.contains("fabricated-email-marker"));
        assert!(!debug.contains("fabricated-application-secret-marker"));
        assert!(!debug.contains("fabricated-endpoint-marker"));
    }
}
