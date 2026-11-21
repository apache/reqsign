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

use crate::Credential;
use crate::imds::ImdsClient;
use crate::provide_credential::utils::parse_imds_error;
use bytes::Bytes;
use http::Method;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;

/// Loads credentials from the EC2 instance metadata service.
///
/// IMDSv2 is attempted first. When [`Self::with_imdsv1_fallback`] is enabled,
/// the provider falls back to IMDSv1 only if the token request returns HTTP 403,
/// 404, or 405. Other token, metadata, credential, role, and transport failures
/// are returned without falling back.
#[derive(Debug, Clone, Default)]
pub struct IMDSv2CredentialProvider {
    client: ImdsClient,
    imdsv1_fallback: bool,
}

impl IMDSv2CredentialProvider {
    /// Create a new `IMDSv2CredentialProvider` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the endpoint for the metadata service.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.client = self.client.with_endpoint(endpoint);
        self
    }

    /// Allow fallback to IMDSv1 when the IMDSv2 token request is rejected.
    ///
    /// Fallback is limited to the token endpoint returning HTTP 403, 404, or
    /// 405. IMDSv2 remains the default, and every other failure is returned
    /// unchanged. Enable this only for instances where IMDSv2 is unavailable.
    ///
    /// # Example
    ///
    /// ```
    /// use reqsign_aws_core::IMDSv2CredentialProvider;
    ///
    /// let provider = IMDSv2CredentialProvider::new().with_imdsv1_fallback();
    /// ```
    pub fn with_imdsv1_fallback(mut self) -> Self {
        self.imdsv1_fallback = true;
        self
    }
}

impl ProvideCredential for IMDSv2CredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if crate::imds::disabled(ctx) {
            return Ok(None);
        }

        let token = self
            .client
            .load_ec2_metadata_token(ctx, self.imdsv1_fallback)
            .await?;

        // List all credentials that node has.
        let endpoint = self.client.get_endpoint(ctx);
        let url = format!("{endpoint}/latest/meta-data/iam/security-credentials/");
        let mut builder = http::Request::builder().uri(&url).method(Method::GET);
        if let Some(token) = &token {
            builder = builder.header("x-aws-ec2-metadata-token", token);
        }
        let req = builder.body(Bytes::new()).map_err(|e| {
            Error::request_invalid("failed to build IMDS credentials list request")
                .with_source(e)
                .with_context("url: {url}")
        })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to list IMDS credentials")
                .with_source(e)
                .with_context("operation: list_instance_profiles")
                .set_retryable(true)
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(parse_imds_error(
                "list_instance_profiles",
                resp.status(),
                resp.body(),
            ));
        }

        let profile_name = resp.into_body();

        if profile_name.is_empty() {
            return Err(
                Error::config_invalid("no IAM role attached to EC2 instance")
                    .with_context("hint: attach an IAM role to your EC2 instance"),
            );
        }

        // Get the credentials via role_name.
        let endpoint = self.client.get_endpoint(ctx);
        let url = format!("{endpoint}/latest/meta-data/iam/security-credentials/{profile_name}");
        let mut builder = http::Request::builder().uri(url).method(Method::GET);
        if let Some(token) = &token {
            builder = builder.header("x-aws-ec2-metadata-token", token);
        }
        let req = builder.body(Bytes::new()).map_err(|e| {
            Error::request_invalid("failed to build IMDS credentials fetch request")
                .with_source(e)
                .with_context(format!("profile: {profile_name}"))
        })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to fetch IMDS credentials")
                .with_source(e)
                .with_context(format!("profile: {profile_name}"))
                .set_retryable(true)
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(
                parse_imds_error("fetch_credentials", resp.status(), resp.body())
                    .with_context(format!("profile: {profile_name}")),
            );
        }

        let content = resp.into_body();
        let resp: Ec2MetadataIamSecurityCredentials =
            serde_json::from_str(&content).map_err(|e| {
                Error::unexpected("failed to parse IMDS credentials response")
                    .with_source(e)
                    .with_context(format!("response_length: {}", content.len()))
                    .with_context(format!("profile: {profile_name}"))
            })?;

        // Check for specific error codes
        match resp.code.as_str() {
            "Success" => {} // Continue processing
            "AssumeRoleUnauthorizedAccess" => {
                return Err(Error::permission_denied(format!(
                    "EC2 instance not authorized to assume role: {}",
                    resp.message
                ))
                .with_context(format!("error_code: {}", resp.code))
                .with_context(format!("profile: {profile_name}"))
                .with_context("hint: check if the IAM role has a trust relationship with EC2"));
            }
            code if code.contains("Expired") => {
                return Err(Error::credential_invalid(format!(
                    "IMDS credentials expired: {}",
                    resp.message
                ))
                .with_context(format!("error_code: {}", resp.code))
                .with_context(format!("profile: {profile_name}")));
            }
            _ => {
                return Err(Error::unexpected(format!(
                    "IMDS returned error: [{}] {}",
                    resp.code, resp.message
                ))
                .with_context(format!("profile: {profile_name}")));
            }
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(resp.expiration.parse().map_err(|e| {
                Error::unexpected("failed to parse IMDS credential expiration time")
                    .with_source(e)
                    .with_context(format!("expiration_value: {}", resp.expiration))
            })?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Ec2MetadataIamSecurityCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,

    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{ErrorKind, HttpSend, StaticEnv};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    const MOCK_TOKEN: &str = "mock-imdsv2-token";
    const MOCK_CREDENTIALS: &str = r#"{
        "Code": "Success",
        "AccessKeyId": "AKIAIMDSEXAMPLE",
        "SecretAccessKey": "imds-secret-key",
        "Token": "imds-session-token",
        "Expiration": "2126-01-01T00:00:00Z"
    }"#;

    #[derive(Clone, Debug)]
    struct MockRequest {
        method: http::Method,
        token: Option<String>,
    }

    #[derive(Clone, Debug)]
    struct MockHttpSend {
        responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
        requests: Arc<Mutex<Vec<MockRequest>>>,
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn requests(&self) -> Vec<MockRequest> {
            self.requests.lock().expect("lock poisoned").clone()
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            let token = req.headers().get("x-aws-ec2-metadata-token").map(|value| {
                value
                    .to_str()
                    .expect("IMDS token header must be valid UTF-8")
                    .to_string()
            });
            self.requests
                .lock()
                .expect("lock poisoned")
                .push(MockRequest {
                    method: req.method().clone(),
                    token,
                });
            let response = self
                .responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .expect("mock HTTP request has no scripted response");
            Ok(response)
        }
    }

    fn http_response(status: http::StatusCode, body: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(Bytes::copy_from_slice(body.as_bytes()))
            .expect("response must build")
    }

    fn token_response() -> http::Response<Bytes> {
        http_response(http::StatusCode::OK, MOCK_TOKEN)
    }

    fn role_response() -> http::Response<Bytes> {
        http_response(http::StatusCode::OK, "test-role")
    }

    fn credentials_response() -> http::Response<Bytes> {
        http_response(http::StatusCode::OK, MOCK_CREDENTIALS)
    }

    fn credential_context(http: &MockHttpSend) -> Context {
        Context::new().with_http_send(http.clone())
    }

    #[tokio::test]
    async fn imdsv1_fallback_is_disabled_by_default() {
        let http = MockHttpSend::new([http_response(http::StatusCode::FORBIDDEN, "")]);
        let ctx = credential_context(&http);

        let error = IMDSv2CredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect_err("default IMDS provider must not fall back");

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(http.requests().len(), 1);
    }

    #[tokio::test]
    async fn imdsv2_is_used_when_available() {
        let http = MockHttpSend::new([token_response(), role_response(), credentials_response()]);
        let ctx = credential_context(&http);

        let credential = IMDSv2CredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect("IMDSv2 request must succeed")
            .expect("IMDSv2 must return a credential");

        assert_eq!(credential.access_key_id, "AKIAIMDSEXAMPLE");
        assert_eq!(credential.secret_access_key, "imds-secret-key");
        assert_eq!(
            credential.session_token.as_deref(),
            Some("imds-session-token")
        );

        let requests = http.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, http::Method::PUT);
        assert_eq!(requests[0].token, None);
        assert_eq!(requests[1].method, http::Method::GET);
        assert_eq!(requests[1].token.as_deref(), Some(MOCK_TOKEN));
        assert_eq!(requests[2].method, http::Method::GET);
        assert_eq!(requests[2].token.as_deref(), Some(MOCK_TOKEN));
    }

    #[tokio::test]
    async fn imdsv1_fallback_covers_unsupported_token_endpoints() {
        for status in [
            http::StatusCode::FORBIDDEN,
            http::StatusCode::NOT_FOUND,
            http::StatusCode::METHOD_NOT_ALLOWED,
        ] {
            let http = MockHttpSend::new([
                http_response(status, ""),
                role_response(),
                credentials_response(),
            ]);
            let ctx = credential_context(&http);

            let credential = IMDSv2CredentialProvider::new()
                .with_imdsv1_fallback()
                .provide_credential(&ctx)
                .await
                .unwrap_or_else(|error| panic!("fallback for {status} failed: {error:?}"))
                .expect("IMDSv1 must return a credential");

            assert_eq!(credential.access_key_id, "AKIAIMDSEXAMPLE");
            let requests = http.requests();
            assert_eq!(requests.len(), 3, "status {status}");
            assert_eq!(requests[1].token, None, "status {status}");
            assert_eq!(requests[2].token, None, "status {status}");
        }
    }

    #[tokio::test]
    async fn imdsv1_fallback_does_not_cover_other_token_errors() {
        let cases = [
            (http::StatusCode::BAD_REQUEST, ErrorKind::Unexpected, false),
            (
                http::StatusCode::UNAUTHORIZED,
                ErrorKind::PermissionDenied,
                false,
            ),
            (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                ErrorKind::Unexpected,
                true,
            ),
        ];

        for (status, kind, retryable) in cases {
            let http = MockHttpSend::new([http_response(status, "")]);
            let ctx = credential_context(&http);

            let error = IMDSv2CredentialProvider::new()
                .with_imdsv1_fallback()
                .provide_credential(&ctx)
                .await
                .expect_err("only unsupported token endpoints may fall back");

            assert_eq!(error.kind(), kind, "status {status}");
            assert_eq!(error.is_retryable(), retryable, "status {status}");
            assert_eq!(http.requests().len(), 1, "status {status}");
        }
    }

    #[tokio::test]
    async fn imdsv1_fallback_surfaces_metadata_errors() {
        let http = MockHttpSend::new([
            http_response(http::StatusCode::FORBIDDEN, ""),
            http_response(http::StatusCode::FORBIDDEN, ""),
        ]);
        let ctx = credential_context(&http);

        let error = IMDSv2CredentialProvider::new()
            .with_imdsv1_fallback()
            .provide_credential(&ctx)
            .await
            .expect_err("metadata failures must be returned");

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(http.requests().len(), 2);
    }

    #[tokio::test]
    async fn metadata_disabled_overrides_imdsv1_fallback() {
        let http = MockHttpSend::new([]);
        let ctx = Context::new()
            .with_http_send(http.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([(
                    "AWS_EC2_METADATA_DISABLED".to_string(),
                    "true".to_string(),
                )]),
            });

        let credential = IMDSv2CredentialProvider::new()
            .with_imdsv1_fallback()
            .provide_credential(&ctx)
            .await
            .expect("disabled metadata must not fail");

        assert!(credential.is_none());
        assert!(http.requests().is_empty());
    }
}
