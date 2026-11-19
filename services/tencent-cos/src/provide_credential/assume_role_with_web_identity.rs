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
use crate::constants::*;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use log::debug;
use reqsign_core::Result;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential};
use serde::{Deserialize, Serialize};

/// Loader that loads credential via AssumeRoleWithWebIdentity.
#[derive(Debug, Default, Clone)]
pub struct AssumeRoleWithWebIdentityCredentialProvider {}

impl AssumeRoleWithWebIdentityCredentialProvider {
    /// Create a new AssumeRoleWithWebIdentityCredentialProvider
    pub fn new() -> Self {
        Self {}
    }
}
impl ProvideCredential for AssumeRoleWithWebIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        // Read environment variables at runtime
        let region = ctx
            .env_var(TENCENTCLOUD_REGION)
            .or_else(|| ctx.env_var(TKE_REGION));
        let token_file = ctx
            .env_var(TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE)
            .or_else(|| ctx.env_var(TKE_IDENTITY_TOKEN_FILE));
        let role_arn = ctx
            .env_var(TENCENTCLOUD_ROLE_ARN)
            .or_else(|| ctx.env_var(TKE_ROLE_ARN));
        let provider_id = ctx
            .env_var(TENCENTCLOUD_PROVIDER_ID)
            .or_else(|| ctx.env_var(TKE_PROVIDER_ID));
        let role_session_name = ctx
            .env_var(TENCENTCLOUD_ROLE_SESSSION_NAME)
            .or_else(|| ctx.env_var(TKE_ROLE_SESSSION_NAME))
            .unwrap_or_else(|| "reqsign".to_string());

        let (region, token_file, role_arn, provider_id) = match (
            region,
            token_file,
            role_arn,
            provider_id,
        ) {
            (Some(region), Some(token_file), Some(role_arn), Some(provider_id)) => {
                (region, token_file, role_arn, provider_id)
            }
            (region, token_file, role_arn, provider_id) => {
                let missing = [
                    ("region", region.is_none()),
                    ("web_identity_token_file", token_file.is_none()),
                    ("role_arn", role_arn.is_none()),
                    ("provider_id", provider_id.is_none()),
                ]
                .iter()
                .filter_map(|&(k, v)| if v { Some(k) } else { None })
                .collect::<Vec<_>>()
                .join(", ");

                debug!(
                    "assume_role_with_web_identity is not configured fully: [{missing}] is missing"
                );

                return Ok(None);
            }
        };

        let token = ctx.file_read_as_string(&token_file).await?;

        // Construct request to Tencent Cloud STS Service.
        let url = "https://sts.tencentcloudapi.com";
        let bs = serde_json::to_vec(&AssumeRoleWithWebIdentityRequest {
            role_session_name,
            web_identity_token: token,
            role_arn: role_arn.clone(),
            provider_id: provider_id.clone(),
        })
        .map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to serialize request: {e}"))
        })?;

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(AUTHORIZATION.as_str(), "SKIP")
            .header(CONTENT_TYPE.as_str(), "application/json")
            .header(CONTENT_LENGTH, bs.len())
            .header("X-TC-Action", "AssumeRoleWithWebIdentity")
            .header("X-TC-Region", &region)
            .header("X-TC-Timestamp", Timestamp::now().as_second())
            .header("X-TC-Version", "2018-08-13")
            .body(bs.into())?;

        let resp = ctx.http_send(req).await?;
        let status = resp.status();
        let body = resp.into_body();

        if status != http::StatusCode::OK {
            return Err(reqsign_core::Error::unexpected(format!(
                "request to Tencent Cloud STS Services failed: {}",
                String::from_utf8_lossy(&body)
            )));
        }

        let resp: AssumeRoleWithWebIdentityResult = serde_json::from_slice(&body).map_err(|e| {
            reqsign_core::Error::unexpected(format!("Failed to parse STS response: {e}"))
        })?;
        if let Some(error) = resp.response.error {
            return Err(reqsign_core::Error::unexpected(format!(
                "request to Tencent Cloud STS Services failed: {error:?}"
            )));
        }
        let resp_expiration = resp.response.expiration;
        let resp_cred = resp.response.credentials;

        let cred = Credential {
            secret_id: resp_cred.tmp_secret_id,
            secret_key: resp_cred.tmp_secret_key,
            security_token: Some(resp_cred.token),
            expires_in: Some(resp_expiration.parse()?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityRequest {
    role_session_name: String,
    web_identity_token: String,
    role_arn: String,
    provider_id: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    response: AssumeRoleWithWebIdentityResponse,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    error: Option<AssumeRoleWithWebIdentityError>,
    expiration: String,
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    token: String,
    tmp_secret_id: String,
    tmp_secret_key: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityError {
    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use reqsign_core::{FileRead, HttpSend, StaticEnv};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct TestFileRead {
        expected_path: String,
        content: Vec<u8>,
    }

    impl FileRead for TestFileRead {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            assert_eq!(path, self.expected_path);
            Ok(self.content.clone())
        }
    }

    #[derive(Clone)]
    struct CaptureHttpSend {
        requests: Arc<Mutex<Vec<http::Request<Bytes>>>>,
        response_body: String,
    }

    impl CaptureHttpSend {
        fn new(response_body: impl Into<String>) -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                response_body: response_body.into(),
            }
        }

        fn requests(&self) -> Vec<http::Request<Bytes>> {
            self.requests.lock().expect("lock poisoned").clone()
        }
    }

    impl std::fmt::Debug for CaptureHttpSend {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CaptureHttpSend").finish_non_exhaustive()
        }
    }

    impl HttpSend for CaptureHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.requests.lock().expect("lock poisoned").push(req);
            Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(Bytes::from(self.response_body.clone()))
                .expect("response must build"))
        }
    }

    // Exercises the full provider path with a synthetic token and STS fixture, without network
    // access or cloud credentials.
    #[tokio::test]
    async fn test_assume_role_with_web_identity_uses_config_and_decodes_credentials() -> Result<()>
    {
        let token_path = "/mock/tencent-web-identity-token";
        let token = "synthetic-tencent-web-identity-token";
        let role_arn = "qcs::cam::uin/123456789:roleName/reqsign-test";
        let provider_id = "123456789";
        let role_session_name = "reqsign-test-session";
        let expiration = "2030-01-02T03:04:05Z";

        let http_send = CaptureHttpSend::new(
            r#"{
                "Response": {
                    "Credentials": {
                        "Token": "temporary-security-token",
                        "TmpSecretId": "temporary-secret-id",
                        "TmpSecretKey": "temporary-secret-key"
                    },
                    "Expiration": "2030-01-02T03:04:05Z",
                    "RequestId": "synthetic-request-id"
                }
            }"#,
        );

        let ctx = Context::new()
            .with_file_read(TestFileRead {
                expected_path: token_path.to_string(),
                content: token.as_bytes().to_vec(),
            })
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::from([
                    (TENCENTCLOUD_REGION.to_string(), "ap-shanghai".to_string()),
                    (
                        TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE.to_string(),
                        token_path.to_string(),
                    ),
                    (TENCENTCLOUD_ROLE_ARN.to_string(), role_arn.to_string()),
                    (
                        TENCENTCLOUD_PROVIDER_ID.to_string(),
                        provider_id.to_string(),
                    ),
                    (
                        TENCENTCLOUD_ROLE_SESSSION_NAME.to_string(),
                        role_session_name.to_string(),
                    ),
                ]),
            });

        let credential = AssumeRoleWithWebIdentityCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        let requests = http_send.requests();
        assert_eq!(1, requests.len());
        let request = &requests[0];
        assert_eq!(http::Method::POST, request.method());
        assert_eq!("https://sts.tencentcloudapi.com", request.uri());
        assert_eq!("SKIP", request.headers()[AUTHORIZATION]);
        assert_eq!(
            "AssumeRoleWithWebIdentity",
            request.headers()["X-TC-Action"]
        );
        assert_eq!("ap-shanghai", request.headers()["X-TC-Region"]);
        assert_eq!("2018-08-13", request.headers()["X-TC-Version"]);
        assert_eq!("application/json", request.headers()[CONTENT_TYPE]);

        let body: Value =
            serde_json::from_slice(request.body()).expect("request body must be valid JSON");
        assert_eq!(role_session_name, body["RoleSessionName"]);
        assert_eq!(token, body["WebIdentityToken"]);
        assert_eq!(role_arn, body["RoleArn"]);
        assert_eq!(provider_id, body["ProviderId"]);

        assert_eq!("temporary-secret-id", credential.secret_id);
        assert_eq!("temporary-secret-key", credential.secret_key);
        assert_eq!(
            Some("temporary-security-token"),
            credential.security_token.as_deref()
        );
        let expected_expiration: Timestamp = expiration.parse().expect("expiration must parse");
        assert_eq!(Some(expected_expiration), credential.expires_in);

        Ok(())
    }
}
