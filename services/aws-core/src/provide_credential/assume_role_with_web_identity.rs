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

use crate::provide_credential::sts_endpoint::resolve_sts_endpoint;
use crate::provide_credential::utils::parse_sts_error;
use crate::{Credential, Profile, SharedConfig};
use bytes::Bytes;
use form_urlencoded::Serializer;
use quick_xml::de;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result, utils::Redact};
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt::{Debug, Formatter};
use std::path::PathBuf;

pub(super) const WEB_IDENTITY_TOKEN_FILE: &str = "web_identity_token_file";

#[derive(Clone)]
struct LoadedSubjectToken {
    token: String,
    expires_at: Option<Timestamp>,
}

impl LoadedSubjectToken {
    fn new(token: impl Into<String>, expires_at: Option<Timestamp>) -> Self {
        Self {
            token: token.into(),
            expires_at,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.token.trim().is_empty() {
            return Err(Error::credential_invalid("subject token is empty"));
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= Timestamp::now())
        {
            return Err(Error::credential_invalid("subject token has expired"));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
enum WebIdentityTokenSource {
    #[default]
    Discover,
    File(PathBuf),
    Direct(LoadedSubjectToken),
}

/// AssumeRoleWithWebIdentityCredentialProvider will load credential via assume role with web identity.
///
/// Role and token settings on the provider take precedence over `AWS_ROLE_ARN` and
/// `AWS_WEB_IDENTITY_TOKEN_FILE`. If those sources do not yield a complete pair, the
/// provider looks for `role_arn` and `web_identity_token_file` together in the selected
/// profile merged from the config and credentials files. Explicit provider settings still
/// apply. A partial environment pair is skipped so the role and token file from the
/// profile stay paired.
///
/// The STS endpoint follows the AWS SDKs' endpoint settings: an endpoint set with
/// [`Self::with_sts_endpoint`], then `AWS_ENDPOINT_URL_STS`, `AWS_ENDPOINT_URL`, the selected
/// profile's `sts` service `endpoint_url` and its global `endpoint_url`, and finally the
/// regional or partition default. The selected profile is the one given to
/// `DefaultCredentialProviderBuilder::with_profile`, else `AWS_PROFILE`, else `default`.
/// When resolving a web identity role through the default provider's profile slot,
/// that slot selects the profile and config file. Endpoint settings are consulted
/// after a role and a subject token are found, and only when the explicit endpoint
/// or the environment does not already decide the endpoint. An endpoint may carry a path
/// prefix: `https://host/prefix` sends the request to `/prefix/`. The global `AWS_ENDPOINT_URL` and profile `endpoint_url`
/// therefore also redirect STS; set `AWS_ENDPOINT_URL_STS` (or the profile's `sts` service
/// endpoint) to send STS elsewhere, or set `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` (or the
/// profile's `ignore_configured_endpoint_urls = true`) to ignore every configured endpoint
/// except the explicit one.
#[derive(Default, Clone)]
pub struct AssumeRoleWithWebIdentityCredentialProvider {
    // Web Identity configuration
    role_arn: Option<String>,
    role_session_name: Option<String>,
    token_source: WebIdentityTokenSource,
    duration_seconds: Option<u32>,
    policy: Option<String>,
    policy_arns: Option<Vec<String>>,

    // STS configuration
    region: Option<String>,
    use_regional_sts_endpoint: Option<bool>,
    sts_endpoint: Option<String>,
    /// Profile for standalone resolution; `None` selects `AWS_PROFILE`, then `default`.
    profile: Option<String>,
}

impl Debug for AssumeRoleWithWebIdentityCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let token_source = match self.token_source {
            WebIdentityTokenSource::Discover => "discovery",
            WebIdentityTokenSource::File(_) => "file",
            WebIdentityTokenSource::Direct(_) => "direct",
        };
        f.debug_struct("AssumeRoleWithWebIdentityCredentialProvider")
            .field("role_arn", &self.role_arn)
            .field("role_session_name", &self.role_session_name)
            .field("token_source", &token_source)
            .field("duration_seconds", &self.duration_seconds)
            .field("policy", &self.policy)
            .field("policy_arns", &self.policy_arns)
            .field("region", &self.region)
            .field("use_regional_sts_endpoint", &self.use_regional_sts_endpoint)
            // Redacted: the setter stores the URL before it is validated, so it may carry
            // credentials or other sensitive values.
            .field(
                "sts_endpoint",
                &self.sts_endpoint.as_ref().map(|_| "<redacted>"),
            )
            .field("profile", &self.profile)
            .finish()
    }
}

impl AssumeRoleWithWebIdentityCredentialProvider {
    /// Create a provider that discovers web identity settings from the environment and shared config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `AssumeRoleWithWebIdentityCredentialProvider` instance with explicit configuration.
    pub fn with_config(role_arn: String, token_file: PathBuf) -> Self {
        Self {
            role_arn: Some(role_arn),
            role_session_name: None,
            token_source: WebIdentityTokenSource::File(token_file),
            duration_seconds: None,
            policy: None,
            policy_arns: None,
            region: None,
            use_regional_sts_endpoint: None,
            sts_endpoint: None,
            profile: None,
        }
    }

    /// Set the role ARN.
    pub fn with_role_arn(mut self, role_arn: impl Into<String>) -> Self {
        self.role_arn = Some(role_arn.into());
        self
    }

    /// Set the web identity token file path.
    ///
    /// This replaces any previously configured subject-token source.
    pub fn with_web_identity_token_file(mut self, token_file: impl Into<PathBuf>) -> Self {
        self.token_source = WebIdentityTokenSource::File(token_file.into());
        self
    }

    /// Set a caller-provided subject token.
    ///
    /// This replaces any previously configured subject-token source.
    pub fn with_subject_token(mut self, subject_token: impl Into<String>) -> Self {
        self.token_source =
            WebIdentityTokenSource::Direct(LoadedSubjectToken::new(subject_token, None));
        self
    }

    /// Set a caller-provided subject token with its absolute source expiration.
    ///
    /// This replaces any previously configured subject-token source.
    pub fn with_subject_token_and_expiration(
        mut self,
        subject_token: impl Into<String>,
        expires_at: Timestamp,
    ) -> Self {
        self.token_source = WebIdentityTokenSource::Direct(LoadedSubjectToken::new(
            subject_token,
            Some(expires_at),
        ));
        self
    }

    /// Set the role session name.
    pub fn with_role_session_name(mut self, name: String) -> Self {
        self.role_session_name = Some(name);
        self
    }

    /// Set the duration in seconds.
    pub fn with_duration_seconds(mut self, seconds: u32) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Set the session policy.
    pub fn with_policy(mut self, policy: String) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the session policy ARNs.
    pub fn with_policy_arns(mut self, policy_arns: Vec<String>) -> Self {
        self.policy_arns = Some(policy_arns);
        self
    }

    /// Set the region.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Use regional STS endpoint.
    pub fn with_regional_sts_endpoint(mut self) -> Self {
        self.use_regional_sts_endpoint = Some(true);
        self
    }

    /// Send the STS request to this endpoint, for example `https://sts.example.com:8443`.
    ///
    /// This takes precedence over every environment and profile endpoint setting, including
    /// `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS`. The URL needs an `https` or `http` scheme and a
    /// host, may carry a path prefix, and has no query.
    ///
    /// An `http://` endpoint sends the web identity token, and receives the temporary
    /// credentials, in cleartext. Use it only on a network you trust to carry them.
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = Some(endpoint.into());
        self
    }

    /// Select the profile for web identity and STS endpoint settings, ahead of `AWS_PROFILE`
    /// and `default`. Set by `DefaultCredentialProviderBuilder::with_profile`.
    pub(crate) fn with_profile(mut self, profile: String) -> Self {
        self.profile = Some(profile);
        self
    }
}

impl AssumeRoleWithWebIdentityCredentialProvider {
    async fn load_subject_token(
        &self,
        ctx: &Context,
        discovered_file: Option<&str>,
    ) -> Result<Option<(LoadedSubjectToken, String)>> {
        let path = match &self.token_source {
            WebIdentityTokenSource::Discover => match discovered_file {
                Some(path) => Cow::Borrowed(path),
                None => return Ok(None),
            },
            WebIdentityTokenSource::File(path) => path.to_string_lossy(),
            WebIdentityTokenSource::Direct(subject_token) => {
                subject_token.validate()?;
                return Ok(Some((
                    subject_token.clone(),
                    "subject_token_source: direct".to_string(),
                )));
            }
        };
        let token = ctx.file_read_as_string(&path).await.map_err(|err| {
            Error::config_invalid("failed to read web identity token file")
                .with_source(err)
                .with_context(format!("file: {path}"))
                .with_context("hint: check if the token file exists and is readable")
        })?;
        let subject_token = LoadedSubjectToken::new(token.trim(), None);
        subject_token.validate()?;
        Ok(Some((subject_token, format!("token_file: {path}"))))
    }

    pub(super) async fn provide_credential_with_config(
        &self,
        ctx: &Context,
        shared: &SharedConfig,
        selected_profile: Option<&Profile>,
    ) -> Result<Option<Credential>> {
        let envs = ctx.env_vars();
        let role_arn = self
            .role_arn
            .as_deref()
            .or_else(|| envs.get("AWS_ROLE_ARN").map(String::as_str));
        let token_file = envs
            .get("AWS_WEB_IDENTITY_TOKEN_FILE")
            .map(String::as_str)
            .filter(|path| !path.is_empty());

        let loaded_profile;
        let profile = if role_arn.is_none()
            || (matches!(self.token_source, WebIdentityTokenSource::Discover)
                && token_file.is_none())
        {
            let profile = match selected_profile {
                Some(profile) => profile,
                None => {
                    loaded_profile = shared.load(ctx).await?;
                    &loaded_profile
                }
            };
            let profile_role = profile.get("role_arn").filter(|value| !value.is_empty());
            let profile_token = profile
                .get(WEB_IDENTITY_TOKEN_FILE)
                .filter(|value| !value.is_empty());
            if profile_role.is_none() || profile_token.is_none() {
                return Ok(None);
            }
            Some(profile)
        } else {
            None
        };
        let (role_arn, token_file) = match profile {
            Some(profile) => (
                self.role_arn.as_deref().or_else(|| profile.get("role_arn")),
                profile.get(WEB_IDENTITY_TOKEN_FILE),
            ),
            None => (role_arn, token_file),
        };

        let Some(role_arn) = role_arn else {
            return Ok(None);
        };
        let Some((subject_token, source_context)) =
            self.load_subject_token(ctx, token_file).await?
        else {
            return Ok(None);
        };

        let region = self
            .region
            .as_deref()
            .or_else(|| envs.get("AWS_REGION").map(String::as_str))
            .or_else(|| profile.and_then(|profile| profile.get("region")));

        // Check if we should use regional STS endpoint
        let use_regional = self.use_regional_sts_endpoint.unwrap_or_else(|| {
            envs.get("AWS_STS_REGIONAL_ENDPOINTS")
                .map(|v| v == "regional")
                .unwrap_or(false)
        });

        let endpoint = resolve_sts_endpoint(
            ctx,
            self.sts_endpoint.as_deref(),
            shared,
            region,
            use_regional,
        )
        .await
        .map_err(|e| e.with_context(format!("role_arn: {role_arn}")))?;

        let session_name = self
            .role_session_name
            .as_deref()
            .or_else(|| envs.get("AWS_ROLE_SESSION_NAME").map(String::as_str))
            .or_else(|| profile.and_then(|profile| profile.get("role_session_name")))
            .unwrap_or("reqsign");

        // Construct request to AWS STS Service.
        let query = {
            let mut serializer = Serializer::new(String::new());
            serializer
                .append_pair("Action", "AssumeRoleWithWebIdentity")
                .append_pair("RoleArn", role_arn)
                .append_pair("WebIdentityToken", &subject_token.token)
                .append_pair("Version", "2011-06-15")
                .append_pair("RoleSessionName", session_name);

            if let Some(duration_seconds) = self.duration_seconds {
                serializer.append_pair("DurationSeconds", &duration_seconds.to_string());
            }
            if let Some(policy) = self.policy.as_deref() {
                serializer.append_pair("Policy", policy);
            }
            if let Some(policy_arns) = self.policy_arns.as_deref() {
                for (idx, arn) in policy_arns.iter().enumerate() {
                    serializer.append_pair(&format!("PolicyArns.member.{}.arn", idx + 1), arn);
                }
            }

            serializer.finish()
        };
        let url = endpoint.url();
        let req = http::request::Request::builder()
            .method("POST")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE.as_str(),
                "application/x-www-form-urlencoded",
            )
            .body(Bytes::from(query))
            .map_err(|e| {
                Error::request_invalid("failed to build STS AssumeRoleWithWebIdentity request")
                    .with_source(e)
                    .with_context(format!("role_arn: {role_arn}"))
                    .with_context(format!("endpoint: {endpoint}"))
            })?;

        let resp = ctx.http_send_as_string(req).await.map_err(|e| {
            Error::unexpected("failed to send AssumeRoleWithWebIdentity request to STS")
                .with_source(e)
                .with_context(format!("role_arn: {role_arn}"))
                .with_context(format!("endpoint: {endpoint}"))
                .set_retryable(true)
        })?;

        let status = resp.status();

        if status != http::StatusCode::OK {
            let content = resp.into_body().replace(&subject_token.token, "[REDACTED]");
            return Err(
                parse_sts_error("AssumeRoleWithWebIdentity", status, &content)
                    .with_context(format!("role_arn: {role_arn}"))
                    .with_context(format!("session_name: {session_name}"))
                    .with_context(source_context),
            );
        }

        let body = resp.into_body();
        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&body).map_err(|e| {
            Error::unexpected("failed to parse STS AssumeRoleWithWebIdentity response")
                .with_source(e)
                .with_context(format!("response_length: {}", body.len()))
                .with_context(format!("role_arn: {role_arn}"))
        })?;
        let resp_cred = resp.result.credentials;

        let cred = Credential {
            access_key_id: resp_cred.access_key_id,
            secret_access_key: resp_cred.secret_access_key,
            session_token: Some(resp_cred.session_token),
            expires_in: Some(resp_cred.expiration.parse().map_err(|e| {
                Error::unexpected("failed to parse web identity credential expiration")
                    .with_source(e)
                    .with_context(format!("expiration_value: {}", resp_cred.expiration))
                    .with_context(format!("role_arn: {role_arn}"))
            })?),
        };

        Ok(Some(cred))
    }
}

impl ProvideCredential for AssumeRoleWithWebIdentityCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let mut shared = SharedConfig::new();
        if let Some(profile) = &self.profile {
            shared = shared.with_profile(profile);
        }
        self.provide_credential_with_config(ctx, &shared, None)
            .await
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

impl Debug for AssumeRoleWithWebIdentityCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleWithWebIdentityCredentials")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("secret_access_key", &Redact::from(&self.secret_access_key))
            .field("session_token", &Redact::from(&self.session_token))
            .field("expiration", &self.expiration)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::{FileRead, HttpSend, StaticEnv};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }

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

    #[derive(Clone, Debug)]
    struct CaptureHttpSend {
        uri: Arc<Mutex<Option<String>>>,
        method: Arc<Mutex<Option<http::Method>>>,
        request_body: Arc<Mutex<Option<String>>>,
        status: http::StatusCode,
        body: String,
    }

    impl CaptureHttpSend {
        fn new(body: impl Into<String>) -> Self {
            Self {
                uri: Arc::new(Mutex::new(None)),
                method: Arc::new(Mutex::new(None)),
                request_body: Arc::new(Mutex::new(None)),
                status: http::StatusCode::OK,
                body: body.into(),
            }
        }

        fn with_status(status: http::StatusCode, body: impl Into<String>) -> Self {
            Self {
                status,
                ..Self::new(body)
            }
        }

        fn uri(&self) -> Option<String> {
            self.uri.lock().unwrap().clone()
        }

        fn method(&self) -> Option<http::Method> {
            self.method.lock().unwrap().clone()
        }

        fn request_body(&self) -> Option<String> {
            self.request_body.lock().unwrap().clone()
        }
    }
    impl HttpSend for CaptureHttpSend {
        async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            *self.uri.lock().unwrap() = Some(req.uri().to_string());
            *self.method.lock().unwrap() = Some(req.method().clone());
            *self.request_body.lock().unwrap() =
                Some(String::from_utf8_lossy(req.body()).into_owned());
            let resp = http::Response::builder()
                .status(self.status)
                .header("x-amzn-requestid", "test-request")
                .body(Bytes::from(self.body.clone()))
                .expect("response must build");
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_assume_role_with_web_identity_encodes_query_parameters() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let token_path = "/mock/token";
        let raw_token = "header.payload+signature/\n";
        let trimmed_token = "header.payload+signature/";

        let file_read = TestFileRead {
            expected_path: token_path.to_string(),
            content: raw_token.as_bytes().to_vec(),
        };

        let http_body = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2124-05-25T11:45:17Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;
        let http_send = CaptureHttpSend::new(http_body);

        let ctx = crate::test_context()
            .with_file_read(file_read)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let provider = AssumeRoleWithWebIdentityCredentialProvider::with_config(
            "arn:aws:iam::123456789012:role/test-role".to_string(),
            token_path.into(),
        );

        let cred = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        assert_eq!(cred.access_key_id, "access_key_id");
        assert_eq!(cred.secret_access_key, "secret_access_key");
        assert_eq!(
            cred.session_token.as_deref(),
            Some("session_token"),
            "session token must be populated"
        );

        let recorded_uri = http_send
            .uri()
            .expect("http_send must capture outgoing uri");
        let expected_query = Serializer::new(String::new())
            .append_pair("Action", "AssumeRoleWithWebIdentity")
            .append_pair("RoleArn", "arn:aws:iam::123456789012:role/test-role")
            .append_pair("WebIdentityToken", trimmed_token)
            .append_pair("Version", "2011-06-15")
            .append_pair("RoleSessionName", "reqsign")
            .finish();
        assert_eq!(recorded_uri, "https://sts.amazonaws.com/");
        assert_eq!(http_send.method(), Some(http::Method::POST));
        assert_eq!(
            http_send.request_body().as_deref(),
            Some(expected_query.as_str())
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_assume_role_with_web_identity_supports_policy_and_policy_arns() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let token_path = "/mock/token";
        let raw_token = "header.payload+signature/\n";

        let file_read = TestFileRead {
            expected_path: token_path.to_string(),
            content: raw_token.as_bytes().to_vec(),
        };

        let http_body = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2124-05-25T11:45:17Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;
        let http_send = CaptureHttpSend::new(http_body);

        let ctx = crate::test_context()
            .with_file_read(file_read)
            .with_http_send(http_send.clone())
            .with_env(StaticEnv {
                home_dir: None,
                envs: HashMap::new(),
            });

        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringEquals":{"s3:prefix":"a b"}}}]}"#;

        let provider = AssumeRoleWithWebIdentityCredentialProvider::with_config(
            "arn:aws:iam::123456789012:role/test-role".to_string(),
            token_path.into(),
        )
        .with_duration_seconds(900)
        .with_policy(policy.to_string())
        .with_policy_arns(vec![
            "arn:aws:iam::aws:policy/ReadOnlyAccess".to_string(),
            "arn:aws:iam::123456789012:policy/ExamplePolicy".to_string(),
        ]);

        let _ = provider
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");

        let recorded_body = http_send
            .request_body()
            .expect("http_send must capture outgoing body");

        assert!(recorded_body.contains("DurationSeconds=900"));
        assert!(
            recorded_body.contains("Policy=%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AListBucket%22%2C%22Resource%22%3A%22*%22%2C%22Condition%22%3A%7B%22StringEquals%22%3A%7B%22s3%3Aprefix%22%3A%22a+b%22%7D%7D%7D%5D%7D")
        );
        assert!(recorded_body.contains(
            "PolicyArns.member.1.arn=arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FReadOnlyAccess"
        ));
        assert!(recorded_body.contains(
            "PolicyArns.member.2.arn=arn%3Aaws%3Aiam%3A%3A123456789012%3Apolicy%2FExamplePolicy"
        ));

        Ok(())
    }

    #[tokio::test]
    async fn caller_provided_subject_tokens_are_isolated_and_use_post_body() -> Result<()> {
        let response = r#"<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2124-05-25T11:45:17Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;
        let http_send = CaptureHttpSend::new(response);
        let ctx = crate::test_context().with_http_send(http_send.clone());

        let first = AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_role_arn("arn:aws:iam::123456789012:role/test-role")
            .with_web_identity_token_file("/must-not-be-read")
            .with_subject_token("first.subject.token");
        first
            .provide_credential(&ctx)
            .await?
            .expect("first credential must load");
        let first_body = http_send
            .request_body()
            .expect("first body must be captured");

        let second = AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_role_arn("arn:aws:iam::123456789012:role/test-role")
            .with_subject_token("second.subject.token");
        second
            .provide_credential(&ctx)
            .await?
            .expect("second credential must load");
        let second_body = http_send
            .request_body()
            .expect("second body must be captured");

        assert!(first_body.contains("WebIdentityToken=first.subject.token"));
        assert!(!first_body.contains("second.subject.token"));
        assert!(second_body.contains("WebIdentityToken=second.subject.token"));
        assert!(!second_body.contains("first.subject.token"));
        assert_eq!(
            http_send.uri().as_deref(),
            Some("https://sts.amazonaws.com/")
        );
        assert_eq!(http_send.method(), Some(http::Method::POST));
        assert!(!format!("{first:?}").contains("first.subject.token"));
        Ok(())
    }

    #[tokio::test]
    async fn sts_endpoint_follows_explicit_and_environment_settings() -> Result<()> {
        let http_body = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2124-05-25T11:45:17Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;
        let provider = || {
            AssumeRoleWithWebIdentityCredentialProvider::new()
                .with_role_arn("arn:aws:iam::123456789012:role/test-role")
                .with_subject_token("subject-token")
        };
        let ctx = |envs: &[(&str, &str)], http: CaptureHttpSend| {
            crate::test_context()
                .with_http_send(http)
                .with_env(StaticEnv {
                    home_dir: None,
                    envs: envs
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                })
        };

        let http = CaptureHttpSend::new(http_body);
        provider()
            .provide_credential(&ctx(
                &[("AWS_ENDPOINT_URL_STS", "http://sts.internal:8333")],
                http.clone(),
            ))
            .await?
            .expect("credential must be loaded");
        assert_eq!(http.uri().as_deref(), Some("http://sts.internal:8333/"));

        let http = CaptureHttpSend::new(http_body);
        provider()
            .with_sts_endpoint("https://sts.example.com:8443")
            .provide_credential(&ctx(
                &[
                    ("AWS_ENDPOINT_URL_STS", "http://sts.internal:8333"),
                    ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"),
                ],
                http.clone(),
            ))
            .await?
            .expect("credential must be loaded");
        assert_eq!(http.uri().as_deref(), Some("https://sts.example.com:8443/"));

        let http = CaptureHttpSend::new(http_body);
        provider()
            .provide_credential(&ctx(
                &[
                    ("AWS_ENDPOINT_URL", "http://sts.internal:8333"),
                    ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"),
                ],
                http.clone(),
            ))
            .await?
            .expect("credential must be loaded");
        assert_eq!(http.uri().as_deref(), Some("https://sts.amazonaws.com/"));

        let http = CaptureHttpSend::new(http_body);
        provider()
            .with_sts_endpoint("https://gateway.example.com:8443/sts")
            .provide_credential(&ctx(&[], http.clone()))
            .await?
            .expect("credential must be loaded");
        assert_eq!(
            http.uri().as_deref(),
            Some("https://gateway.example.com:8443/sts/"),
            "the path prefix joins the STS operation path"
        );

        let http = CaptureHttpSend::new(http_body);
        provider()
            .with_sts_endpoint("https://gateway.example.com:8443/sts//")
            .provide_credential(&ctx(&[], http.clone()))
            .await?
            .expect("credential must be loaded");
        assert_eq!(
            http.uri().as_deref(),
            Some("https://gateway.example.com:8443/sts//"),
            "repeated trailing slashes keep all but one, as in Smithy"
        );

        Ok(())
    }

    #[test]
    fn debug_redacts_the_explicit_sts_endpoint() {
        let provider = AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_sts_endpoint("https://user:secret-token@sts.example.com:notaport");
        let debug = format!("{provider:?}");
        assert!(!debug.contains("secret-token"), "{debug}");
        assert!(
            debug.contains("sts_endpoint: Some(\"<redacted>\")"),
            "{debug}"
        );
    }

    #[tokio::test]
    async fn the_selected_profile_supplies_the_sts_endpoint() -> Result<()> {
        #[derive(Debug)]
        struct Config;
        impl FileRead for Config {
            async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
                assert_eq!(path, "/home/test/.aws/config");
                Ok(b"[profile ambient]\nendpoint_url = https://ambient.example.com\n\n[profile prod]\nservices = prod-services\n\n[services prod-services]\nsts =\n  endpoint_url = http://sts.prod.internal:8333/prefix\n".to_vec())
            }
        }
        let http_body = r#"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>a</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2124-05-25T11:45:17Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#;
        let http = CaptureHttpSend::new(http_body);
        let ctx = crate::test_context()
            .with_file_read(Config)
            .with_http_send(http.clone())
            .with_env(StaticEnv {
                home_dir: Some(PathBuf::from("/home/test")),
                envs: HashMap::from([("AWS_PROFILE".to_string(), "ambient".to_string())]),
            });

        AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_role_arn("arn:aws:iam::123456789012:role/test-role")
            .with_subject_token("subject-token")
            .with_profile("prod".to_string())
            .provide_credential(&ctx)
            .await?
            .expect("credential must be loaded");
        assert_eq!(
            http.uri().as_deref(),
            Some("http://sts.prod.internal:8333/prefix/")
        );
        Ok(())
    }

    #[tokio::test]
    async fn without_a_role_and_token_no_endpoint_configuration_is_read() -> Result<()> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug, Default)]
        struct Config(AtomicUsize);
        impl FileRead for Config {
            async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
                if path == "/home/test/.aws/credentials" {
                    return Err(Error::unexpected("credentials file not found"));
                }
                assert_eq!(path, "/home/test/.aws/config");
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(b"[profile prod]\nendpoint_url = https://unused.example.test\n".to_vec())
            }
        }
        let config = Arc::new(Config::default());
        let ctx = crate::test_context()
            .with_file_read(config.clone())
            .with_env(StaticEnv {
                home_dir: Some(PathBuf::from("/home/test")),
                envs: HashMap::new(),
            });
        let loaded = AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_profile("prod".to_string())
            .provide_credential(&ctx)
            .await?;
        assert!(loaded.is_none());
        // The first read discovers role and token settings. Endpoint lookup is skipped.
        assert_eq!(config.0.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn expired_subject_token_is_rejected_before_http() {
        let http_send = CaptureHttpSend::new("unused");
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let provider = AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_role_arn("arn:aws:iam::123456789012:role/test-role")
            .with_subject_token_and_expiration(
                "expired.subject.token",
                Timestamp::now() - std::time::Duration::from_secs(1),
            );

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("expired token must fail");
        assert_eq!(err.kind(), reqsign_core::ErrorKind::CredentialInvalid);
        assert!(http_send.uri().is_none());
    }

    #[tokio::test]
    async fn sts_error_cannot_echo_subject_token() {
        let secret = "echoed.subject.token";
        let response = format!(
            "<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>{secret}</Message></Error></ErrorResponse>"
        );
        let http_send = CaptureHttpSend::with_status(http::StatusCode::BAD_REQUEST, response);
        let ctx = crate::test_context().with_http_send(http_send);
        let provider = AssumeRoleWithWebIdentityCredentialProvider::new()
            .with_role_arn("arn:aws:iam::123456789012:role/test-role")
            .with_subject_token(secret);

        let err = provider
            .provide_credential(&ctx)
            .await
            .expect_err("STS error must be returned");
        assert!(!err.to_string().contains(secret));
        assert!(!format!("{err:?}").contains(secret));
    }
}
