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

//! Tencent Cloud STS `GetFederationToken` credential granting.
//!
//! [`GetFederationTokenGranter`] consumes an existing permanent Tencent Cloud
//! credential and issues a temporary credential under a caller-supplied CAM
//! policy. The returned [`Credential`] can be passed directly to the existing
//! COS [`RequestSigner`](crate::RequestSigner).
//!
//! The protocol follows the Tencent Cloud API 3.0 `GetFederationToken` action:
//! `Name`, `Policy`, and an optional `DurationSeconds` in the JSON request body,
//! signed with `TC3-HMAC-SHA256`. The response's `ExpiredTime` Unix timestamp is
//! used for exact credential expiration. See
//! <https://cloud.tencent.com/document/api/1312/73427>.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use percent_encoding::utf8_percent_encode;
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use serde::{Deserialize, Serialize};

use crate::Credential;
use crate::constants::TENCENT_URI_ENCODE_SET;

const DEFAULT_STS_ENDPOINT: &str = "https://sts.tencentcloudapi.com";
const STS_ACTION: &str = "GetFederationToken";
const STS_VERSION: &str = "2018-08-13";
const STS_SERVICE: &str = "sts";
const STS_REQUEST_HEADROOM: Duration = Duration::from_secs(20);
const MAX_DURATION_SECONDS: u64 = 129_600;

/// A typed, explicitly bound Tencent Cloud STS `GetFederationToken` grant.
///
/// The caller owns the authorization policy. `name` is the caller name returned
/// in the issued temporary identity and must contain ASCII letters only, as
/// required by the API. `policy` is a raw CAM policy document that the service
/// intersects with the source identity's permissions. Reqsign URL-encodes the
/// policy exactly once for the wire field before signing; it does not parse or
/// evaluate the policy. Bind a new grant for each authorization decision.
#[derive(Clone)]
pub struct GetFederationTokenGrant {
    name: String,
    policy: String,
}

impl Debug for GetFederationTokenGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetFederationTokenGrant")
            .field("name", &self.name)
            .field("policy", &"REDACTED")
            .finish()
    }
}

impl GetFederationTokenGrant {
    /// Create a grant with a caller name and a raw CAM policy.
    ///
    /// `name` must contain ASCII letters only. `policy` is preserved verbatim
    /// as the CAM document and URL-encoded once when the request is built. The
    /// host is responsible for the policy's syntax, resources, and permissions.
    pub fn new(name: impl Into<String>, policy: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            policy: policy.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.name.is_empty() || !self.name.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(Error::request_invalid(
                "Tencent Cloud STS GetFederationToken Name must contain ASCII letters only",
            ));
        }
        if self.policy.trim().is_empty() {
            return Err(Error::request_invalid(
                "Tencent Cloud STS GetFederationToken requires a non-empty Policy",
            ));
        }
        Ok(())
    }
}

/// Explicitly grants a Tencent Cloud STS `GetFederationToken` credential.
///
/// The source credential supplied by [`reqsign_core::Granter`] must be a
/// permanent Tencent Cloud credential: it must contain a secret ID and secret
/// key and must not contain a security token or an expiration. The STS API only
/// accepts permanent keys for this action. The source signs the request with
/// `TC3-HMAC-SHA256`; granted credentials are never cached.
///
/// `expires_in` maps to `DurationSeconds`. `None` omits the field and uses the
/// service default of 1800 seconds. A requested lifetime must be a whole number
/// of seconds between 1 and 129600, the documented maximum for a sub-account.
/// The service may apply a lower maximum for a main account.
///
/// Every grant performs a new STS exchange. The returned credential contains the
/// temporary secret ID, secret key, token, and the exact `ExpiredTime` from the
/// response, so it can be consumed directly by [`crate::RequestSigner`].
///
/// The service default of 1800 seconds is shorter than the COS request signer's
/// default 3600-second header-signing lifetime. A credential granted with the
/// default lifetime is therefore rejected by `Signer::sign(..., None)`. Request
/// a longer grant, such as 7200 seconds for a main account, or pass a shorter
/// explicit `expires_in` to the signer. The signer's lifetime checks and default
/// are unchanged.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter};
/// use reqsign_tencent_cos::{
///     GetFederationTokenGrant, GetFederationTokenGranter, StaticCredentialProvider,
/// };
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = StaticCredentialProvider::new("source-secret-id", "source-secret-key");
/// let grant = GetFederationTokenGrant::new(
///     "customer",
///     r#"{"version":"2.0","statement":[{"effect":"allow","action":["cos:GetObject"],"resource":["qcs::cos:ap-beijing:uid/100000000001:bucket/example/reports/2025-Q1.csv"]}]}"#,
/// );
/// // Supply a Context configured with an HttpSend implementation.
/// // The COS signer defaults to a 3600-second header lifetime, so request
/// // longer than that when using the granted credential with the default.
/// let credential = Granter::new(
///     Context::new(),
///     source,
///     GetFederationTokenGranter::new(grant),
/// )
/// .grant(Some(Duration::from_secs(7200)))
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct GetFederationTokenGranter {
    grant: GetFederationTokenGrant,
    sts_endpoint: Option<String>,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for GetFederationTokenGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetFederationTokenGranter")
            .finish_non_exhaustive()
    }
}

impl GetFederationTokenGranter {
    /// Create a granter for a bound authorization decision.
    pub fn new(grant: GetFederationTokenGrant) -> Self {
        Self {
            grant,
            sts_endpoint: None,
            #[cfg(test)]
            now: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound authorization decision.
    pub fn with_grant(mut self, grant: GetFederationTokenGrant) -> Self {
        self.grant = grant;
        self
    }

    /// Set the STS endpoint. Accepts a bare host or a full URL.
    ///
    /// The endpoint must be an HTTP(S) origin without a path or query. The
    /// default is `https://sts.tencentcloudapi.com`. Callers that replace it are
    /// responsible for trusting the endpoint with their authorization headers.
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = Some(endpoint.into());
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    fn time_after_request(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(now) = self.time_after_request {
            return now;
        }
        #[cfg(test)]
        if let Some(now) = self.now {
            return now;
        }
        Timestamp::now()
    }

    fn endpoint(&self) -> Result<ValidatedEndpoint> {
        let endpoint = self
            .sts_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_STS_ENDPOINT)
            .trim();
        let endpoint = if endpoint.contains("://") {
            endpoint.to_string()
        } else {
            format!("https://{endpoint}")
        };
        let endpoint = endpoint.trim_end_matches('/');
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|_| Error::config_invalid("invalid Tencent Cloud STS endpoint"))?;
        let scheme = uri
            .scheme_str()
            .filter(|scheme| matches!(*scheme, "http" | "https"))
            .ok_or_else(|| {
                Error::config_invalid("Tencent Cloud STS endpoint must use HTTP or HTTPS")
            })?;
        let authority = uri
            .authority()
            .ok_or_else(|| Error::config_invalid("Tencent Cloud STS endpoint has no authority"))?;
        let authority = authority.as_str().to_ascii_lowercase();
        if authority.contains('@') {
            return Err(Error::config_invalid(
                "Tencent Cloud STS endpoint must not contain user information",
            ));
        }
        if uri.query().is_some() {
            return Err(Error::config_invalid(
                "Tencent Cloud STS endpoint must not contain a query",
            ));
        }
        if !matches!(uri.path(), "" | "/") {
            return Err(Error::config_invalid(
                "Tencent Cloud STS endpoint must not contain a path",
            ));
        }

        Ok(ValidatedEndpoint {
            origin: format!("{scheme}://{authority}"),
            authority,
        })
    }

    fn duration_seconds(expires_in: Option<Duration>) -> Result<Option<u64>> {
        let Some(expires_in) = expires_in else {
            return Ok(None);
        };
        if expires_in.is_zero()
            || expires_in.subsec_nanos() != 0
            || expires_in.as_secs() > MAX_DURATION_SECONDS
        {
            return Err(Error::request_invalid(
                "Tencent Cloud STS GetFederationToken duration must be a whole number of seconds between 1 and 129600",
            ));
        }
        Ok(Some(expires_in.as_secs()))
    }

    fn validate_source(&self, credential: &Credential, required_until: Timestamp) -> Result<()> {
        if credential.secret_id.is_empty() || credential.secret_key.is_empty() {
            return Err(Error::credential_invalid(
                "Tencent Cloud STS GetFederationToken requires a source secret ID and secret key",
            ));
        }
        if credential.security_token.is_some() {
            return Err(Error::credential_invalid(
                "Tencent Cloud STS GetFederationToken requires a permanent source credential without a security token",
            ));
        }
        if credential.expires_in.is_some() {
            return Err(Error::credential_invalid(
                "Tencent Cloud STS GetFederationToken requires a permanent source credential without an expiration",
            ));
        }
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Tencent source credential expires before the GetFederationToken request can complete",
            ));
        }
        Ok(())
    }

    fn build_request(
        &self,
        credential: &Credential,
        duration_seconds: Option<u64>,
        signing_time: Timestamp,
    ) -> Result<http::Request<Vec<u8>>> {
        let endpoint = self.endpoint()?;
        let policy = encode_policy(&self.grant.policy);
        let body = serde_json::to_vec(&GetFederationTokenRequest {
            name: &self.grant.name,
            policy: &policy,
            duration_seconds,
        })
        .map_err(|err| {
            Error::unexpected("failed to serialize Tencent Cloud STS request").with_source(err)
        })?;

        let timestamp = signing_time.as_second().to_string();
        let date = tc3_date(signing_time);
        let canonical_headers = format!(
            "content-type:application/json\nhost:{}\n",
            endpoint.authority
        );
        let signed_headers = "content-type;host";
        let canonical_request = format!(
            "POST\n/\n\n{canonical_headers}\n{signed_headers}\n{}",
            hex_sha256(&body)?
        );
        let credential_scope = format!("{date}/{STS_SERVICE}/tc3_request");
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())?
        );
        let secret_date = hmac_sha256(
            format!("TC3{}", credential.secret_key).as_bytes(),
            date.as_bytes(),
        )?;
        let secret_service = hmac_sha256(&secret_date, STS_SERVICE.as_bytes())?;
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request")?;
        let signature = hex_hmac_sha256(&secret_signing, string_to_sign.as_bytes())?;
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credential.secret_id
        );

        let mut request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("{}/", endpoint.origin))
            .header(CONTENT_TYPE, "application/json")
            .header("X-TC-Action", STS_ACTION)
            .header("X-TC-Version", STS_VERSION)
            .header("X-TC-Timestamp", timestamp)
            .header(AUTHORIZATION, authorization)
            .body(body)
            .map_err(|_| {
                Error::request_invalid(
                    "failed to build Tencent Cloud STS GetFederationToken request",
                )
            })?;
        request
            .headers_mut()
            .get_mut(AUTHORIZATION)
            .expect("authorization header was just inserted")
            .set_sensitive(true);
        Ok(request)
    }

    fn parse_response<B: AsRef<[u8]>>(
        &self,
        response: http::Response<B>,
        response_time: Timestamp,
    ) -> Result<Credential> {
        let status = response.status();
        let body = response.body().as_ref();
        if status != http::StatusCode::OK {
            return Err(sts_error(status, body));
        }

        let response: GetFederationTokenResponse = serde_json::from_slice(body).map_err(|_| {
            Error::unexpected("failed to parse Tencent Cloud STS GetFederationToken response")
        })?;
        if let Some(error) = response.response.error {
            return Err(sts_error_from_code(status, safe_sts_code(&error.code)));
        }

        let credentials = response.response.credentials.ok_or_else(|| {
            Error::unexpected("Tencent Cloud STS GetFederationToken response has no credentials")
        })?;
        if credentials.tmp_secret_id.is_empty()
            || credentials.tmp_secret_key.is_empty()
            || credentials.token.is_empty()
        {
            return Err(Error::unexpected(
                "Tencent Cloud STS GetFederationToken response is malformed",
            ));
        }

        let expires_in = match response.response.expired_time {
            Some(expired_time) => {
                let expired_time = i64::try_from(expired_time).map_err(|_| {
                    Error::unexpected(
                        "Tencent Cloud STS GetFederationToken expiration is out of range",
                    )
                })?;
                Timestamp::from_second(expired_time).map_err(|_| {
                    Error::unexpected(
                        "Tencent Cloud STS GetFederationToken expiration is out of range",
                    )
                })?
            }
            None => response
                .response
                .expiration
                .ok_or_else(|| {
                    Error::unexpected(
                        "Tencent Cloud STS GetFederationToken response has no expiration",
                    )
                })?
                .parse()
                .map_err(|_| {
                    Error::unexpected("Tencent Cloud STS GetFederationToken expiration is invalid")
                })?,
        };

        let credential = Credential {
            secret_id: credentials.tmp_secret_id,
            secret_key: credentials.tmp_secret_key,
            security_token: Some(credentials.token),
            expires_in: Some(expires_in),
        };
        if !credential.is_valid_at(response_time) {
            return Err(Error::credential_invalid(
                "Tencent Cloud STS GetFederationToken returned a credential that is already expired",
            ));
        }
        Ok(credential)
    }

    #[cfg(test)]
    fn with_time(mut self, now: Timestamp) -> Self {
        self.now = Some(now);
        self.time_after_request = Some(now);
        self
    }

    #[cfg(test)]
    fn with_time_after_request(mut self, now: Timestamp) -> Self {
        self.time_after_request = Some(now);
        self
    }
}

impl GrantCredential for GetFederationTokenGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + STS_REQUEST_HEADROOM
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let duration_seconds = Self::duration_seconds(expires_in)?;
        self.grant.validate()?;
        let required_until = self.required_valid_until(credential, expires_in);
        self.validate_source(credential, required_until)?;

        let request = self.build_request(credential, duration_seconds, self.now())?;
        let response = ctx
            .http_send(request.map(Into::into))
            .await
            .map_err(|err| {
                Error::new(
                    err.kind(),
                    "Tencent Cloud STS GetFederationToken request failed",
                )
                .set_retryable(err.is_retryable())
            })?;
        self.parse_response(response, self.time_after_request())
    }
}

struct ValidatedEndpoint {
    origin: String,
    authority: String,
}

fn tc3_date(signing_time: Timestamp) -> String {
    let date = signing_time.format_date();
    format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8])
}

fn encode_policy(policy: &str) -> String {
    utf8_percent_encode(policy, &TENCENT_URI_ENCODE_SET).to_string()
}

#[derive(Serialize)]
struct GetFederationTokenRequest<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Policy")]
    policy: &'a str,
    #[serde(rename = "DurationSeconds", skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct GetFederationTokenResponse {
    #[serde(rename = "Response")]
    response: GetFederationTokenResponseBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetFederationTokenResponseBody {
    #[serde(default)]
    error: Option<GetFederationTokenError>,
    #[serde(default)]
    credentials: Option<GetFederationTokenCredentials>,
    #[serde(default)]
    expired_time: Option<u64>,
    #[serde(default)]
    expiration: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetFederationTokenCredentials {
    tmp_secret_id: String,
    tmp_secret_key: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetFederationTokenError {
    #[serde(default)]
    code: String,
}

#[derive(Deserialize)]
struct StsErrorEnvelope {
    #[serde(rename = "Response")]
    response: StsErrorResponse,
}

#[derive(Deserialize)]
struct StsErrorResponse {
    #[serde(default)]
    error: Option<GetFederationTokenError>,
}

fn safe_sts_code(code: &str) -> Option<&str> {
    let safe = !code.is_empty()
        && code.len() <= 128
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    safe.then_some(code)
}

fn sts_error(status: http::StatusCode, body: &[u8]) -> Error {
    let code = serde_json::from_slice::<StsErrorEnvelope>(body)
        .ok()
        .and_then(|response| response.response.error)
        .and_then(|error| safe_sts_code(&error.code).map(str::to_owned));
    sts_error_from_code(status, code.as_deref())
}

fn sts_error_from_code(status: http::StatusCode, code: Option<&str>) -> Error {
    let mut error = match code {
        Some(code) if code.starts_with("AuthFailure") => Error::credential_invalid(
            "Tencent Cloud STS GetFederationToken rejected the source credential",
        ),
        Some("UnauthorizedOperation") => {
            Error::permission_denied("Tencent Cloud STS GetFederationToken was denied")
        }
        Some(code) if code.starts_with("InvalidParameter") => {
            Error::request_invalid("Tencent Cloud STS GetFederationToken rejected the request")
        }
        Some("RequestLimitExceeded") => {
            Error::rate_limited("Tencent Cloud STS GetFederationToken was rate limited")
        }
        Some(code) if code.starts_with("InternalError") => {
            Error::unexpected("Tencent Cloud STS GetFederationToken failed").set_retryable(true)
        }
        _ if status == http::StatusCode::UNAUTHORIZED => Error::credential_invalid(
            "Tencent Cloud STS GetFederationToken rejected the source credential",
        ),
        _ if status == http::StatusCode::FORBIDDEN => {
            Error::permission_denied("Tencent Cloud STS GetFederationToken was denied")
        }
        _ if status == http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("Tencent Cloud STS GetFederationToken was rate limited")
        }
        _ => Error::unexpected("Tencent Cloud STS GetFederationToken failed")
            .set_retryable(status.is_server_error()),
    }
    .with_context(format!("sts_status: {}", status.as_u16()));

    if let Some(code) = code {
        error = error.with_context(format!("sts_error: {code}"));
    }
    error
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use http::header::{HeaderMap, HeaderValue};
    use percent_encoding::percent_decode_str;
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer};

    use super::*;
    use crate::RequestSigner;

    const SUCCESS_BODY: &[u8] = br#"{"Response":{"Credentials":{"TmpSecretId":"sts-secret-id","TmpSecretKey":"sts-secret-key","Token":"sts-security-token"},"ExpiredTime":4872311117,"Expiration":"2124-05-25T11:45:17Z","RequestId":"request-id"}}"#;
    const SOURCE_SECRET_ID: &str = "source-secret-id";
    const SOURCE_SECRET_KEY: &str = "source-secret-key";
    const GRANT_NAME: &str = "reqsign";
    const POLICY: &str = r#"{"version":"2.0","statement":[{"effect":"allow","action":["cos:GetObject"],"resource":["qcs::cos:ap-beijing:uid/100000000001:bucket/example/reports/2025%2FQ1+final&draft=yes.csv"]}]}"#;

    #[derive(Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("CapturedRequest")
                .field("method", &self.method)
                .field("uri", &self.uri)
                .field("headers", &"REDACTED")
                .field("body", &"REDACTED")
                .finish()
        }
    }

    #[derive(Clone)]
    struct MockHttpSend {
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        responses: Arc<Mutex<VecDeque<http::Response<Bytes>>>>,
    }

    impl Debug for MockHttpSend {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockHttpSend").finish_non_exhaustive()
        }
    }

    impl MockHttpSend {
        fn new(responses: impl IntoIterator<Item = http::Response<Bytes>>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            }
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().expect("lock poisoned").clone()
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl HttpSend for MockHttpSend {
        async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (parts, body) = request.into_parts();
            self.requests
                .lock()
                .expect("lock poisoned")
                .push(CapturedRequest {
                    method: parts.method,
                    uri: parts.uri,
                    headers: parts.headers,
                    body: body.to_vec(),
                });
            self.responses
                .lock()
                .expect("lock poisoned")
                .pop_front()
                .ok_or_else(|| Error::unexpected("mock response queue is empty"))
        }
    }

    #[derive(Clone)]
    struct FixedCredentialProvider {
        credential: Credential,
    }

    impl Debug for FixedCredentialProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("FixedCredentialProvider")
                .finish_non_exhaustive()
        }
    }

    impl ProvideCredential for FixedCredentialProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            Ok(Some(self.credential.clone()))
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must be valid")
    }

    fn source_credential() -> Credential {
        Credential {
            secret_id: SOURCE_SECRET_ID.to_string(),
            secret_key: SOURCE_SECRET_KEY.to_string(),
            security_token: None,
            expires_in: None,
        }
    }

    fn source_provider() -> FixedCredentialProvider {
        FixedCredentialProvider {
            credential: source_credential(),
        }
    }

    fn response(status: http::StatusCode, body: impl Into<Bytes>) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(body.into())
            .expect("response must build")
    }

    fn success_response(expired_time: i64) -> http::Response<Bytes> {
        let body = serde_json::json!({
            "Response": {
                "Credentials": {
                    "TmpSecretId": "sts-secret-id",
                    "TmpSecretKey": "sts-secret-key",
                    "Token": "sts-security-token",
                },
                "ExpiredTime": expired_time,
            }
        });
        response(
            http::StatusCode::OK,
            serde_json::to_vec(&body).expect("response body must serialize"),
        )
    }

    fn request_parts() -> http::request::Parts {
        http::Request::get("https://bucket.cos.ap-beijing.myqcloud.com/object")
            .body(())
            .expect("request must build")
            .into_parts()
            .0
    }

    fn granter(signing_time: Timestamp) -> GetFederationTokenGranter {
        GetFederationTokenGranter::new(GetFederationTokenGrant::new(GRANT_NAME, POLICY))
            .with_sts_endpoint("https://sts.example.com")
            .with_time(signing_time)
    }

    fn request_json(request: &CapturedRequest) -> serde_json::Value {
        serde_json::from_slice(&request.body).expect("request body must be valid JSON")
    }

    #[test]
    fn policy_encoding_is_rfc3986_and_round_trips() {
        assert_eq!(
            "a%20b%2Bc%25d%26e%3Df%2Fg%3Ah",
            encode_policy("a b+c%d&e=f/g:h")
        );

        let encoded = encode_policy(POLICY);
        assert_ne!(POLICY, encoded);
        assert_eq!(
            POLICY,
            percent_decode_str(&encoded)
                .decode_utf8()
                .expect("encoded policy must be valid UTF-8")
        );
    }

    #[test]
    fn endpoint_accepts_bare_host_and_rejects_paths() {
        let granter =
            GetFederationTokenGranter::new(GetFederationTokenGrant::new(GRANT_NAME, POLICY))
                .with_sts_endpoint("sts.example.com");
        let endpoint = granter.endpoint().expect("bare host must be accepted");
        assert_eq!("https://sts.example.com", endpoint.origin);
        assert_eq!("sts.example.com", endpoint.authority);

        let granter =
            GetFederationTokenGranter::new(GetFederationTokenGrant::new(GRANT_NAME, POLICY))
                .with_sts_endpoint("https://sts.example.com/path");
        assert!(granter.endpoint().is_err());
    }

    #[tokio::test]
    async fn grants_with_exact_tc3_signature_and_epoch_expiration() -> Result<()> {
        let signing_time = timestamp("2024-03-05T06:07:08Z");
        let http_send = MockHttpSend::new([response(http::StatusCode::OK, SUCCESS_BODY)]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let credential = Granter::new(ctx, source_provider(), granter(signing_time))
            .grant(Some(Duration::from_secs(3600)))
            .await?;

        assert_eq!("sts-secret-id", credential.secret_id);
        assert_eq!("sts-secret-key", credential.secret_key);
        assert_eq!(
            Some("sts-security-token"),
            credential.security_token.as_deref()
        );
        assert_eq!(
            Some(timestamp("2124-05-25T11:45:17Z")),
            credential.expires_in
        );
        assert_eq!(1, http_send.calls());

        let request = &http_send.requests()[0];
        assert_eq!(http::Method::POST, request.method);
        assert_eq!("https://sts.example.com/", request.uri.to_string());
        assert_eq!(
            HeaderValue::from_static("application/json"),
            request.headers[CONTENT_TYPE]
        );
        assert_eq!("GetFederationToken", request.headers["X-TC-Action"]);
        assert_eq!("2018-08-13", request.headers["X-TC-Version"]);
        assert_eq!("1709618828", request.headers["X-TC-Timestamp"]);
        assert!(!request.headers.contains_key("X-TC-Token"));
        assert!(!request.headers.contains_key("X-TC-Region"));
        assert_eq!(
            "TC3-HMAC-SHA256 Credential=source-secret-id/2024-03-05/sts/tc3_request, SignedHeaders=content-type;host, Signature=09c6966e359938640cf430c5b819a480100f671adefe3e78366c68faa314805f",
            request.headers[AUTHORIZATION]
        );
        assert!(request.headers[AUTHORIZATION].is_sensitive());

        let body = request_json(request);
        assert_eq!(GRANT_NAME, body["Name"]);
        let encoded_policy = body["Policy"].as_str().expect("Policy must be a string");
        assert_eq!(encode_policy(POLICY), encoded_policy);
        assert_eq!(
            POLICY,
            percent_decode_str(encoded_policy)
                .decode_utf8()
                .expect("encoded policy must be valid UTF-8")
        );
        assert_eq!(3600, body["DurationSeconds"]);
        assert_eq!(3, body.as_object().expect("body must be an object").len());
        Ok(())
    }

    #[tokio::test]
    async fn omitted_duration_uses_the_service_default_and_accepts_iso_expiration() -> Result<()> {
        let body = br#"{"Response":{"Credentials":{"TmpSecretId":"sts-secret-id","TmpSecretKey":"sts-secret-key","Token":"sts-security-token"},"Expiration":"2124-05-25T11:45:17Z"}}"#;
        let http_send = MockHttpSend::new([response(http::StatusCode::OK, body.as_slice())]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let credential = Granter::new(
            ctx,
            source_provider(),
            granter(timestamp("2024-03-05T06:07:08Z")),
        )
        .grant(None)
        .await?;

        assert_eq!(
            Some(timestamp("2124-05-25T11:45:17Z")),
            credential.expires_in
        );
        let body = request_json(&http_send.requests()[0]);
        assert!(
            !body
                .as_object()
                .expect("body must be an object")
                .contains_key("DurationSeconds")
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_grant_and_source_before_io() {
        let signing_time = timestamp("2024-03-05T06:07:08Z");
        let durations = [
            Some(Duration::ZERO),
            Some(Duration::from_secs(MAX_DURATION_SECONDS + 1)),
            Some(Duration::from_millis(1500)),
        ];
        for duration in durations {
            let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
            let ctx = Context::new().with_http_send(http_send.clone());
            let err = Granter::new(ctx, source_provider(), granter(signing_time))
                .grant(duration)
                .await
                .expect_err("invalid duration must be rejected");
            assert_eq!(ErrorKind::RequestInvalid, err.kind());
            assert_eq!(0, http_send.calls());
        }

        let mut invalid_grants = vec![GetFederationTokenGrant::new(GRANT_NAME, "")];
        invalid_grants.extend(
            ["", "reqsign-test", "reqsign1", "reqsign test"]
                .map(|name| GetFederationTokenGrant::new(name, POLICY)),
        );
        for grant in invalid_grants {
            let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
            let ctx = Context::new().with_http_send(http_send.clone());
            let err = Granter::new(
                ctx,
                source_provider(),
                GetFederationTokenGranter::new(grant).with_time(signing_time),
            )
            .grant(None)
            .await
            .expect_err("invalid grant must be rejected before I/O");
            assert_eq!(ErrorKind::RequestInvalid, err.kind());
            assert_eq!(0, http_send.calls());
        }

        let invalid_sources = [
            Credential {
                security_token: Some("temporary-token".to_string()),
                ..source_credential()
            },
            Credential {
                expires_in: Some(signing_time + Duration::from_secs(3600)),
                ..source_credential()
            },
            Credential {
                secret_id: String::new(),
                ..source_credential()
            },
        ];
        for source in invalid_sources {
            let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
            let ctx = Context::new().with_http_send(http_send.clone());
            let err = Granter::new(
                ctx,
                FixedCredentialProvider { credential: source },
                granter(signing_time),
            )
            .grant(None)
            .await
            .expect_err("invalid source must be rejected before I/O");
            assert_eq!(ErrorKind::CredentialInvalid, err.kind());
            assert_eq!(0, http_send.calls());
        }
    }

    #[tokio::test]
    async fn rejects_expired_granted_credential_after_io() {
        let body = br#"{"Response":{"Credentials":{"TmpSecretId":"sts-secret-id","TmpSecretKey":"sts-secret-key","Token":"sts-security-token"},"ExpiredTime":1893553445}}"#;
        let http_send = MockHttpSend::new([response(http::StatusCode::OK, body.as_slice())]);
        let ctx = Context::new().with_http_send(http_send.clone());

        let err = Granter::new(
            ctx,
            source_provider(),
            granter(timestamp("2024-03-05T06:07:08Z"))
                .with_time_after_request(timestamp("2031-01-01T00:00:00Z")),
        )
        .grant(None)
        .await
        .expect_err("granted credential must be rejected after the response time");

        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert_eq!(1, http_send.calls());
        assert!(!format!("{err:?}").contains(SOURCE_SECRET_KEY));
        assert!(!format!("{err:?}").contains(POLICY));
    }

    #[tokio::test]
    async fn errors_and_debug_do_not_expose_secrets_or_policy() {
        let grant = GetFederationTokenGrant::new(GRANT_NAME, POLICY);
        let debug = format!("{grant:?}");
        assert!(debug.contains(GRANT_NAME));
        assert!(!debug.contains(POLICY));

        let debug_granter = GetFederationTokenGranter::new(grant.clone());
        let debug = format!("{debug_granter:?}");
        assert!(!debug.contains(GRANT_NAME));
        assert!(!debug.contains(POLICY));

        let error_body = br#"{"Response":{"Error":{"Code":"AuthFailure.SignatureFailure","Message":"source-secret-key and policy detail"},"RequestId":"request-id"}}"#;
        let http_send = MockHttpSend::new([response(http::StatusCode::OK, error_body.as_slice())]);
        let ctx = Context::new().with_http_send(http_send.clone());
        let err = Granter::new(
            ctx,
            source_provider(),
            granter(timestamp("2024-03-05T06:07:08Z")),
        )
        .grant(None)
        .await
        .expect_err("STS API error must be returned");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        let debug = format!("{err:?}");
        assert!(debug.contains("AuthFailure.SignatureFailure"));
        assert!(!debug.contains(SOURCE_SECRET_KEY));
        assert!(!debug.contains(POLICY));

        let error_body = format!("source-secret-key {POLICY}");
        let http_send = MockHttpSend::new([response(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from(error_body),
        )]);
        let ctx = Context::new().with_http_send(http_send.clone());
        let err = Granter::new(
            ctx,
            source_provider(),
            granter(timestamp("2024-03-05T06:07:08Z")),
        )
        .grant(None)
        .await
        .expect_err("non-success status must be returned");
        let debug = format!("{err:?}");
        assert!(!debug.contains(SOURCE_SECRET_KEY));
        assert!(!debug.contains(POLICY));
    }

    #[tokio::test]
    async fn granted_credential_is_consumable_by_the_cos_signer() -> Result<()> {
        let now = Timestamp::now();
        let http_send = MockHttpSend::new([success_response(now.as_second() + 7200)]);
        let ctx = Context::new().with_http_send(http_send);
        let granted = Granter::new(ctx, source_provider(), granter(now))
            .grant(Some(Duration::from_secs(7200)))
            .await?;

        let signer = Signer::new(
            Context::new(),
            FixedCredentialProvider {
                credential: granted,
            },
            RequestSigner::new(),
        );
        let mut request = request_parts();
        signer.sign(&mut request, None).await?;

        let authorization = request.headers[AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert!(authorization.contains("q-ak=sts-secret-id"));
        assert_eq!(
            "sts-security-token",
            request.headers["x-cos-security-token"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn default_grant_lifetime_is_shorter_than_the_default_cos_signing_lifetime() -> Result<()>
    {
        let now = Timestamp::now();
        let http_send = MockHttpSend::new([success_response(now.as_second() + 1800)]);
        let ctx = Context::new().with_http_send(http_send);
        let granted = Granter::new(ctx, source_provider(), granter(now))
            .grant(None)
            .await?;

        let signer = Signer::new(
            Context::new(),
            FixedCredentialProvider {
                credential: granted,
            },
            RequestSigner::new(),
        );
        let mut request = request_parts();
        let err = signer
            .sign(&mut request, None)
            .await
            .expect_err("default COS signing lifetime must reject a 1800-second grant");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert!(
            format!("{err:?}").contains("requested operation deadline"),
            "error must come from the signing deadline check: {err:?}"
        );

        let mut request = request_parts();
        signer
            .sign(&mut request, Some(Duration::from_secs(900)))
            .await?;
        assert!(
            request
                .uri
                .query()
                .is_some_and(|query| query.contains("q-signature=")),
            "shorter explicit lifetime must select query authentication"
        );
        Ok(())
    }
}
