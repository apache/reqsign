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

//! Volcengine STS `AssumeRole` credential granting.
//!
//! [`AssumeRoleGranter`] consumes an existing Volcengine credential and calls
//! the regional STS `AssumeRole` OpenAPI. The returned [`Credential`] contains
//! the issued access key, secret key, session token, and the exact
//! `ExpiredTime` reported by STS, so it can be passed directly to the existing
//! TOS [`RequestSigner`](crate::RequestSigner).
//!
//! The request uses the Volcengine OpenAPI `HMAC-SHA256` signature scheme with
//! the `<date>/<region>/sts/request` scope. This is separate from TOS4 request
//! signing. See
//! <https://docs.volcengine.com/docs/iam/assume-role?lang=zh> and
//! <https://docs.volcengine.com/docs/api-signature-call-guide/signature-method?lang=zh>.

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::time::Duration;

use http::header::{AUTHORIZATION, HeaderValue};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use serde::Deserialize;

use crate::Credential;
use crate::constants::EMPTY_PAYLOAD_SHA256;
use crate::uri::percent_encode_query;

const DEFAULT_STS_SERVICE: &str = "sts";
const STS_ACTION: &str = "AssumeRole";
const STS_VERSION: &str = "2018-01-01";
const STS_REQUEST_HEADROOM: Duration = Duration::from_secs(20);
const MIN_DURATION_SECONDS: u64 = 900;
const MAX_DURATION_SECONDS: u64 = 43_200;
const HEADER_X_DATE: &str = "x-date";
const HEADER_X_SECURITY_TOKEN: &str = "x-security-token";

/// A typed, explicitly bound Volcengine STS `AssumeRole` authority transition.
///
/// The caller owns the target role, trust relationship, session name, optional
/// inline policy, and the TOS resources and actions those permissions reach.
/// `AssumeRole` is an authority transition: the returned session receives the
/// intersection of the target role's permissions and the optional inline
/// policy, not necessarily a subset of the source principal's direct
/// permissions.
///
/// `role_trn` must use the documented `trn:iam::<account>:role/<name>` form.
/// `role_session_name` must contain 2-64 ASCII letters, digits, or `.`, `-`,
/// `_`, `@`. `policy` is a raw IAM policy document; reqsign does not parse or
/// evaluate it and redacts it from [`Debug`] output.
#[derive(Clone)]
pub struct AssumeRoleGrant {
    role_trn: String,
    role_session_name: String,
    policy: Option<String>,
}

impl Debug for AssumeRoleGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleGrant")
            .field("role_trn", &self.role_trn)
            .field("role_session_name", &self.role_session_name)
            .field("policy", &self.policy.as_ref().map(|_| "REDACTED"))
            .finish()
    }
}

impl AssumeRoleGrant {
    /// Create a grant for a target role TRN and auditable role session name.
    pub fn new(role_trn: impl Into<String>, role_session_name: impl Into<String>) -> Self {
        Self {
            role_trn: role_trn.into(),
            role_session_name: role_session_name.into(),
            policy: None,
        }
    }

    /// Set an optional inline IAM policy that further restricts the session.
    ///
    /// The policy is sent as one `Policy` query value and is encoded exactly
    /// once. It is not parsed or evaluated by reqsign.
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    fn validate(&self) -> Result<()> {
        let Some(role_path) = self.role_trn.strip_prefix("trn:iam::") else {
            return Err(Error::request_invalid(
                "Volcengine STS AssumeRole RoleTrn must use trn:iam::<account>:role/<name>",
            ));
        };
        let Some((account, role_name)) = role_path.split_once(":role/") else {
            return Err(Error::request_invalid(
                "Volcengine STS AssumeRole RoleTrn must use trn:iam::<account>:role/<name>",
            ));
        };
        if account.is_empty() || role_name.is_empty() {
            return Err(Error::request_invalid(
                "Volcengine STS AssumeRole RoleTrn must use trn:iam::<account>:role/<name>",
            ));
        }

        let session_name = self.role_session_name.as_bytes();
        if !(2..=64).contains(&session_name.len())
            || !session_name.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@')
            })
        {
            return Err(Error::request_invalid(
                "Volcengine STS AssumeRole RoleSessionName must be 2-64 ASCII letters, digits, or .-_@",
            ));
        }

        if self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.trim().is_empty())
        {
            return Err(Error::request_invalid(
                "Volcengine STS AssumeRole Policy must not be empty",
            ));
        }

        Ok(())
    }
}

/// Explicitly grants a Volcengine STS `AssumeRole` credential for TOS.
///
/// The source credential supplied by [`reqsign_core::Granter`] signs the STS
/// request directly. Both long-lived IAM sub-user access keys and valid
/// temporary role-session credentials are accepted; a temporary source's
/// session token is sent in `X-Security-Token` and included in the signature.
/// The Volcengine service rejects a root-account source, and it remains
/// authoritative for the role trust relationship and the target role's
/// configured maximum session duration.
///
/// `expires_in` maps to `DurationSeconds`. `None` omits the field and uses the
/// service default of 3600 seconds. An explicit lifetime must be a whole
/// number of seconds between 900 and 43200; values outside that range are
/// rejected before I/O instead of being silently replaced by the service.
///
/// Every call performs a new STS exchange. The returned credential carries the
/// exact server-provided `ExpiredTime`; granted credentials are never cached.
///
/// The STS endpoint defaults to `https://sts.<region>.volcengineapi.com`. The
/// region is also used in the OpenAPI credential scope.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter};
/// use reqsign_volcengine_tos::{
///     AssumeRoleGrant, AssumeRoleGranter, StaticCredentialProvider,
/// };
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = StaticCredentialProvider::new("source-access-key-id", "source-secret-key");
/// let grant = AssumeRoleGrant::new(
///     "trn:iam::2000012345:role/customer-reader",
///     "customer-a",
/// )
/// .with_policy(r#"{"Statement":[{"Effect":"Allow","Action":["tos:GetObject"],"Resource":["*"]}]}"#);
/// // Supply a Context configured with an HttpSend implementation.
/// let credential = Granter::new(
///     Context::new(),
///     source,
///     AssumeRoleGranter::new("cn-beijing", grant),
/// )
/// .grant(Some(Duration::from_secs(3600)))
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AssumeRoleGranter {
    region: String,
    grant: AssumeRoleGrant,
    sts_endpoint: Option<String>,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for AssumeRoleGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleGranter").finish_non_exhaustive()
    }
}

impl AssumeRoleGranter {
    /// Create a granter for a signing region and bound AssumeRole grant.
    pub fn new(region: impl Into<String>, grant: AssumeRoleGrant) -> Self {
        Self {
            region: region.into(),
            grant,
            sts_endpoint: None,
            #[cfg(test)]
            now: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound authority transition.
    pub fn with_grant(mut self, grant: AssumeRoleGrant) -> Self {
        self.grant = grant;
        self
    }

    /// Set the STS endpoint. Accepts a bare host or a full URL.
    ///
    /// The endpoint must be an HTTP(S) origin without a path, query, or user
    /// information. The configured region remains the signing scope even when
    /// the endpoint is replaced. Callers that replace the endpoint are
    /// responsible for trusting it with their authorization headers.
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

    fn duration_seconds(expires_in: Option<Duration>) -> Result<Option<u64>> {
        let Some(expires_in) = expires_in else {
            return Ok(None);
        };
        let seconds = expires_in.as_secs();
        if expires_in.subsec_nanos() != 0
            || !(MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&seconds)
        {
            return Err(Error::request_invalid(
                "Volcengine STS AssumeRole duration must be a whole number of seconds between 900 and 43200",
            ));
        }
        Ok(Some(seconds))
    }

    fn endpoint(&self) -> Result<ValidatedEndpoint> {
        if self.region.is_empty()
            || !self
                .region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::config_invalid(
                "Volcengine STS region must contain only ASCII letters, digits, or '-'",
            ));
        }

        let endpoint = match &self.sts_endpoint {
            Some(endpoint) => {
                let endpoint = endpoint.trim();
                if endpoint.contains("://") {
                    endpoint.to_string()
                } else {
                    format!("https://{endpoint}")
                }
            }
            None => format!("https://sts.{}.volcengineapi.com", self.region),
        };
        let endpoint = endpoint.trim_end_matches('/');
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|_| Error::config_invalid("invalid Volcengine STS endpoint"))?;
        let scheme = uri
            .scheme_str()
            .filter(|scheme| matches!(*scheme, "http" | "https"))
            .ok_or_else(|| {
                Error::config_invalid("Volcengine STS endpoint must use HTTP or HTTPS")
            })?;
        let authority = uri
            .authority()
            .ok_or_else(|| Error::config_invalid("Volcengine STS endpoint has no authority"))?;
        let authority = authority.as_str().to_ascii_lowercase();
        if authority.contains('@') {
            return Err(Error::config_invalid(
                "Volcengine STS endpoint must not contain user information",
            ));
        }
        if uri.query().is_some() {
            return Err(Error::config_invalid(
                "Volcengine STS endpoint must not contain a query",
            ));
        }
        if !matches!(uri.path(), "" | "/") {
            return Err(Error::config_invalid(
                "Volcengine STS endpoint must not contain a path",
            ));
        }

        Ok(ValidatedEndpoint {
            origin: format!("{scheme}://{authority}"),
            authority,
        })
    }

    fn validate_source(&self, credential: &Credential, required_until: Timestamp) -> Result<()> {
        if credential.access_key_id.trim().is_empty()
            || credential.secret_access_key.trim().is_empty()
        {
            return Err(Error::credential_invalid(
                "Volcengine STS AssumeRole requires a source access key id and secret access key",
            ));
        }
        if credential.session_token.as_ref().is_some_and(|token| {
            token.trim().is_empty()
                || token != token.trim()
                || HeaderValue::try_from(token.as_str()).is_err()
        }) {
            return Err(Error::credential_invalid(
                "Volcengine STS AssumeRole source session token is invalid",
            ));
        }
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Volcengine source credential expires before the STS AssumeRole request can complete",
            ));
        }
        Ok(())
    }

    fn build_request(
        &self,
        provider: &dyn CryptoProvider,
        credential: &Credential,
        duration_seconds: Option<u64>,
        signing_time: Timestamp,
    ) -> Result<http::Request<Vec<u8>>> {
        let endpoint = self.endpoint()?;
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), STS_ACTION.to_string());
        params.insert("Version".to_string(), STS_VERSION.to_string());
        params.insert("RoleTrn".to_string(), self.grant.role_trn.clone());
        params.insert(
            "RoleSessionName".to_string(),
            self.grant.role_session_name.clone(),
        );
        if let Some(seconds) = duration_seconds {
            params.insert("DurationSeconds".to_string(), seconds.to_string());
        }
        if let Some(policy) = &self.grant.policy {
            params.insert("Policy".to_string(), policy.clone());
        }

        let canonical_query = canonical_query_string(&params);
        let date = signing_time.format_iso8601();
        let short_date = signing_time.format_date();
        let credential_scope =
            format!("{short_date}/{}/{DEFAULT_STS_SERVICE}/request", self.region);

        let mut signed_headers = vec!["host", HEADER_X_DATE];
        let mut canonical_headers =
            format!("host:{}\n{HEADER_X_DATE}:{date}\n", endpoint.authority);
        let mut security_token = None;
        if let Some(token) = &credential.session_token {
            signed_headers.push(HEADER_X_SECURITY_TOKEN);
            canonical_headers.push_str(&format!("{HEADER_X_SECURITY_TOKEN}:{token}\n"));
            security_token = Some(token.as_str());
        }
        let signed_headers = signed_headers.join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            http::Method::GET.as_str(),
            "/",
            canonical_query,
            canonical_headers,
            signed_headers,
            EMPTY_PAYLOAD_SHA256
        );
        let string_to_sign = format!(
            "HMAC-SHA256\n{date}\n{credential_scope}\n{}",
            hex_sha256(provider, canonical_request.as_bytes())?
        );
        let signing_key = derive_signing_key(
            provider,
            &credential.secret_access_key,
            &short_date,
            &self.region,
            DEFAULT_STS_SERVICE,
        )?;
        let signature = hex_hmac_sha256(provider, &signing_key, string_to_sign.as_bytes())?;
        let authorization = format!(
            "HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credential.access_key_id
        );

        let uri = format!("{}/?{canonical_query}", endpoint.origin);
        let mut authorization = HeaderValue::try_from(authorization)
            .map_err(|_| Error::request_invalid("invalid Volcengine STS Authorization header"))?;
        authorization.set_sensitive(true);

        let mut request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .header(HEADER_X_DATE, date)
            .header(AUTHORIZATION, authorization)
            .body(Vec::new())
            .map_err(|_| {
                Error::request_invalid("failed to build Volcengine STS AssumeRole request")
            })?;
        if let Some(token) = security_token {
            let mut token = HeaderValue::try_from(token)
                .map_err(|_| Error::request_invalid("invalid Volcengine STS session token"))?;
            token.set_sensitive(true);
            request.headers_mut().insert(HEADER_X_SECURITY_TOKEN, token);
        }

        Ok(request)
    }

    fn parse_response<B: AsRef<[u8]>>(
        &self,
        response: http::Response<B>,
        response_time: Timestamp,
    ) -> Result<Credential> {
        let status = response.status();
        let body = response.body().as_ref();
        if !status.is_success() {
            return Err(sts_error(status, body));
        }

        let response: AssumeRoleResponse = serde_json::from_slice(body)
            .map_err(|_| Error::unexpected("failed to parse Volcengine STS AssumeRole response"))?;
        if let Some(error) = response.metadata.error {
            return Err(sts_error_from_code(status, safe_sts_code(&error.code)));
        }

        let credentials = response
            .result
            .and_then(|result| result.credentials)
            .ok_or_else(|| {
                Error::unexpected("Volcengine STS AssumeRole response has no credentials")
            })?;
        if credentials.access_key_id.trim().is_empty()
            || credentials.secret_access_key.trim().is_empty()
            || credentials.session_token.trim().is_empty()
            || credentials.session_token != credentials.session_token.trim()
            || HeaderValue::try_from(credentials.session_token.as_str()).is_err()
        {
            return Err(Error::unexpected(
                "Volcengine STS AssumeRole response is malformed",
            ));
        }
        let expires_at: Timestamp = credentials.expired_time.parse().map_err(|_| {
            Error::unexpected("Volcengine STS AssumeRole response has an invalid ExpiredTime")
        })?;
        let credential =
            Credential::new(&credentials.access_key_id, &credentials.secret_access_key)
                .with_session_token(&credentials.session_token)
                .with_expires_at(expires_at);
        if !credential.is_valid_at(response_time) {
            return Err(Error::credential_invalid(
                "Volcengine STS AssumeRole returned a credential that is already expired",
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

impl GrantCredential for AssumeRoleGranter {
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

        let request = self.build_request(
            ctx.crypto_provider()?,
            credential,
            duration_seconds,
            self.now(),
        )?;
        let response = ctx
            .http_send(request.map(Into::into))
            .await
            .map_err(|err| {
                Error::new(err.kind(), "Volcengine STS AssumeRole request failed")
                    .set_retryable(err.is_retryable())
            })?;
        self.parse_response(response, self.time_after_request())
    }
}

struct ValidatedEndpoint {
    origin: String,
    authority: String,
}

fn canonical_query_string(params: &BTreeMap<String, String>) -> String {
    let mut pairs = params
        .iter()
        .map(|(key, value)| (percent_encode_query(key), percent_encode_query(value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn derive_signing_key(
    provider: &dyn CryptoProvider,
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>> {
    let date_key = hmac_sha256(provider, secret.as_bytes(), date.as_bytes())?;
    let region_key = hmac_sha256(provider, &date_key, region.as_bytes())?;
    let service_key = hmac_sha256(provider, &region_key, service.as_bytes())?;
    Ok(hmac_sha256(provider, &service_key, b"request")?.to_vec())
}

#[derive(Deserialize)]
struct AssumeRoleResponse {
    #[serde(rename = "ResponseMetadata", default)]
    metadata: AssumeRoleResponseMetadata,
    #[serde(rename = "Result", default)]
    result: Option<AssumeRoleResult>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleResponseMetadata {
    #[serde(default)]
    error: Option<AssumeRoleError>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleResult {
    #[serde(default)]
    credentials: Option<AssumeRoleCredentials>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleCredentials {
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    secret_access_key: String,
    #[serde(default)]
    session_token: String,
    #[serde(default)]
    expired_time: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssumeRoleError {
    #[serde(default)]
    code: String,
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
    let code = serde_json::from_slice::<AssumeRoleResponse>(body)
        .ok()
        .and_then(|response| response.metadata.error)
        .and_then(|error| safe_sts_code(&error.code).map(str::to_owned));
    sts_error_from_code(status, code.as_deref())
}

fn sts_error_from_code(status: http::StatusCode, code: Option<&str>) -> Error {
    let mut error = match code {
        Some("InvalidAccessKey" | "SignatureDoesNotMatch" | "InvalidSecretToken") => {
            Error::credential_invalid("Volcengine STS AssumeRole rejected the source credential")
        }
        Some("RootUserAssumeRole") => Error::credential_invalid(
            "Volcengine STS AssumeRole requires a sub-user or role source credential",
        ),
        Some("AccessDenied" | "NoPermission") => {
            Error::permission_denied("Volcengine STS AssumeRole was denied")
        }
        Some("RoleNotExist") => {
            Error::request_invalid("Volcengine STS AssumeRole target role was not found")
        }
        Some(
            "MissingParameter"
            | "InvalidParameter"
            | "MissingRequestInfo"
            | "InvalidTimestamp"
            | "InvalidAuthorization"
            | "InvalidCredential"
            | "InvalidActionOrVersion"
            | "ServiceNotFound",
        ) => Error::request_invalid("Volcengine STS AssumeRole rejected the request"),
        Some("FlowLimitExceeded") => {
            Error::rate_limited("Volcengine STS AssumeRole was rate limited")
        }
        Some("InternalError" | "InternalServiceTimeout" | "InternalServiceError") => {
            Error::unexpected("Volcengine STS AssumeRole failed").set_retryable(true)
        }
        Some("ServiceUnavailableTemp") => {
            Error::unexpected("Volcengine STS AssumeRole is temporarily unavailable")
                .set_retryable(true)
        }
        _ if status == http::StatusCode::UNAUTHORIZED => {
            Error::credential_invalid("Volcengine STS AssumeRole rejected the source credential")
        }
        _ if status == http::StatusCode::FORBIDDEN => {
            Error::permission_denied("Volcengine STS AssumeRole was denied")
        }
        _ if status == http::StatusCode::BAD_REQUEST || status == http::StatusCode::NOT_FOUND => {
            Error::request_invalid("Volcengine STS AssumeRole rejected the request")
        }
        _ if status == http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("Volcengine STS AssumeRole was rate limited")
        }
        _ => Error::unexpected("Volcengine STS AssumeRole failed")
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
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, SignRequest, Signer};

    use super::*;
    use crate::RequestSigner;

    const SOURCE_ACCESS_KEY: &str = "synthetic-ak";
    const SOURCE_SECRET_KEY: &str = "synthetic-sk";
    const SOURCE_SESSION_TOKEN: &str = "synthetic-token";
    const ROLE_TRN: &str = "trn:iam::2000012345:role/reader";
    const REGION: &str = "cn-beijing";
    const SESSION_NAME: &str = "test-01";
    const SIGNING_TIME: &str = "2030-01-02T03:04:05Z";
    const FAR_FUTURE_EXPIRY: &str = "2124-05-25T11:45:17Z";
    const SIGNER_SIGNING_TIME: &str = "2124-05-25T10:45:17Z";
    const SIGNER_EXPIRY: &str = "2124-05-25T11:45:17Z";
    const GRANTED_ACCESS_KEY: &str = "tos-sts-ak";
    const GRANTED_SECRET_KEY: &str = "tos-sts-sk";
    const GRANTED_SESSION_TOKEN: &str = "tos-sts-token";
    const POLICY: &str = r#"{"Statement":[{"Effect":"Allow","Action":["tos:GetObject"],"Resource":["trn:tos:::bucket/example/a b+c%d&e.json"]}]}"#;

    // These fixed vectors were calculated independently from the documented
    // OpenAPI HMAC-SHA256 algorithm for the exact requests exercised below.
    const LONG_LIVED_QUERY: &str = "Action=AssumeRole&DurationSeconds=900&RoleSessionName=test-01&RoleTrn=trn%3Aiam%3A%3A2000012345%3Arole%2Freader&Version=2018-01-01";
    const LONG_LIVED_AUTHORIZATION: &str = "HMAC-SHA256 Credential=synthetic-ak/20300102/cn-beijing/sts/request, SignedHeaders=host;x-date, Signature=351a644bce27ef36722f7585c106f149642555769e6231d64f325078b921e88e";

    const TEMPORARY_QUERY: &str = "Action=AssumeRole&DurationSeconds=3600&Policy=%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22tos%3AGetObject%22%5D%2C%22Resource%22%3A%5B%22trn%3Atos%3A%3A%3Abucket%2Fexample%2Fa%20b%2Bc%25d%26e.json%22%5D%7D%5D%7D&RoleSessionName=test-01&RoleTrn=trn%3Aiam%3A%3A2000012345%3Arole%2Freader&Version=2018-01-01";
    const TEMPORARY_AUTHORIZATION: &str = "HMAC-SHA256 Credential=synthetic-ak/20300102/cn-beijing/sts/request, SignedHeaders=host;x-date;x-security-token, Signature=2402085d7d642b6ff9c6543740f77408ad19bd6bc896a66437a046ad6a3df1f3";

    #[derive(Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CapturedRequest")
                .field("method", &self.method)
                .field("uri", &"REDACTED")
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
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
        calls: Arc<AtomicUsize>,
    }

    impl Debug for FixedCredentialProvider {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FixedCredentialProvider")
                .finish_non_exhaustive()
        }
    }

    impl FixedCredentialProvider {
        fn new(credential: Credential) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    credential,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl ProvideCredential for FixedCredentialProvider {
        type Credential = Credential;

        async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.credential.clone()))
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must be valid")
    }

    fn source_credential() -> Credential {
        Credential::new(SOURCE_ACCESS_KEY, SOURCE_SECRET_KEY)
    }

    fn source_provider() -> (FixedCredentialProvider, Arc<AtomicUsize>) {
        FixedCredentialProvider::new(source_credential())
    }

    fn response(status: http::StatusCode, body: impl Into<Bytes>) -> http::Response<Bytes> {
        http::Response::builder()
            .status(status)
            .body(body.into())
            .expect("response must build")
    }

    fn success_body(expired_time: &str) -> Vec<u8> {
        format!(
            r#"{{"ResponseMetadata":{{"RequestId":"request-id","Action":"AssumeRole","Version":"2018-01-01","Service":"sts"}},"Result":{{"Credentials":{{"ExpiredTime":"{expired_time}","AccessKeyId":"{GRANTED_ACCESS_KEY}","SecretAccessKey":"{GRANTED_SECRET_KEY}","SessionToken":"{GRANTED_SESSION_TOKEN}"}}}}}}"#
        )
        .into_bytes()
    }

    fn granter(signing_time: Timestamp) -> AssumeRoleGranter {
        AssumeRoleGranter::new(REGION, AssumeRoleGrant::new(ROLE_TRN, SESSION_NAME))
            .with_time(signing_time)
    }

    fn request_parts() -> http::request::Parts {
        http::Request::get("https://bucket.tos-cn-beijing.volces.com/object")
            .body(())
            .expect("request must build")
            .into_parts()
            .0
    }

    fn assert_request_head_unchanged(
        actual: &http::request::Parts,
        expected: &http::request::Parts,
    ) {
        assert_eq!(actual.method, expected.method);
        assert_eq!(actual.uri, expected.uri);
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.headers, expected.headers);
    }

    #[tokio::test]
    async fn fixed_long_lived_signing_vector() -> Result<()> {
        let signing_time = timestamp(SIGNING_TIME);
        let http_send = MockHttpSend::new([response(
            http::StatusCode::OK,
            success_body(FAR_FUTURE_EXPIRY),
        )]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, provider_calls) = source_provider();

        let credential = Granter::new(ctx, provider, granter(signing_time))
            .grant(Some(Duration::from_secs(900)))
            .await?;

        assert_eq!(GRANTED_ACCESS_KEY, credential.access_key_id);
        assert_eq!(GRANTED_SECRET_KEY, credential.secret_access_key);
        assert_eq!(
            Some(GRANTED_SESSION_TOKEN),
            credential.session_token.as_deref()
        );
        assert_eq!(Some(timestamp(FAR_FUTURE_EXPIRY)), credential.expires_at);
        assert_eq!(1, provider_calls.load(Ordering::SeqCst));
        assert_eq!(1, http_send.calls());

        let request = &http_send.requests()[0];
        assert_eq!(http::Method::GET, request.method);
        assert_eq!(
            format!("https://sts.cn-beijing.volcengineapi.com/?{LONG_LIVED_QUERY}"),
            request.uri.to_string()
        );
        assert_eq!(
            HeaderValue::from_static("20300102T030405Z"),
            request.headers[HEADER_X_DATE]
        );
        assert_eq!(
            HeaderValue::from_static(LONG_LIVED_AUTHORIZATION),
            request.headers[AUTHORIZATION]
        );
        assert!(request.headers[AUTHORIZATION].is_sensitive());
        assert!(!request.headers.contains_key(HEADER_X_SECURITY_TOKEN));
        assert!(request.body.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn temporary_source_and_policy_are_encoded_and_signed_once() -> Result<()> {
        let signing_time = timestamp(SIGNING_TIME);
        let source = Credential::new(SOURCE_ACCESS_KEY, SOURCE_SECRET_KEY)
            .with_session_token(SOURCE_SESSION_TOKEN)
            .with_expires_at("2124-05-25T11:45:17Z".parse()?);
        let (provider, provider_calls) = FixedCredentialProvider::new(source);
        let http_send = MockHttpSend::new([response(
            http::StatusCode::OK,
            success_body(FAR_FUTURE_EXPIRY),
        )]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let grant = AssumeRoleGrant::new(ROLE_TRN, SESSION_NAME).with_policy(POLICY);
        let granter = AssumeRoleGranter::new(REGION, grant).with_time(signing_time);

        let credential = Granter::new(ctx, provider, granter)
            .grant(Some(Duration::from_secs(3600)))
            .await?;

        assert_eq!(
            Some(GRANTED_SESSION_TOKEN),
            credential.session_token.as_deref()
        );
        assert_eq!(1, provider_calls.load(Ordering::SeqCst));
        assert_eq!(1, http_send.calls());

        let request = &http_send.requests()[0];
        assert_eq!(http::Method::GET, request.method);
        assert_eq!(
            format!("https://sts.cn-beijing.volcengineapi.com/?{TEMPORARY_QUERY}"),
            request.uri.to_string()
        );
        assert_eq!(
            HeaderValue::from_static(TEMPORARY_AUTHORIZATION),
            request.headers[AUTHORIZATION]
        );
        assert!(request.headers[AUTHORIZATION].is_sensitive());
        assert_eq!(
            HeaderValue::from_static(SOURCE_SESSION_TOKEN),
            request.headers[HEADER_X_SECURITY_TOKEN]
        );
        assert!(request.headers[HEADER_X_SECURITY_TOKEN].is_sensitive());

        let policy = request
            .uri
            .query()
            .expect("query must exist")
            .split('&')
            .find_map(|pair| pair.strip_prefix("Policy="))
            .expect("Policy must be present");
        assert_eq!(
            POLICY,
            percent_decode_str(policy)
                .decode_utf8()
                .expect("encoded policy must be valid UTF-8")
        );
        Ok(())
    }

    #[tokio::test]
    async fn omitted_duration_uses_the_service_default() -> Result<()> {
        let signing_time = timestamp(SIGNING_TIME);
        let http_send = MockHttpSend::new([response(
            http::StatusCode::OK,
            success_body(FAR_FUTURE_EXPIRY),
        )]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = source_provider();

        Granter::new(ctx, provider, granter(signing_time))
            .grant(None)
            .await?;

        assert_eq!(
            "https://sts.cn-beijing.volcengineapi.com/?Action=AssumeRole&RoleSessionName=test-01&RoleTrn=trn%3Aiam%3A%3A2000012345%3Arole%2Freader&Version=2018-01-01",
            http_send.requests()[0].uri.to_string()
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_grant_duration_source_and_endpoint_before_io() {
        let signing_time = timestamp(SIGNING_TIME);

        for duration in [
            Some(Duration::from_secs(899)),
            Some(Duration::from_secs(43_201)),
            Some(Duration::from_millis(900_500)),
        ] {
            let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
            let ctx = crate::test_context().with_http_send(http_send.clone());
            let (provider, _) = source_provider();
            let err = Granter::new(ctx, provider, granter(signing_time))
                .grant(duration)
                .await
                .expect_err("invalid duration must be rejected");
            assert_eq!(ErrorKind::RequestInvalid, err.kind());
            assert_eq!(0, http_send.calls());
        }

        let invalid_grants = [
            AssumeRoleGrant::new("", SESSION_NAME),
            AssumeRoleGrant::new("trn:iam::2000012345:user/reader", SESSION_NAME),
            AssumeRoleGrant::new("trn:iam:::role/reader", SESSION_NAME),
            AssumeRoleGrant::new(ROLE_TRN, ""),
            AssumeRoleGrant::new(ROLE_TRN, "a"),
            AssumeRoleGrant::new(ROLE_TRN, "bad name"),
            AssumeRoleGrant::new(ROLE_TRN, "bad/name"),
            AssumeRoleGrant::new(ROLE_TRN, SESSION_NAME).with_policy("   "),
        ];
        for grant in invalid_grants {
            let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
            let ctx = crate::test_context().with_http_send(http_send.clone());
            let (provider, _) = source_provider();
            let err = Granter::new(
                ctx,
                provider,
                AssumeRoleGranter::new(REGION, grant).with_time(signing_time),
            )
            .grant(None)
            .await
            .expect_err("invalid grant must be rejected before I/O");
            assert_eq!(ErrorKind::RequestInvalid, err.kind());
            assert_eq!(0, http_send.calls());
        }

        let invalid_sources = [
            Credential::new("", SOURCE_SECRET_KEY),
            Credential::new(SOURCE_ACCESS_KEY, ""),
            source_credential().with_session_token(" "),
        ];
        for source in invalid_sources {
            let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
            let ctx = crate::test_context().with_http_send(http_send.clone());
            let (provider, _) = FixedCredentialProvider::new(source);
            let err = Granter::new(ctx, provider, granter(signing_time))
                .grant(None)
                .await
                .expect_err("invalid source must be rejected before I/O");
            assert_eq!(ErrorKind::CredentialInvalid, err.kind());
            assert_eq!(0, http_send.calls());
        }

        let expired_source =
            source_credential().with_expires_at(signing_time + Duration::from_secs(19));
        let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = FixedCredentialProvider::new(expired_source);
        let err = Granter::new(ctx, provider, granter(signing_time))
            .grant(None)
            .await
            .expect_err("source that cannot cover the request must be rejected");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert_eq!(0, http_send.calls());

        let http_send = MockHttpSend::new(Vec::<http::Response<Bytes>>::new());
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = source_provider();
        let err = Granter::new(
            ctx,
            provider,
            granter(signing_time).with_sts_endpoint("https://sts.example.com/path"),
        )
        .grant(None)
        .await
        .expect_err("endpoint with a path must be rejected before I/O");
        assert_eq!(ErrorKind::ConfigInvalid, err.kind());
        assert_eq!(0, http_send.calls());
    }

    #[tokio::test]
    async fn maps_sts_errors_without_exposing_request_secrets() {
        let signing_time = timestamp(SIGNING_TIME);
        let error_body = serde_json::to_vec(&serde_json::json!({
            "ResponseMetadata": {
                "RequestId": "request-id",
                "Error": {
                    "Code": "SignatureDoesNotMatch",
                    "Message": format!("{SOURCE_SECRET_KEY} {POLICY}"),
                },
            },
        }))
        .expect("error body must serialize");
        let http_send = MockHttpSend::new([response(http::StatusCode::UNAUTHORIZED, error_body)]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = FixedCredentialProvider::new(
            source_credential().with_session_token(SOURCE_SESSION_TOKEN),
        );
        let err = Granter::new(ctx, provider, granter(signing_time))
            .grant(None)
            .await
            .expect_err("STS error must be returned");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert_eq!(1, http_send.calls());
        let debug = format!("{err:?}");
        assert!(debug.contains("SignatureDoesNotMatch"));
        assert!(!debug.contains(SOURCE_SECRET_KEY));
        assert!(!debug.contains(SOURCE_SESSION_TOKEN));
        assert!(!debug.contains(POLICY));

        let http_send = MockHttpSend::new([response(
            http::StatusCode::FORBIDDEN,
            br#"{"ResponseMetadata":{"Error":{"Code":"AccessDenied"}}}"#.as_slice(),
        )]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = source_provider();
        let err = Granter::new(ctx, provider, granter(signing_time))
            .grant(None)
            .await
            .expect_err("denied request must be returned");
        assert_eq!(ErrorKind::PermissionDenied, err.kind());
        assert_eq!(1, http_send.calls());

        let http_send = MockHttpSend::new([response(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"ResponseMetadata":{"Error":{"Code":"InternalError"}}}"#.as_slice(),
        )]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = source_provider();
        let err = Granter::new(ctx, provider, granter(signing_time))
            .grant(None)
            .await
            .expect_err("server error must be returned");
        assert_eq!(ErrorKind::Unexpected, err.kind());
        assert!(err.is_retryable());
        assert_eq!(1, http_send.calls());
    }

    #[tokio::test]
    async fn rejects_malformed_and_expired_responses_after_io() {
        let signing_time = timestamp(SIGNING_TIME);
        let malformed = [
            br#"{"ResponseMetadata":{},"Result":{}}"#.as_slice(),
            br#"{"ResponseMetadata":{},"Result":{"Credentials":{"ExpiredTime":"2124-05-25T11:45:17Z","AccessKeyId":"","SecretAccessKey":"tos-sts-sk","SessionToken":"tos-sts-token"}}}"#.as_slice(),
            br#"{"ResponseMetadata":{},"Result":{"Credentials":{"AccessKeyId":"tos-sts-ak","SecretAccessKey":"tos-sts-sk","SessionToken":"tos-sts-token"}}}"#.as_slice(),
            br#"{"ResponseMetadata":{},"Result":{"Credentials":{"ExpiredTime":"2124-05-25T11:45:17Z","AccessKeyId":"tos-sts-ak","SecretAccessKey":"tos-sts-sk","SessionToken":" "}}}"#.as_slice(),
            br#"{"ResponseMetadata":{},"Result":{"Credentials":{"ExpiredTime":"not-a-time","AccessKeyId":"tos-sts-ak","SecretAccessKey":"tos-sts-sk","SessionToken":"tos-sts-token"}}}"#.as_slice(),
        ];
        for body in malformed {
            let http_send = MockHttpSend::new([response(http::StatusCode::OK, body)]);
            let ctx = crate::test_context().with_http_send(http_send.clone());
            let (provider, _) = source_provider();
            let err = Granter::new(ctx, provider, granter(signing_time))
                .grant(None)
                .await
                .expect_err("malformed response must be rejected");
            assert_eq!(ErrorKind::Unexpected, err.kind());
            assert_eq!(1, http_send.calls());
        }

        let http_send = MockHttpSend::new([response(
            http::StatusCode::OK,
            success_body("2030-01-02T04:04:05Z"),
        )]);
        let ctx = crate::test_context().with_http_send(http_send.clone());
        let (provider, _) = source_provider();
        let err = Granter::new(
            ctx,
            provider,
            granter(signing_time).with_time_after_request(timestamp("2030-01-02T04:04:05Z")),
        )
        .grant(None)
        .await
        .expect_err("credential that expires during the request must be rejected");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert_eq!(1, http_send.calls());
        let debug = format!("{err:?}");
        assert!(debug.contains("already expired"));
        assert!(!debug.contains(GRANTED_SECRET_KEY));
        assert!(!debug.contains(GRANTED_SESSION_TOKEN));
    }

    #[tokio::test]
    async fn granted_credential_drives_header_signing_and_presign_expiry() -> Result<()> {
        let signing_time = timestamp(SIGNER_SIGNING_TIME);
        let http_send =
            MockHttpSend::new([response(http::StatusCode::OK, success_body(SIGNER_EXPIRY))]);
        let ctx = crate::test_context().with_http_send(http_send);
        let (provider, _) = source_provider();
        let granted = Granter::new(ctx, provider, granter(signing_time))
            .grant(Some(Duration::from_secs(3600)))
            .await?;
        let (provider, _) = FixedCredentialProvider::new(granted.clone());
        let signer = Signer::new(
            crate::test_context(),
            provider,
            RequestSigner::new(REGION).with_time(signing_time),
        );

        let mut header_request = request_parts();
        signer.sign(&mut header_request, None).await?;
        let authorization = header_request.headers[AUTHORIZATION]
            .to_str()
            .expect("authorization must be ASCII");
        assert!(authorization.contains(GRANTED_ACCESS_KEY));
        assert_eq!(
            GRANTED_SESSION_TOKEN,
            header_request.headers["x-tos-security-token"]
        );

        let mut presign_request = request_parts();
        signer
            .sign(&mut presign_request, Some(Duration::from_secs(3599)))
            .await?;
        let query = presign_request
            .uri
            .query()
            .expect("presign query must exist");
        assert!(query.contains(&format!("X-Tos-Security-Token={GRANTED_SESSION_TOKEN}")));
        assert!(query.contains(&format!("X-Tos-Credential={GRANTED_ACCESS_KEY}%2F")));

        let mut expired_request = request_parts();
        let expected = expired_request.clone();
        let err = signer
            .sign(&mut expired_request, Some(Duration::from_secs(3600)))
            .await
            .expect_err("presign lifetime that reaches ExpiredTime must fail");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert_request_head_unchanged(&expired_request, &expected);

        let direct_signer = RequestSigner::new(REGION).with_time(signing_time);
        let mut direct_request = request_parts();
        let expected = direct_request.clone();
        let err = direct_signer
            .sign_request(
                &crate::test_context(),
                &mut direct_request,
                Some(&granted),
                Some(Duration::from_secs(3600)),
            )
            .await
            .expect_err("direct presign must also enforce ExpiredTime");
        assert_eq!(ErrorKind::CredentialInvalid, err.kind());
        assert_request_head_unchanged(&direct_request, &expected);
        Ok(())
    }

    #[test]
    fn grant_and_granter_debug_are_redacted() {
        let grant = AssumeRoleGrant::new(ROLE_TRN, SESSION_NAME).with_policy(POLICY);
        let debug = format!("{grant:?}");
        assert!(debug.contains(ROLE_TRN));
        assert!(debug.contains(SESSION_NAME));
        assert!(!debug.contains(POLICY));

        let debug = format!("{:?}", granter(timestamp(SIGNING_TIME)));
        assert!(!debug.contains(ROLE_TRN));
        assert!(!debug.contains(POLICY));

        let debug = format!("{:?}", source_credential());
        assert!(!debug.contains(SOURCE_ACCESS_KEY));
        assert!(!debug.contains(SOURCE_SECRET_KEY));

        let debug = format!(
            "{:?}",
            source_credential().with_session_token(SOURCE_SESSION_TOKEN)
        );
        assert!(!debug.contains(SOURCE_SESSION_TOKEN));
    }
}
