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

//! Huawei Cloud IAM agency credential granting.
//!
//! [`AgencyGranter`] consumes an existing OBS [`Credential`] and calls the IAM
//! `assume_role` endpoint used by `CreateTemporaryAccessKeyByAgency`. The
//! returned credential contains the newly issued temporary AK/SK/security token
//! and the exact absolute `expires_at` reported by IAM, so it can be passed
//! directly to the existing OBS [`RequestSigner`](crate::RequestSigner).
//!
//! The IAM request is signed with Huawei `SDK-HMAC-SHA256`, not the OBS
//! signature algorithm. See
//! <https://support.huaweicloud.com/intl/en-us/api-iam/iam_04_0101.html>
//! and
//! <https://support.huaweicloud.com/intl/en-us/devg-apisign/api-sign-algorithm-001.html>.

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::time::Duration;

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use reqsign_core::hash::{hex_hmac_sha256, hex_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use serde::{Deserialize, Serialize};

use crate::Credential;

const DEFAULT_IAM_ENDPOINT: &str = "https://iam.myhuaweicloud.com";
const IAM_SECURITY_TOKENS_PATH: &str = "/v3.0/OS-CREDENTIAL/securitytokens";
const IAM_CONTENT_TYPE: &str = "application/json;charset=utf8";
const X_SDK_DATE: &str = "x-sdk-date";
const X_SECURITY_TOKEN: &str = "x-security-token";
const SDK_HMAC_SHA256: &str = "SDK-HMAC-SHA256";
const IAM_REQUEST_HEADROOM: Duration = Duration::from_secs(20);
const MIN_AGENCY_DURATION: Duration = Duration::from_secs(900);
const MAX_AGENCY_DURATION: Duration = Duration::from_secs(86_400);

#[derive(Clone, Debug, PartialEq, Eq)]
enum DelegatingDomain {
    Id(String),
    Name(String),
}

/// A typed Huawei Cloud IAM agency grant.
///
/// The delegating domain identifies the account that owns the agency. IAM
/// accepts either a domain ID or a domain name for this field; binding one of
/// them here makes the authority transition explicit. Reqsign does not add a
/// policy, session user, or default-chain behavior to this grant.
#[derive(Clone, Debug)]
pub struct AgencyGrant {
    agency_name: String,
    delegating_domain: DelegatingDomain,
}

impl AgencyGrant {
    /// Create a grant that identifies the delegating account by domain ID.
    pub fn new(agency_name: impl Into<String>, domain_id: impl Into<String>) -> Self {
        Self {
            agency_name: agency_name.into(),
            delegating_domain: DelegatingDomain::Id(domain_id.into()),
        }
    }

    /// Create a grant that identifies the delegating account by domain name.
    pub fn with_domain_name(
        agency_name: impl Into<String>,
        domain_name: impl Into<String>,
    ) -> Self {
        Self {
            agency_name: agency_name.into(),
            delegating_domain: DelegatingDomain::Name(domain_name.into()),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.agency_name.trim().is_empty() {
            return Err(Error::request_invalid(
                "Huawei Cloud IAM agency name must not be empty",
            ));
        }

        let (field, value) = self.domain();
        if value.trim().is_empty() {
            return Err(Error::request_invalid(format!(
                "Huawei Cloud IAM delegating {field} must not be empty"
            )));
        }
        Ok(())
    }

    fn domain(&self) -> (&'static str, &str) {
        match &self.delegating_domain {
            DelegatingDomain::Id(value) => ("domain_id", value),
            DelegatingDomain::Name(value) => ("domain_name", value),
        }
    }
}

/// Explicitly grants a Huawei Cloud IAM agency credential.
///
/// The source credential supplied by [`reqsign_core::Granter`] signs the IAM
/// request with `SDK-HMAC-SHA256`. Both a permanent source credential and a
/// temporary source credential are accepted; a temporary source's security
/// token is sent as `X-Security-Token` and included in the signature.
///
/// The target authority is the bound agency and delegating domain. The granted
/// credential may have permissions from the agency that are not a subset of the
/// source principal's direct permissions, so this is an explicit authority
/// transition rather than a generic downscoping operation.
///
/// `expires_in` maps to `duration_seconds`. `None` omits the field and uses the
/// IAM default of 900 seconds. An explicit lifetime must be a whole number of
/// seconds between 900 and 86400. The service remains authoritative for the
/// actual expiration reported in `credential.expires_at`.
///
/// Every grant performs a new IAM exchange. The returned credential is never
/// cached by this granter or by core.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use reqsign_core::{Context, Granter};
/// use reqsign_huaweicloud_obs::{AgencyGrant, AgencyGranter, StaticCredentialProvider};
///
/// # async fn example() -> reqsign_core::Result<()> {
/// let source = StaticCredentialProvider::new("source-access-key", "source-secret-key");
/// let grant = AgencyGrant::new("obs-reader", "1234567890123456");
/// // Supply a Context configured with an HttpSend implementation.
/// let credential = Granter::new(
///     Context::new(),
///     source,
///     AgencyGranter::new(grant),
/// )
/// .grant(Some(Duration::from_secs(3600)))
/// .await?;
/// # let _ = credential;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AgencyGranter {
    grant: AgencyGrant,
    iam_endpoint: Option<String>,
    #[cfg(test)]
    now: Option<Timestamp>,
    #[cfg(test)]
    time_after_request: Option<Timestamp>,
}

impl Debug for AgencyGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgencyGranter").finish_non_exhaustive()
    }
}

impl AgencyGranter {
    /// Create a granter for a bound agency and delegating domain.
    ///
    /// The IAM endpoint defaults to `https://iam.myhuaweicloud.com`. Use
    /// [`AgencyGranter::with_iam_endpoint`] for a region-specific IAM endpoint.
    pub fn new(grant: AgencyGrant) -> Self {
        Self {
            grant,
            iam_endpoint: None,
            #[cfg(test)]
            now: None,
            #[cfg(test)]
            time_after_request: None,
        }
    }

    /// Replace the bound agency grant.
    pub fn with_grant(mut self, grant: AgencyGrant) -> Self {
        self.grant = grant;
        self
    }

    /// Set the IAM endpoint. Accepts a bare host or a full URL.
    ///
    /// The endpoint must be an HTTP(S) origin without a path or query. The
    /// default is `https://iam.myhuaweicloud.com`. Callers that replace it are
    /// responsible for trusting the endpoint with their IAM credentials.
    pub fn with_iam_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.iam_endpoint = Some(endpoint.into());
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
            .iam_endpoint
            .as_deref()
            .unwrap_or(DEFAULT_IAM_ENDPOINT)
            .trim();
        let endpoint = if endpoint.contains("://") {
            endpoint.to_string()
        } else {
            format!("https://{endpoint}")
        };
        let endpoint = endpoint.trim_end_matches('/');
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|_| Error::config_invalid("invalid Huawei Cloud IAM endpoint"))?;
        let scheme = uri
            .scheme_str()
            .filter(|scheme| matches!(*scheme, "http" | "https"))
            .ok_or_else(|| {
                Error::config_invalid("Huawei Cloud IAM endpoint must use HTTP or HTTPS")
            })?;
        let authority = uri
            .authority()
            .ok_or_else(|| Error::config_invalid("Huawei Cloud IAM endpoint has no authority"))?;
        let authority = authority.as_str().to_ascii_lowercase();
        if authority.contains('@') {
            return Err(Error::config_invalid(
                "Huawei Cloud IAM endpoint must not contain user information",
            ));
        }
        if uri.query().is_some() {
            return Err(Error::config_invalid(
                "Huawei Cloud IAM endpoint must not contain a query",
            ));
        }
        if !matches!(uri.path(), "" | "/") {
            return Err(Error::config_invalid(
                "Huawei Cloud IAM endpoint must not contain a path",
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
        if expires_in < MIN_AGENCY_DURATION
            || expires_in > MAX_AGENCY_DURATION
            || expires_in.subsec_nanos() != 0
        {
            return Err(Error::request_invalid(
                "Huawei Cloud IAM agency duration must be a whole number of seconds between 900 and 86400",
            ));
        }
        Ok(Some(expires_in.as_secs()))
    }

    fn validate_source(&self, credential: &Credential, required_until: Timestamp) -> Result<()> {
        if credential.access_key_id.is_empty()
            || credential.secret_access_key.is_empty()
            || http::HeaderValue::try_from(credential.access_key_id.as_str()).is_err()
        {
            return Err(Error::credential_invalid(
                "Huawei Cloud IAM agency grant requires a source access key and secret access key",
            ));
        }
        if credential.security_token.as_ref().is_some_and(|token| {
            token.trim().is_empty() || http::HeaderValue::try_from(token.trim()).is_err()
        }) {
            return Err(Error::credential_invalid(
                "Huawei Cloud IAM agency source security token is invalid",
            ));
        }
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Huawei source credential expires before the IAM agency request can complete",
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
        let (domain_field, domain_value) = self.grant.domain();
        let body = serde_json::to_vec(&AgencyRequest {
            auth: AgencyAuth {
                identity: AgencyIdentity {
                    methods: ["assume_role"],
                    assume_role: AgencyAssumeRole {
                        agency_name: &self.grant.agency_name,
                        domain_id: (domain_field == "domain_id").then_some(domain_value),
                        domain_name: (domain_field == "domain_name").then_some(domain_value),
                        duration_seconds,
                    },
                },
            },
        })
        .map_err(|err| {
            Error::unexpected("failed to serialize Huawei Cloud IAM agency request")
                .with_source(err)
        })?;

        let signing_date = signing_time.format_iso8601();
        let mut signed_headers = BTreeMap::new();
        signed_headers.insert("content-type".to_string(), IAM_CONTENT_TYPE.to_string());
        signed_headers.insert("host".to_string(), endpoint.authority.clone());
        signed_headers.insert(X_SDK_DATE.to_string(), signing_date.clone());
        if let Some(token) = &credential.security_token {
            signed_headers.insert(X_SECURITY_TOKEN.to_string(), token.trim().to_string());
        }
        let authorization = authorization_header(
            http::Method::POST.as_str(),
            IAM_SECURITY_TOKENS_PATH,
            "",
            &signed_headers,
            &body,
            &credential.access_key_id,
            &credential.secret_access_key,
        )?;

        let mut request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("{}{}", endpoint.origin, IAM_SECURITY_TOKENS_PATH))
            .header(CONTENT_TYPE, IAM_CONTENT_TYPE)
            .header("X-Sdk-Date", &signing_date)
            .header(AUTHORIZATION, authorization)
            .body(body)
            .map_err(|_| {
                Error::request_invalid("failed to build Huawei Cloud IAM agency request")
            })?;
        request
            .headers_mut()
            .get_mut(AUTHORIZATION)
            .expect("authorization header was just inserted")
            .set_sensitive(true);
        if let Some(token) = &credential.security_token {
            request
                .headers_mut()
                .insert("x-security-token", token.parse()?);
            request
                .headers_mut()
                .get_mut("x-security-token")
                .expect("security token header was just inserted")
                .set_sensitive(true);
        }
        Ok(request)
    }

    fn parse_response<B: AsRef<[u8]>>(
        &self,
        response: http::Response<B>,
        response_time: Timestamp,
    ) -> Result<Credential> {
        let status = response.status();
        if !status.is_success() {
            return Err(iam_status_error(status));
        }

        let response: AgencyResponse = serde_json::from_slice(response.body().as_ref())
            .map_err(|_| Error::unexpected("failed to parse Huawei Cloud IAM agency response"))?;
        let issued = response.credential.ok_or_else(|| {
            Error::unexpected("Huawei Cloud IAM agency response has no credential")
        })?;
        if issued.access.is_empty()
            || issued.secret.is_empty()
            || issued.securitytoken.is_empty()
            || http::HeaderValue::try_from(issued.access.as_str()).is_err()
            || http::HeaderValue::try_from(issued.securitytoken.as_str()).is_err()
        {
            return Err(Error::unexpected(
                "Huawei Cloud IAM agency response contains invalid credential material",
            ));
        }

        let expires_at: Timestamp = issued.expires_at.parse().map_err(|_| {
            Error::unexpected("Huawei Cloud IAM agency response expiration is invalid")
        })?;
        if expires_at <= response_time {
            return Err(Error::credential_invalid(
                "Huawei Cloud IAM agency returned a credential that is already expired",
            ));
        }

        Ok(
            Credential::new(issued.access, issued.secret, Some(issued.securitytoken))
                .with_expires_at(expires_at),
        )
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

impl GrantCredential for AgencyGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now() + IAM_REQUEST_HEADROOM
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
                Error::new(err.kind(), "Huawei Cloud IAM agency request failed")
                    .set_retryable(err.is_retryable())
            })?;
        self.parse_response(response, self.time_after_request())
    }
}

struct ValidatedEndpoint {
    origin: String,
    authority: String,
}

fn authorization_header(
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<String> {
    let mut canonical_uri = path.to_string();
    if !canonical_uri.ends_with('/') {
        canonical_uri.push('/');
    }

    let normalized_headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let mut canonical_headers = String::new();
    let mut signed_header_names = Vec::with_capacity(normalized_headers.len());
    for (name, value) in &normalized_headers {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
        signed_header_names.push(name.as_str());
    }
    let signed_headers = signed_header_names.join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
        hex_sha256(body)?
    );
    let signing_date = normalized_headers.get(X_SDK_DATE).ok_or_else(|| {
        Error::request_invalid("Huawei Cloud IAM request is missing the X-Sdk-Date header")
    })?;
    let string_to_sign = format!(
        "{SDK_HMAC_SHA256}\n{signing_date}\n{}",
        hex_sha256(canonical_request.as_bytes())?
    );
    let signature = hex_hmac_sha256(secret_access_key.as_bytes(), string_to_sign.as_bytes())?;

    Ok(format!(
        "{SDK_HMAC_SHA256} Access={access_key_id}, SignedHeaders={signed_headers}, Signature={signature}"
    ))
}

fn iam_status_error(status: http::StatusCode) -> Error {
    match status.as_u16() {
        400 => Error::request_invalid("Huawei Cloud IAM agency request was rejected"),
        401 => Error::credential_invalid("Huawei Cloud IAM agency source authentication failed"),
        403 => Error::permission_denied("Huawei Cloud IAM agency grant was denied"),
        429 => Error::rate_limited("Huawei Cloud IAM agency grant was rate limited"),
        500..=599 => Error::unexpected("Huawei Cloud IAM agency grant failed").set_retryable(true),
        _ => Error::unexpected("Huawei Cloud IAM agency grant failed"),
    }
}

#[derive(Serialize)]
struct AgencyRequest<'a> {
    auth: AgencyAuth<'a>,
}

#[derive(Serialize)]
struct AgencyAuth<'a> {
    identity: AgencyIdentity<'a>,
}

#[derive(Serialize)]
struct AgencyIdentity<'a> {
    methods: [&'static str; 1],
    assume_role: AgencyAssumeRole<'a>,
}

#[derive(Serialize)]
struct AgencyAssumeRole<'a> {
    agency_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct AgencyResponse {
    credential: Option<AgencyCredential>,
}

#[derive(Deserialize)]
struct AgencyCredential {
    #[serde(default)]
    access: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    securitytoken: String,
    #[serde(default)]
    expires_at: String,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use reqsign_core::{ErrorKind, Granter, HttpSend, ProvideCredential, Signer};

    use super::*;

    const SOURCE_ACCESS_KEY: &str = "HUAWEI_SOURCE_ACCESS_KEY";
    const SOURCE_SECRET_KEY: &str = "source-secret-key";
    const SOURCE_SECURITY_TOKEN: &str = "source-security-token";
    const GRANTED_ACCESS_KEY: &str = "GRANTED_ACCESS_KEY";
    const GRANTED_SECRET_KEY: &str = "granted-secret-key";
    const GRANTED_SECURITY_TOKEN: &str = "granted-security-token";
    const EXPIRATION: &str = "2099-11-19T08:00:00.123456Z";
    const EXPECTED_AUTHORIZATION: &str = "SDK-HMAC-SHA256 Access=HUAWEI_SOURCE_ACCESS_KEY, SignedHeaders=content-type;host;x-sdk-date;x-security-token, Signature=fdbd60e8f05280961c92f4ed3b515bc911da23f183d77d86fbf81423bec83424";
    const BODY: &str = r#"{"auth":{"identity":{"methods":["assume_role"],"assume_role":{"agency_name":"obs-reader","domain_id":"1234567890123456","duration_seconds":3600}}}}"#;

    fn signing_time() -> Timestamp {
        "2026-11-19T08:00:00Z"
            .parse()
            .expect("signing time must parse")
    }

    fn source_credential(
        security_token: Option<&str>,
        expires_at: Option<Timestamp>,
    ) -> Credential {
        let credential = Credential::new(
            SOURCE_ACCESS_KEY.to_string(),
            SOURCE_SECRET_KEY.to_string(),
            security_token.map(str::to_owned),
        );
        match expires_at {
            Some(expires_at) => credential.with_expires_at(expires_at),
            None => credential,
        }
    }

    fn grant() -> AgencyGrant {
        AgencyGrant::new("obs-reader", "1234567890123456")
    }

    fn success_response_with_expiry(expires_at: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(http::StatusCode::CREATED)
            .body(Bytes::from(format!(
                r#"{{"credential":{{"access":"{GRANTED_ACCESS_KEY}","secret":"{GRANTED_SECRET_KEY}","securitytoken":"{GRANTED_SECURITY_TOKEN}","expires_at":"{expires_at}"}}}}"#
            )))
            .expect("response must build")
    }

    fn success_response() -> http::Response<Bytes> {
        success_response_with_expiry(EXPIRATION)
    }

    #[derive(Clone)]
    struct CapturedRequest {
        method: http::Method,
        uri: http::Uri,
        headers: http::HeaderMap,
        body: Bytes,
    }

    impl Debug for CapturedRequest {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().expect("lock poisoned").clone()
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
                    body,
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

    #[tokio::test]
    async fn grants_exact_request_and_returns_issued_expiry() {
        let http = MockHttpSend::new([success_response()]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, provider_calls) =
            FixedCredentialProvider::new(source_credential(Some(SOURCE_SECURITY_TOKEN), None));
        let granter = Granter::new(
            context,
            provider,
            AgencyGranter::new(grant()).with_time(signing_time()),
        );

        let credential = granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect("grant must succeed");

        assert_eq!(credential.access_key_id, GRANTED_ACCESS_KEY);
        assert_eq!(credential.secret_access_key, GRANTED_SECRET_KEY);
        assert_eq!(
            credential.security_token.as_deref(),
            Some(GRANTED_SECURITY_TOKEN)
        );
        assert_eq!(
            credential.expires_at,
            Some(EXPIRATION.parse().expect("expiration must parse"))
        );
        assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
        assert_eq!(http.calls(), 1);

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, http::Method::POST);
        assert_eq!(
            requests[0].uri.to_string(),
            "https://iam.myhuaweicloud.com/v3.0/OS-CREDENTIAL/securitytokens"
        );
        assert_eq!(
            requests[0]
                .headers
                .get(CONTENT_TYPE)
                .expect("content type must be set"),
            IAM_CONTENT_TYPE
        );
        assert_eq!(
            requests[0]
                .headers
                .get("x-sdk-date")
                .expect("signing date must be set"),
            "20261119T080000Z"
        );
        assert_eq!(
            requests[0]
                .headers
                .get("x-security-token")
                .expect("source token must be sent"),
            SOURCE_SECURITY_TOKEN
        );
        assert!(
            requests[0]
                .headers
                .get(AUTHORIZATION)
                .expect("authorization must be set")
                .is_sensitive()
        );
        assert!(
            requests[0]
                .headers
                .get("x-security-token")
                .expect("source token must be sent")
                .is_sensitive()
        );
        assert_eq!(
            requests[0]
                .headers
                .get(AUTHORIZATION)
                .expect("authorization must be set")
                .to_str()
                .expect("authorization must be text"),
            EXPECTED_AUTHORIZATION
        );
        assert_eq!(
            std::str::from_utf8(&requests[0].body).expect("body must be UTF-8"),
            BODY
        );

        let (issued_provider, _) = FixedCredentialProvider::new(credential.clone());
        let signer = Signer::new(
            Context::new(),
            issued_provider,
            crate::RequestSigner::new("bucket").with_time(signing_time()),
        );
        let mut parts =
            http::Request::get("https://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("issued credential must sign an OBS request");
        assert_eq!(
            parts
                .headers
                .get("x-obs-security-token")
                .expect("issued token must be sent"),
            GRANTED_SECURITY_TOKEN
        );
        assert!(
            parts
                .headers
                .get(AUTHORIZATION)
                .expect("authorization must be set")
                .to_str()
                .expect("authorization must be text")
                .starts_with(&format!("OBS {GRANTED_ACCESS_KEY}:"))
        );
    }

    #[tokio::test]
    async fn supports_permanent_source_and_domain_name() {
        let http = MockHttpSend::new([success_response()]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, _) = FixedCredentialProvider::new(source_credential(None, None));
        let granter = Granter::new(
            context,
            provider,
            AgencyGranter::new(AgencyGrant::with_domain_name("obs-reader", "IAMDomainA"))
                .with_time(signing_time()),
        );

        granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect("grant must succeed");

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].headers.contains_key("x-security-token"));
        let authorization = requests[0]
            .headers
            .get(AUTHORIZATION)
            .expect("authorization must be set")
            .to_str()
            .expect("authorization must be text");
        assert!(authorization.contains("SignedHeaders=content-type;host;x-sdk-date,"));
        let body = std::str::from_utf8(&requests[0].body).expect("body must be UTF-8");
        assert!(body.contains(r#""domain_name":"IAMDomainA""#));
        assert!(!body.contains(r#""domain_id""#));
    }

    #[tokio::test]
    async fn rejects_invalid_duration_before_io() {
        let http = MockHttpSend::new([]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, _) = FixedCredentialProvider::new(source_credential(None, None));
        let granter = Granter::new(
            context,
            provider,
            AgencyGranter::new(grant()).with_time(signing_time()),
        );

        for duration in [
            Duration::from_secs(899),
            Duration::from_secs(86_401),
            Duration::from_millis(900_500),
        ] {
            let err = granter
                .grant(Some(duration))
                .await
                .expect_err("invalid duration must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        assert_eq!(http.calls(), 0);
    }

    #[tokio::test]
    async fn rejects_expired_source_before_io() {
        let http = MockHttpSend::new([]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, _) = FixedCredentialProvider::new(source_credential(
            None,
            Some(signing_time() - Duration::from_secs(1)),
        ));
        let granter = Granter::new(
            context,
            provider,
            AgencyGranter::new(grant()).with_time(signing_time()),
        );

        let err = granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect_err("expired source must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.calls(), 0);
    }

    #[tokio::test]
    async fn rejects_denied_response_without_exposing_body() {
        let http = MockHttpSend::new([http::Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .body(Bytes::from_static(
                br#"{"error_msg":"source-secret-key granted-secret-key source-security-token"}"#,
            ))
            .expect("response must build")]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, _) =
            FixedCredentialProvider::new(source_credential(Some(SOURCE_SECURITY_TOKEN), None));
        let granter = Granter::new(
            context,
            provider,
            AgencyGranter::new(grant()).with_time(signing_time()),
        );

        let err = granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect_err("denied response must fail");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        for output in [err.to_string(), format!("{err:?}")] {
            assert!(!output.contains(SOURCE_SECRET_KEY));
            assert!(!output.contains(GRANTED_SECRET_KEY));
            assert!(!output.contains(SOURCE_SECURITY_TOKEN));
            assert!(!output.contains("error_msg"));
        }
        assert_eq!(http.calls(), 1);
    }

    #[tokio::test]
    async fn rejects_response_expired_after_io() {
        let http = MockHttpSend::new([success_response_with_expiry("2026-11-19T08:00:00Z")]);
        let context = Context::new().with_http_send(http.clone());
        let (provider, _) =
            FixedCredentialProvider::new(source_credential(Some(SOURCE_SECURITY_TOKEN), None));
        let granter = Granter::new(
            context,
            provider,
            AgencyGranter::new(grant())
                .with_time(signing_time())
                .with_time_after_request(signing_time() + Duration::from_secs(1)),
        );

        let err = granter
            .grant(Some(Duration::from_secs(3_600)))
            .await
            .expect_err("expired response must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        for output in [err.to_string(), format!("{err:?}")] {
            assert!(!output.contains(GRANTED_SECRET_KEY));
            assert!(!output.contains(GRANTED_SECURITY_TOKEN));
        }
    }

    #[test]
    fn signs_like_the_official_go_sdk_vector() {
        let headers = BTreeMap::from([("x-sdk-date".to_string(), "20060102T150405Z".to_string())]);

        let authorization = authorization_header(
            "GET",
            "/path",
            "limit=1",
            &headers,
            b"",
            "AccessKey",
            "SecretKey",
        )
        .expect("request must sign");

        assert_eq!(
            authorization,
            "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, Signature=5a2ce64c865e0e6046321c6f3d5a77ba8413eeaf355c3166c03d58d02ac79624"
        );
    }
}
