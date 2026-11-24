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

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use asyncband::mutex::Mutex;
use http::StatusCode;
use http::header::{CONTENT_TYPE, USER_AGENT as USER_AGENT_HEADER};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::{Deserialize, Serialize};

use crate::Credential;
use crate::constants::{DEFAULT_TOKEN_ENDPOINT, USER_AGENT};

/// Exchanges an Aliyun Drive refresh token for an access token.
///
/// Aliyun Drive uses OAuth 2.0 authorization but its documented token endpoint
/// takes a vendor-specific JSON body instead of the RFC 6749
/// `application/x-www-form-urlencoded` format. This provider sends:
///
/// ```json
/// {
///   "client_id": "...",
///   "client_secret": "...",
///   "grant_type": "refresh_token",
///   "refresh_token": "..."
/// }
/// ```
///
/// to the trusted token endpoint with `Content-Type: application/json` and the
/// non-empty `User-Agent` header the endpoint requires. All three client
/// credentials are required: Aliyun Drive's official PKCE public-client flow
/// returns a 30-day access token without a refresh token, so public clients use
/// [`crate::StaticCredentialProvider`] with the access token they obtained.
///
/// Aliyun Drive returns a new single-use refresh token with every successful
/// exchange. A provider keeps only the latest token in memory, clones share
/// that state, and every exchange is serialized so concurrent callers use the
/// latest rotated token. The configured initial refresh token may be consumed
/// after a successful exchange; a restart needs a fresh authorized grant, or an
/// application that manages and persists its own exchange and supplies an
/// access token. Reqsign exposes no persistence callback or token getter.
/// Access-token caching belongs to [`reqsign_core::Signer`]; this provider
/// performs no implicit retry.
///
/// The `expires_in` field is required. The access token's absolute expiration is
/// derived from the time the request started. A success response commits a
/// non-empty rotated refresh token as soon as it can be read, before the
/// remaining fields are validated or reported as unparseable, because the
/// previous refresh token is single-use even when the rest of the response is
/// unusable.
#[derive(Clone)]
pub struct RefreshCredentialProvider {
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    refresh_token: Arc<Mutex<String>>,
}

impl Debug for RefreshCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl RefreshCredentialProvider {
    /// Create a provider for an Aliyun Drive confidential client.
    ///
    /// `client_id`, `client_secret`, and `refresh_token` must be non-empty. The
    /// first-party token endpoint is used until
    /// [`RefreshCredentialProvider::with_token_endpoint`] selects another
    /// trusted endpoint.
    ///
    /// Public clients use the official PKCE flow, which returns an access token
    /// without a refresh token. Supply that access token through
    /// [`crate::StaticCredentialProvider`] instead.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(Error::config_invalid(
                "Aliyun Drive client ID must not be empty",
            ));
        }

        let client_secret = client_secret.into();
        if client_secret.is_empty() {
            return Err(Error::config_invalid(
                "Aliyun Drive client secret must not be empty",
            ));
        }

        let refresh_token = refresh_token.into();
        if refresh_token.is_empty() {
            return Err(Error::config_invalid(
                "Aliyun Drive refresh token must not be empty",
            ));
        }

        Ok(Self {
            token_endpoint: DEFAULT_TOKEN_ENDPOINT.to_string(),
            client_id,
            client_secret,
            refresh_token: Arc::new(Mutex::new(refresh_token)),
        })
    }

    /// Replace the token endpoint while preserving the latest refresh token.
    ///
    /// The endpoint must be an absolute HTTPS URI with a host and without
    /// userinfo or a fragment. The caller owns this explicit trust decision.
    pub fn with_token_endpoint(mut self, token_endpoint: impl Into<String>) -> Result<Self> {
        let token_endpoint = token_endpoint.into();
        validate_token_endpoint(&token_endpoint)?;
        self.token_endpoint = token_endpoint;
        Ok(self)
    }

    async fn exchange(
        &self,
        ctx: &Context,
        current_refresh_token: &mut String,
    ) -> Result<Credential> {
        let started_at = Timestamp::now();
        let request_body = serde_json::to_vec(&TokenRequest {
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            grant_type: "refresh_token",
            refresh_token: current_refresh_token,
        })
        .map_err(|_| Error::unexpected("failed to build Aliyun Drive token request"))?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.token_endpoint.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(USER_AGENT_HEADER, USER_AGENT)
            .body(request_body.into())
            .map_err(|_| Error::unexpected("failed to build Aliyun Drive token request"))?;

        let response = ctx.http_send(request).await.map_err(|err| {
            // Transport error sources can contain the request URI or other
            // caller-held material, so retain only the bounded classification.
            Error::new(err.kind(), "Aliyun Drive token refresh request failed")
                .set_retryable(err.is_retryable())
        })?;

        if !response.status().is_success() {
            return Err(token_exchange_error(response.status(), response.body()));
        }

        let body = response.body();
        let response: TokenResponse = match serde_json::from_slice(body) {
            Ok(response) => response,
            Err(_) => {
                // Aliyun Drive consumes the previous refresh token before it
                // answers. Commit a rotated token that can still be read so a
                // malformed secondary field cannot strand local state on the
                // consumed token, then report the parse failure.
                if let Some(rotated_refresh_token) = extract_rotated_refresh_token(body) {
                    *current_refresh_token = rotated_refresh_token;
                }
                return Err(Error::unexpected(
                    "failed to parse Aliyun Drive token response",
                ));
            }
        };

        let rotated_refresh_token = response
            .refresh_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                Error::unexpected("Aliyun Drive token response omitted a rotated refresh token")
            })?;
        *current_refresh_token = rotated_refresh_token.to_string();

        let token_type = response.token_type.as_deref().unwrap_or_default();
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(Error::unexpected(
                "Aliyun Drive token response did not use the Bearer token type",
            ));
        }

        let expires_in = response.expires_in.ok_or_else(|| {
            Error::credential_invalid(
                "Aliyun Drive token response omitted expires_in required for refresh credentials",
            )
        })?;
        let expires_at = checked_expiration(started_at, expires_in)?;
        let credential =
            Credential::from_parts(response.access_token.unwrap_or_default(), Some(expires_at))
                .map_err(|_| {
                    Error::unexpected("Aliyun Drive token response omitted a usable access token")
                })?;

        if !credential.is_valid_at(Timestamp::now()) {
            return Err(Error::credential_invalid(
                "Aliyun Drive token response is not currently valid",
            ));
        }

        Ok(credential)
    }
}

impl ProvideCredential for RefreshCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let mut current_refresh_token = self.refresh_token.lock().await;
        Ok(Some(self.exchange(ctx, &mut current_refresh_token).await?))
    }
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    grant_type: &'a str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// Extract a rotated refresh token from a body that does not deserialize into
/// [`TokenResponse`].
///
/// Only `refresh_token` is read, so an unexpected type in any other field
/// cannot block the extraction. Returns `None` when the body is not JSON or
/// carries no non-empty `refresh_token` string.
fn extract_rotated_refresh_token(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("refresh_token")?
        .as_str()
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    code: Option<String>,
}

fn validate_token_endpoint(value: &str) -> Result<()> {
    let invalid = || {
        Error::config_invalid(
            "Aliyun Drive token endpoint must be an absolute HTTPS URI with a host and no userinfo or fragment",
        )
    };
    if value.is_empty()
        || value.contains('#')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(invalid());
    }

    let uri: http::Uri = value.parse().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    if uri.scheme_str() != Some("https")
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || (authority.as_str().len() != authority.host().len() && authority.port_u16().is_none())
    {
        return Err(invalid());
    }

    Ok(())
}

fn checked_expiration(started_at: Timestamp, expires_in: u64) -> Result<Timestamp> {
    let expires_in = i64::try_from(expires_in)
        .map_err(|_| Error::unexpected("Aliyun Drive token expiration is invalid"))?;
    let expiration_second = started_at
        .as_second()
        .checked_add(expires_in)
        .ok_or_else(|| Error::unexpected("Aliyun Drive token expiration is invalid"))?;
    Timestamp::from_second(expiration_second)
        .map_err(|_| Error::unexpected("Aliyun Drive token expiration is invalid"))
}

fn token_exchange_error(status: StatusCode, body: &[u8]) -> Error {
    let error_code = serde_json::from_slice::<ErrorResponse>(body)
        .ok()
        .and_then(|response| response.code);
    let recognized_code = match error_code.as_deref() {
        Some(
            code @ ("AppNotExists"
            | "InvalidClientId"
            | "InvalidClientSecret"
            | "InvalidCode"
            | "InvalidGrantType"
            | "RefreshTokenExpired"
            | "RefreshTokenInvalid"
            | "TooManyRequests"),
        ) => Some(code),
        _ => None,
    };

    let mut error = match recognized_code {
        Some("AppNotExists" | "InvalidClientId" | "InvalidClientSecret") => {
            Error::config_invalid("Aliyun Drive token exchange rejected the client configuration")
        }
        Some("InvalidCode" | "RefreshTokenExpired" | "RefreshTokenInvalid") => {
            Error::credential_invalid("Aliyun Drive token exchange rejected the refresh token")
        }
        Some("InvalidGrantType") => {
            Error::request_invalid("Aliyun Drive token exchange rejected the grant type")
        }
        Some("TooManyRequests") => {
            Error::rate_limited("Aliyun Drive token exchange was rate limited")
        }
        _ if status == StatusCode::UNAUTHORIZED => {
            Error::credential_invalid("Aliyun Drive token exchange rejected the source credential")
        }
        _ if status == StatusCode::FORBIDDEN => {
            Error::permission_denied("Aliyun Drive token exchange was denied")
        }
        _ if status == StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("Aliyun Drive token exchange was rate limited")
        }
        _ if status == StatusCode::REQUEST_TIMEOUT => {
            Error::unexpected("Aliyun Drive token exchange timed out").set_retryable(true)
        }
        _ if status == StatusCode::BAD_REQUEST => {
            Error::request_invalid("Aliyun Drive token exchange was rejected")
        }
        _ => Error::unexpected("Aliyun Drive token exchange failed")
            .set_retryable(status.is_server_error()),
    }
    .with_context(format!("aliyun_drive_status: {}", status.as_u16()));

    if let Some(code) = recognized_code {
        error = error.with_context(format!("aliyun_drive_error: {code}"));
    }

    error
}
