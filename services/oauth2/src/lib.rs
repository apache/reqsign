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

//! Shared RFC 6749 OAuth 2.0 refresh-token support for reqsign.
//!
//! This crate intentionally covers one protocol slice: the
//! [refresh token grant](https://www.rfc-editor.org/rfc/rfc6749#section-6),
//! form-encoded client credentials in the request body, and the resulting
//! Bearer token.
//!
//! ## Scope
//!
//! [`RefreshTokenGrant`] sends `grant_type`, `refresh_token`, `client_id`, and
//! optional `client_secret` and `scope` fields in an
//! `application/x-www-form-urlencoded` body. It does not send HTTP Basic
//! authentication, an `Authorization` header, or any other client
//! authentication method at the same time. This form-body mode is used by the
//! first consumers of this crate (Dropbox and Microsoft Graph) and by the
//! RFC 6749 refresh token grant itself; it is not a general client
//! authentication policy. An endpoint that requires HTTP Basic, mTLS, or a
//! provider-specific assertion needs a different implementation.
//!
//! The token endpoint is explicit and must be an absolute HTTPS URI with a
//! host and without userinfo or a fragment. The caller owns endpoint trust and
//! the HTTP adapter's TLS, proxy, redirect, timeout, and retry policy.
//!
//! ## State and caching
//!
//! Each [`RefreshTokenGrant`] keeps only the latest refresh token in memory. A
//! clone shares that state. Every [`RefreshTokenGrant::refresh`] holds an async
//! lock from reading the current refresh token until the response has been
//! received and a replacement, when present, has been committed. Concurrent
//! calls through the same grant therefore exchange tokens one at a time, and
//! later calls use the latest refresh token. Independent grants and processes
//! do not coordinate, and this crate never persists tokens to disk.
//!
//! Access-token caching belongs to [`reqsign_core::Signer`]. This crate does
//! not keep a second access-token cache, and it performs no implicit retry.
//!
//! On `wasm32-unknown-unknown`, this crate enables Jiff's `js` feature. A
//! refresh requires a wasm-bindgen JavaScript host such as a browser or Node;
//! a bare WASM runtime without a JavaScript clock can compile the crate but is
//! not a supported runtime.
//!
//! ## Expiration
//!
//! [`AccessToken::expires_at`] is either the absolute expiration derived from
//! the response's `expires_in` and the time the refresh request started, or
//! `None` when the response omitted `expires_in`. The shared parser preserves
//! that distinction. A service that requires an expiration must reject a
//! token whose expiration is unknown; it must not cache it as permanent.
//!
//! ## Security
//!
//! [`Debug`] output and returned errors omit the token endpoint, client secret,
//! refresh token, access token, response body, `error_description`, unknown
//! error codes, and transport error sources. Error classification uses only the
//! HTTP status and a fixed allowlist of standard RFC 6749 error codes.

use asyncband::mutex::Mutex;
use form_urlencoded::Serializer;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, StatusCode};
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use reqsign_core::{Context, Error, Result, SigningCredential};
use serde::Deserialize;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;

/// Proactive refresh window used when deciding whether a cached access token
/// should be refreshed.
const TOKEN_REFRESH_WINDOW: Duration = Duration::from_secs(120);

/// An OAuth 2.0 access token and its optional absolute expiration.
///
/// The access token is a secret. Its `Debug` output is redacted, and the only
/// supported way to obtain request authentication material is
/// [`AccessToken::bearer_header_value`].
#[derive(Clone)]
pub struct AccessToken {
    access_token: String,
    expires_at: Option<Timestamp>,
}

impl Debug for AccessToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("access_token", &Redact::from(&self.access_token))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AccessToken {
    /// Create an access token from validated input.
    ///
    /// The token must be non-empty and usable as an HTTP header value. The
    /// expiration is an absolute timestamp; `None` means the caller does not
    /// know when the token expires. This constructor does not require the token
    /// to be currently valid, so callers can represent and reject an expired
    /// token explicitly.
    pub fn new(access_token: impl Into<String>, expires_at: Option<Timestamp>) -> Result<Self> {
        let access_token = access_token.into();
        validate_access_token(&access_token)?;

        Ok(Self {
            access_token,
            expires_at,
        })
    }

    /// Return the absolute expiration, if one is known.
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Build a sensitive `Authorization: Bearer <token>` header value.
    pub fn bearer_header_value(&self) -> Result<HeaderValue> {
        let mut value: HeaderValue =
            format!("Bearer {}", self.access_token)
                .parse()
                .map_err(|_| {
                    Error::config_invalid(
                        "OAuth access token cannot be used as a Bearer header value",
                    )
                })?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// Return whether the token is exactly usable at `timestamp`.
    ///
    /// This is the true expiration check without the proactive refresh window
    /// used by [`SigningCredential::is_valid`].
    pub fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        !self.access_token.is_empty()
            && self
                .expires_at
                .is_none_or(|expires_at| expires_at > timestamp)
    }
}

impl SigningCredential for AccessToken {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + TOKEN_REFRESH_WINDOW)
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        AccessToken::is_valid_at(self, timestamp)
    }
}

/// An RFC 6749 refresh-token grant bound to one token endpoint and client.
///
/// The grant owns the latest refresh token in memory. Clones share that state
/// and serialize exchanges. See the [crate documentation](crate) for the exact
/// protocol and security scope.
#[derive(Clone)]
pub struct RefreshTokenGrant {
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: Arc<Mutex<String>>,
    scope: Option<String>,
}

impl Debug for RefreshTokenGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshTokenGrant").finish_non_exhaustive()
    }
}

impl RefreshTokenGrant {
    /// Create a refresh-token grant.
    ///
    /// `token_endpoint` must be an absolute HTTPS URI with a host and without
    /// userinfo or a fragment. `client_id` and `refresh_token` must be
    /// non-empty. `client_secret` is omitted for public clients. `scope`, when
    /// present, requests the same or a narrower scope than the original grant.
    pub fn new(
        token_endpoint: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        refresh_token: impl Into<String>,
        scope: Option<String>,
    ) -> Result<Self> {
        let token_endpoint = token_endpoint.into();
        validate_token_endpoint(&token_endpoint)?;

        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(Error::config_invalid("OAuth client ID must not be empty"));
        }

        if client_secret.as_deref().is_some_and(str::is_empty) {
            return Err(Error::config_invalid(
                "OAuth client secret must not be empty when provided",
            ));
        }

        let refresh_token = refresh_token.into();
        if refresh_token.is_empty() {
            return Err(Error::config_invalid(
                "OAuth refresh token must not be empty",
            ));
        }

        if scope.as_deref().is_some_and(str::is_empty) {
            return Err(Error::config_invalid(
                "OAuth scope must not be empty when provided",
            ));
        }

        Ok(Self {
            token_endpoint,
            client_id,
            client_secret,
            refresh_token: Arc::new(Mutex::new(refresh_token)),
            scope,
        })
    }

    /// Replace the token endpoint while preserving the latest refresh token.
    ///
    /// The new endpoint must satisfy the same trust constraints as
    /// [`RefreshTokenGrant::new`]. This method is intended for explicit
    /// service configuration, not endpoint discovery.
    pub fn with_token_endpoint(mut self, token_endpoint: impl Into<String>) -> Result<Self> {
        let token_endpoint = token_endpoint.into();
        validate_token_endpoint(&token_endpoint)?;
        self.token_endpoint = token_endpoint;
        Ok(self)
    }

    /// Exchange the latest refresh token for a new access token.
    ///
    /// The exchange is serialized with every other call through this grant or
    /// its clones. A non-empty `refresh_token` in a valid success response
    /// replaces the stored token before this method returns, even when the
    /// service later rejects the access token because its expiration is
    /// missing or already past. An omitted replacement keeps the current
    /// token. Failed, malformed, or unparseable responses do not update it.
    pub async fn refresh(&self, ctx: &Context) -> Result<AccessToken> {
        let mut current_refresh_token = self.refresh_token.lock().await;
        let started_at = Timestamp::now();

        let body = {
            let mut serializer = Serializer::new(String::new());
            serializer.append_pair("grant_type", "refresh_token");
            serializer.append_pair("refresh_token", &current_refresh_token);
            serializer.append_pair("client_id", &self.client_id);
            if let Some(client_secret) = &self.client_secret {
                serializer.append_pair("client_secret", client_secret);
            }
            if let Some(scope) = &self.scope {
                serializer.append_pair("scope", scope);
            }
            serializer.finish()
        };

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.token_endpoint.as_str())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes().into())
            .map_err(|_| Error::unexpected("failed to build OAuth token request"))?;

        let response = ctx.http_send(request).await.map_err(|err| {
            // Transport error sources can contain the request URI or other
            // caller-held material, so retain only the bounded classification.
            Error::new(err.kind(), "OAuth token request failed").set_retryable(err.is_retryable())
        })?;

        if response.status() != StatusCode::OK {
            return Err(oauth_error(response.status(), response.body()));
        }

        let response: TokenResponse = serde_json::from_slice(response.body())
            .map_err(|_| Error::unexpected("failed to parse OAuth token response"))?;

        let access_token = response.access_token.unwrap_or_default();
        AccessToken::new(&access_token, None)
            .map_err(|_| Error::unexpected("OAuth token response omitted a usable access token"))?;

        let token_type = response.token_type.unwrap_or_default();
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(Error::unexpected(
                "OAuth token response did not use the Bearer token type",
            ));
        }

        let expires_at = response
            .expires_in
            .map(|expires_in| checked_expiration(started_at, expires_in))
            .transpose()?;

        if let Some(refresh_token) = response.refresh_token.filter(|token| !token.is_empty()) {
            *current_refresh_token = refresh_token;
        }

        Ok(AccessToken {
            access_token,
            expires_at,
        })
    }
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

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

fn validate_access_token(value: &str) -> Result<()> {
    let invalid = || Error::config_invalid("OAuth access token must be a non-empty header value");
    if value.is_empty()
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
        || HeaderValue::from_str(value).is_err()
    {
        return Err(invalid());
    }

    Ok(())
}

fn validate_token_endpoint(value: &str) -> Result<()> {
    let invalid = || {
        Error::config_invalid(
            "OAuth token endpoint must be an absolute HTTPS URI with a host and no userinfo or fragment",
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
        .map_err(|_| Error::unexpected("OAuth token expiration is invalid"))?;
    let expiration_second = started_at
        .as_second()
        .checked_add(expires_in)
        .ok_or_else(|| Error::unexpected("OAuth token expiration is invalid"))?;
    Timestamp::from_second(expiration_second)
        .map_err(|_| Error::unexpected("OAuth token expiration is invalid"))
}

fn oauth_error(status: StatusCode, body: &[u8]) -> Error {
    let error_code = serde_json::from_slice::<ErrorResponse>(body)
        .ok()
        .and_then(|response| response.error);
    let recognized_code = match error_code.as_deref() {
        Some(
            code @ ("invalid_grant"
            | "invalid_request"
            | "invalid_scope"
            | "unsupported_grant_type"
            | "unauthorized_client"
            | "invalid_client"
            | "access_denied"
            | "temporarily_unavailable"),
        ) => Some(code),
        _ => None,
    };

    let mut error = match recognized_code {
        Some("invalid_grant" | "invalid_client") => {
            Error::credential_invalid("OAuth token exchange rejected the source credential")
        }
        Some("invalid_request" | "invalid_scope" | "unsupported_grant_type") => {
            Error::request_invalid("OAuth token exchange rejected the request")
        }
        Some("unauthorized_client" | "access_denied") => {
            Error::permission_denied("OAuth token exchange was denied")
        }
        Some("temporarily_unavailable") => {
            Error::unexpected("OAuth token exchange is temporarily unavailable").set_retryable(true)
        }
        _ if status == StatusCode::UNAUTHORIZED => {
            Error::credential_invalid("OAuth token exchange rejected the source credential")
        }
        _ if status == StatusCode::FORBIDDEN => {
            Error::permission_denied("OAuth token exchange was denied")
        }
        _ if status == StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("OAuth token exchange was rate limited")
        }
        _ if status == StatusCode::REQUEST_TIMEOUT => {
            Error::unexpected("OAuth token exchange timed out").set_retryable(true)
        }
        _ => {
            Error::unexpected("OAuth token exchange failed").set_retryable(status.is_server_error())
        }
    }
    .with_context(format!("oauth_status: {}", status.as_u16()));

    if let Some(code) = recognized_code {
        error = error.with_context(format!("oauth_error: {code}"));
    }

    error
}

#[cfg(test)]
mod tests;
