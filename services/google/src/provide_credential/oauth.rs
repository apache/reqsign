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

use std::time::Duration;

use reqsign_core::time::Timestamp;
use reqsign_core::{Error, ErrorKind, Result};
use serde::Deserialize;

pub(super) const OAUTH_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

pub(super) fn validate_token_uri(value: &str) -> Result<()> {
    let invalid = || {
        Error::config_invalid(
            "OAuth token URI must be an absolute HTTP(S) URI with a host and no userinfo or fragment",
        )
    };
    if value.contains('#')
        || value
            .bytes()
            .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err(invalid());
    }
    let uri: http::Uri = value.parse().map_err(|_| invalid())?;
    let authority = uri.authority().ok_or_else(invalid)?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || (authority.as_str().len() != authority.host().len() && authority.port_u16().is_none())
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

pub(super) fn checked_expiration(started_at: Timestamp, expires_in: Duration) -> Result<Timestamp> {
    let expires_in_seconds = i64::try_from(expires_in.as_secs())
        .map_err(|_| Error::unexpected("OAuth token expiration is invalid"))?;
    let expiration_second = started_at
        .as_second()
        .checked_add(expires_in_seconds)
        .ok_or_else(|| Error::unexpected("OAuth token expiration is invalid"))?;
    Timestamp::from_second(expiration_second)
        .map_err(|_| Error::unexpected("OAuth token expiration is invalid"))
}

pub(super) fn oauth_error(status: http::StatusCode, body: &[u8]) -> Error {
    let error_code = serde_json::from_slice::<OAuthErrorResponse>(body)
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
        _ if status == http::StatusCode::UNAUTHORIZED => {
            Error::credential_invalid("OAuth token exchange rejected the source credential")
        }
        _ if status == http::StatusCode::FORBIDDEN => {
            Error::permission_denied("OAuth token exchange was denied")
        }
        _ if status == http::StatusCode::TOO_MANY_REQUESTS => {
            Error::rate_limited("OAuth token exchange was rate limited")
        }
        _ => {
            Error::unexpected("OAuth token exchange failed").set_retryable(status.is_server_error())
        }
    }
    .with_context(format!("oauth_status: {}", status.as_u16()));

    if let Some(code) = recognized_code {
        error = error.with_context(format!("oauth_error: {code}"));
    }
    if error.kind() == ErrorKind::Unexpected && status.is_server_error() {
        error = error.set_retryable(true);
    }
    error
}
