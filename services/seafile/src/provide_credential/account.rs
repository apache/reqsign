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
use crate::constants::AUTH_TOKEN_PATH;
use http::HeaderMap;
use http::StatusCode;
use http::header;
use log::debug;
use reqsign_core::utils::Redact;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use std::fmt::{self, Debug, Formatter};

/// Exchanges a configured Seafile username and password for an account token.
///
/// The provider sends `username` and `password` as an
/// `application/x-www-form-urlencoded` body to
/// `{server}/api2/auth-token/`, matching the documented endpoint used by
/// `seaf-cli`, the official Python SDK, and OpenDAL. The `server` value is the
/// deployment root and may include a reverse-proxy base path, such as
/// `https://files.example.com/seafile`; the path is preserved.
///
/// The response must be HTTP 200 with a JSON object containing a non-empty
/// `token`. The token is returned without an expiration because Seafile does
/// not document one. The provider performs no repository lookup and does not
/// cache the token; [`reqsign_core::Signer`] owns caching and single-flight
/// refresh.
///
/// The request carries a login secret. Use HTTPS in production. An explicit
/// `http://` server is accepted for self-hosted deployments, but sends the
/// username and password in cleartext. Two-factor authentication is not
/// supported by this exchange; callers that require it should obtain a token
/// separately and use [`crate::StaticCredentialProvider`].
#[derive(Clone)]
pub struct AccountTokenCredentialProvider {
    server: String,
    username: String,
    password: String,
}

impl Debug for AccountTokenCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountTokenCredentialProvider")
            .field("server", &self.server)
            .field("username", &Redact::from(&self.username))
            .field("password", &Redact::from(&self.password))
            .finish()
    }
}

impl AccountTokenCredentialProvider {
    /// Create a provider from an explicit server, username, and password.
    ///
    /// `server` must be an absolute `http` or `https` URL with an authority.
    /// A path prefix is preserved when the account-token endpoint is appended.
    pub fn new(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            username: username.into(),
            password: password.into(),
        }
    }

    fn auth_endpoint(&self) -> Result<http::Uri> {
        if self.server.is_empty() {
            return Err(Error::config_invalid(
                "Seafile server URL must not be empty",
            ));
        }

        let base: http::Uri = self
            .server
            .parse()
            .map_err(|_| Error::config_invalid("Seafile server URL is not a valid URI"))?;
        let scheme = base
            .scheme_str()
            .ok_or_else(|| Error::config_invalid("Seafile server URL must be absolute"))?;
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(Error::config_invalid(
                "Seafile server URL must use http or https",
            ));
        }
        let authority = base
            .authority()
            .ok_or_else(|| Error::config_invalid("Seafile server URL must include a host"))?;
        if authority.as_str().contains('@') {
            return Err(Error::config_invalid(
                "Seafile server URL must not contain user information",
            ));
        }
        if base.query().is_some() {
            return Err(Error::config_invalid(
                "Seafile server URL must not contain a query",
            ));
        }

        let path = base.path().trim_end_matches('/');
        format!("{scheme}://{authority}{path}{AUTH_TOKEN_PATH}")
            .parse()
            .map_err(|_| Error::config_invalid("failed to build the Seafile account-token URL"))
    }

    fn validate_configured_values(&self) -> Result<()> {
        if self.username.is_empty() {
            return Err(Error::config_invalid("Seafile username must not be empty"));
        }
        if self.password.is_empty() {
            return Err(Error::config_invalid("Seafile password must not be empty"));
        }

        Ok(())
    }
}

impl ProvideCredential for AccountTokenCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.validate_configured_values()?;
        let endpoint = self.auth_endpoint()?;

        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("username", &self.username)
            .append_pair("password", &self.password)
            .finish();
        let request = http::Request::post(endpoint.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(bytes::Bytes::from(body))
            .map_err(|_| Error::unexpected("failed to build the Seafile account-token request"))?;

        debug!("requesting a Seafile account token from {endpoint}");
        let response = ctx.http_send(request).await?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(exchange_error(status, response.headers()));
        }

        let response: AuthTokenResponse = serde_json::from_slice(response.body().as_ref())
            .map_err(|e| {
                Error::unexpected("failed to parse the Seafile account-token response")
                    .with_source(e)
            })?;

        Credential::new(response.token).map(Some).map_err(|_| {
            Error::unexpected("Seafile account-token response contains an unusable token")
        })
    }
}

fn exchange_error(status: StatusCode, headers: &HeaderMap) -> Error {
    let mut message = format!("Seafile account token exchange failed (status {status})");
    if headers.contains_key("x-seafile-otp") {
        message.push_str(
            "; two-factor authentication is required, which this provider does not support",
        );
    }

    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => Error::credential_invalid(message),
        StatusCode::FORBIDDEN => Error::permission_denied(message),
        StatusCode::TOO_MANY_REQUESTS => Error::rate_limited(message),
        status if status.is_server_error() => Error::unexpected(message).set_retryable(true),
        _ => Error::unexpected(message),
    }
}

#[derive(serde::Deserialize)]
struct AuthTokenResponse {
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_the_username_and_password() {
        let provider = AccountTokenCredentialProvider::new(
            "https://files.example.com",
            "user@example.com",
            "password-secret",
        );
        let debug = format!("{provider:?}");

        assert!(debug.contains("https://files.example.com"));
        assert!(!debug.contains("user@example.com"));
        assert!(!debug.contains("password-secret"));
    }

    #[test]
    fn two_factor_errors_are_identified() {
        let mut headers = HeaderMap::new();
        headers.insert("x-seafile-otp", http::HeaderValue::from_static("required"));

        let error = exchange_error(StatusCode::BAD_REQUEST, &headers);

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        assert!(format!("{error:?}").contains("two-factor authentication"));
    }
}
