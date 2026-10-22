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

use http::header::CONTENT_TYPE;
use log::debug;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

use crate::credential::{Credential, OAuth2Credentials, Token};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use super::oauth::{OAUTH_TOKEN_ENDPOINT, checked_expiration, oauth_error, validate_token_uri};

/// OAuth2 refresh token request.
#[derive(Serialize)]
struct RefreshTokenRequest {
    grant_type: &'static str,
    refresh_token: String,
    client_id: String,
    client_secret: String,
}

/// OAuth2 token response.
#[derive(Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

fn parse_refresh_token_response(body: &[u8]) -> Result<RefreshTokenResponse> {
    serde_json::from_slice(body)
        .map_err(|_| Error::unexpected("failed to parse OAuth refresh token response"))
}

/// Exchanges OAuth2 user credentials for access tokens.
///
/// Each call performs a refresh-token exchange; an outer [`reqsign_core::Signer`]
/// or [`reqsign_core::Granter`] owns caching and refresh scheduling.
///
/// ```no_run
/// use reqsign_google::{AuthorizedUserCredentialProvider, OAuth2Credentials};
///
/// # fn example() -> reqsign_core::Result<()> {
/// let provider = AuthorizedUserCredentialProvider::new(OAuth2Credentials {
///     client_id: "client-id".into(),
///     client_secret: "client-secret".into(),
///     refresh_token: "refresh-token".into(),
/// })
/// .with_token_uri("https://trusted.example/oauth/token")?;
/// # let _ = provider;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AuthorizedUserCredentialProvider {
    oauth2_credentials: OAuth2Credentials,
    token_uri: String,
}

impl fmt::Debug for AuthorizedUserCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedUserCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl AuthorizedUserCredentialProvider {
    /// Create a new AuthorizedUserCredentialProvider.
    pub fn new(oauth2_credentials: OAuth2Credentials) -> Self {
        Self {
            oauth2_credentials,
            token_uri: OAUTH_TOKEN_ENDPOINT.to_string(),
        }
    }

    /// Set the trusted OAuth token URI, defaulting to Google's canonical endpoint.
    ///
    /// The endpoint receives the refresh token and client secret. The URI must
    /// be absolute HTTP(S), with a host and without userinfo or a fragment.
    /// HTTP is intended for trusted local testing; use HTTPS in production.
    /// The caller owns endpoint trust and the HTTP transport's TLS and redirect
    /// policy. Errors and Debug output omit the URI. There is no discovery or
    /// fallback to another endpoint after failure.
    ///
    /// Credential-file `token_uri` is not selected automatically. An adapter can
    /// extract it from trusted JSON and pass it here, preferring its explicit
    /// configuration. See the crate's OAuth endpoint example.
    pub fn with_token_uri(mut self, token_uri: impl Into<String>) -> Result<Self> {
        let token_uri = token_uri.into();
        validate_token_uri(&token_uri)?;
        self.token_uri = token_uri;
        Ok(self)
    }
}
impl ProvideCredential for AuthorizedUserCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        debug!("exchanging refresh token for access token");

        let req_body = RefreshTokenRequest {
            grant_type: "refresh_token",
            refresh_token: self.oauth2_credentials.refresh_token.clone(),
            client_id: self.oauth2_credentials.client_id.clone(),
            client_secret: self.oauth2_credentials.client_secret.clone(),
        };

        let body = serde_json::to_vec(&req_body).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize request").with_source(e)
        })?;
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.token_uri.as_str())
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())
            .map_err(|e| {
                reqsign_core::Error::unexpected("failed to build HTTP request").with_source(e)
            })?;

        let resp = ctx.http_send(req).await.map_err(|err| {
            Error::new(err.kind(), "OAuth refresh token request failed")
                .set_retryable(err.is_retryable())
        })?;

        if resp.status() != http::StatusCode::OK {
            return Err(oauth_error(resp.status(), resp.body()));
        }

        let token_resp = parse_refresh_token_response(resp.body())?;

        let expires_at = token_resp
            .expires_in
            .map(|expires_in| checked_expiration(Timestamp::now(), Duration::from_secs(expires_in)))
            .transpose()?;

        Ok(Some(Credential::with_token(Token {
            access_token: token_resp.access_token,
            expires_at,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redacted_real_authorized_user_response() {
        let response = parse_refresh_token_response(include_bytes!(
            "../../tests/fixtures/authorized_user_token_response.json"
        ))
        .expect("real authorized-user token response fixture must parse");

        assert_eq!(response.access_token, "REDACTED");
        assert_eq!(response.expires_in, Some(3599));
    }
}
