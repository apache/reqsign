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

use std::fmt::{self, Debug};
use std::time::Duration;

use http::header;
use log::debug;
use reqsign_core::hash::base64_encode;
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::credential::Credential;

/// The documented HTTPS endpoint for `b2_authorize_account`.
///
/// API v4 supports Multi-Bucket Application Keys. Earlier versions reject them
/// with an `unsupported` response, so reqsign uses v4 for every application key.
const AUTHORIZE_ACCOUNT_URL: &str = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";

/// B2 caps an authorization token at 24 hours.
const AUTHORIZATION_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Credential provider that exchanges an application key for a Native API
/// authorization token with `b2_authorize_account`.
///
/// The application key is sent only to the documented Backblaze HTTPS endpoint
/// with HTTP Basic authentication. The response supplies the authorization
/// token, the Native API and download base URLs, and an optional application
/// key expiration timestamp.
#[derive(Clone)]
pub struct AccountAuthorizationCredentialProvider {
    application_key_id: String,
    application_key: String,
}

impl Debug for AccountAuthorizationCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountAuthorizationCredentialProvider")
            .field(
                "application_key_id",
                &Redact::from(&self.application_key_id),
            )
            .field("application_key", &Redact::from(&self.application_key))
            .finish()
    }
}

impl AccountAuthorizationCredentialProvider {
    /// Create a provider from an explicit application key ID and application key.
    pub fn new(application_key_id: impl Into<String>, application_key: impl Into<String>) -> Self {
        Self {
            application_key_id: application_key_id.into(),
            application_key: application_key.into(),
        }
    }

    fn authorization_header(&self) -> Result<http::HeaderValue> {
        let encoded = base64_encode(
            format!("{}:{}", self.application_key_id, self.application_key).as_bytes(),
        );
        let mut value = http::HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|e| {
            Error::config_invalid("B2 application key cannot be encoded as a Basic header")
                .with_source(e)
        })?;
        value.set_sensitive(true);

        Ok(value)
    }
}

impl ProvideCredential for AccountAuthorizationCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.application_key_id.is_empty() || self.application_key.is_empty() {
            debug!(
                "B2 application key ID or application key is empty, skipping account authorization"
            );
            return Ok(None);
        }

        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(AUTHORIZE_ACCOUNT_URL)
            .header(header::AUTHORIZATION, self.authorization_header()?)
            .body(bytes::Bytes::new())
            .map_err(|e| {
                Error::unexpected("failed to build B2 account authorization request").with_source(e)
            })?;

        // The token is issued no earlier than the request start, so measuring the
        // documented 24-hour cap from here never extends past the provider limit.
        let requested_at = Timestamp::now();
        debug!("authorizing B2 account at {AUTHORIZE_ACCOUNT_URL}");
        let response = ctx.http_send(request).await?;

        if response.status() != http::StatusCode::OK {
            return Err(authorization_error(response.status(), response.body()));
        }

        let response: AuthorizeAccountResponse =
            serde_json::from_slice(response.body()).map_err(|e| {
                Error::unexpected("failed to parse B2 account authorization response")
                    .with_source(e)
            })?;

        if response.authorization_token.is_empty() {
            return Err(Error::unexpected(
                "B2 account authorization response is missing authorizationToken",
            ));
        }

        let storage_api = response.api_info.storage_api;
        validate_endpoint("apiUrl", &storage_api.api_url)?;
        validate_endpoint("downloadUrl", &storage_api.download_url)?;

        let expires_at = match response.application_key_expiration_timestamp {
            Some(millis) => {
                let key_expires_at = Timestamp::from_millisecond(millis)?;
                if key_expires_at <= Timestamp::now() {
                    return Err(Error::credential_invalid("B2 application key has expired"));
                }

                (requested_at + AUTHORIZATION_TOKEN_LIFETIME).min(key_expires_at)
            }
            None => requested_at + AUTHORIZATION_TOKEN_LIFETIME,
        };

        debug!(
            "B2 account authorization succeeded, token expires at {expires_at} with apiUrl {} and downloadUrl {}",
            storage_api.api_url, storage_api.download_url
        );

        Ok(Some(
            Credential::new(
                response.authorization_token,
                storage_api.api_url,
                storage_api.download_url,
            )
            .with_expires_at(expires_at),
        ))
    }
}

fn validate_endpoint(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::unexpected(format!(
            "B2 account authorization response is missing {field}"
        )));
    }

    let uri: http::Uri = value.parse().map_err(|e| {
        Error::unexpected(format!(
            "B2 account authorization response contains an invalid {field}"
        ))
        .with_source(e)
    })?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(Error::unexpected(format!(
            "B2 account authorization response contains a relative {field}"
        )));
    }

    Ok(())
}

fn authorization_error(status: http::StatusCode, body: &[u8]) -> Error {
    #[derive(serde::Deserialize)]
    struct ErrorResponse {
        #[serde(default)]
        code: Option<String>,
    }

    // B2 error bodies are not secret, but only the stable error code is useful
    // for diagnosis. Do not echo the response body or the request credentials.
    let code = serde_json::from_slice::<ErrorResponse>(body)
        .ok()
        .and_then(|response| response.code);
    let code = code
        .map(|code| format!(", code {code}"))
        .unwrap_or_default();
    let message = format!("B2 account authorization failed (status {status}{code})");

    match status {
        http::StatusCode::UNAUTHORIZED => Error::credential_invalid(message),
        http::StatusCode::FORBIDDEN => Error::permission_denied(message),
        http::StatusCode::BAD_REQUEST => Error::config_invalid(message),
        http::StatusCode::TOO_MANY_REQUESTS => Error::rate_limited(message),
        _ if status.is_server_error() => Error::unexpected(message).set_retryable(true),
        _ => Error::unexpected(message),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeAccountResponse {
    authorization_token: String,
    api_info: ApiInfo,
    #[serde(default)]
    application_key_expiration_timestamp: Option<i64>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiInfo {
    storage_api: StorageApi,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageApi {
    api_url: String,
    download_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_application_keys() {
        let provider = AccountAuthorizationCredentialProvider::new(
            "application-key-id-value",
            "application-key-secret-value",
        );
        let debug = format!("{provider:?}");

        assert!(!debug.contains("application-key-id-value"));
        assert!(!debug.contains("application-key-secret-value"));
    }

    #[test]
    fn error_response_reports_only_the_status_and_code() {
        let body = br#"{"status":401,"code":"unauthorized","message":"do not echo application-key-secret"}"#;
        let error = authorization_error(http::StatusCode::UNAUTHORIZED, body);

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        let text = format!("{error:?}");
        assert!(text.contains("status 401"));
        assert!(text.contains("code unauthorized"));
        assert!(!text.contains("application-key-secret"));
    }
}
