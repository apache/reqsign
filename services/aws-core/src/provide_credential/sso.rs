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
use asyncband::mutex::Mutex;
use http::{Method, Request, StatusCode};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

const AWS_SSO_ACCOUNT_ID: &str = "sso_account_id";
const AWS_SSO_REGION: &str = "sso_region";
const AWS_SSO_ROLE_NAME: &str = "sso_role_name";
const AWS_SSO_START_URL: &str = "sso_start_url";
const AWS_SSO_SESSION_NAME: &str = "sso_session";

/// SSO Credentials Provider
///
/// This provider fetches credentials from AWS SSO (IAM Identity Center).
/// It reads cached SSO tokens from ~/.aws/sso/cache/ and exchanges them for temporary credentials.
///
/// # Configuration
/// SSO configuration is typically stored in ~/.aws/config under a profile:
/// ```ini
/// [profile my-sso-profile]
/// sso_session = my-session
/// sso_account_id = 123456789012
/// sso_role_name = MyRole
///
/// [sso-session my-session]
/// sso_start_url = https://my-sso-portal.awsapps.com/start
/// sso_region = us-east-1
/// ```
///
/// Named sessions refresh expired access tokens using cached OIDC registration
/// and refresh tokens. Refreshed material is kept in memory for this provider
/// and its clones; independently constructed providers do not coordinate refreshes.
/// The AWS CLI cache is read through `Context` and is never written. On restart,
/// the on-disk registration and refresh token must still be usable. When an
/// in-memory token expires, a newer disk token (for example after `aws sso login`)
/// replaces it. Recreate the provider to discard its in-memory state immediately.
///
/// Legacy inline `sso_start_url` / `sso_region` profiles and configuration supplied
/// directly through the setters remain non-refreshable. This provider never
/// starts interactive login and does not resolve assume-role profile chains.
/// When assembling a custom credential chain, use
/// [`reqsign_core::ProvideCredentialChain::push_with_error_propagation`] to keep
/// SSO failures from falling back to an unrelated identity.
#[derive(Debug, Clone)]
pub struct SSOCredentialProvider {
    profile: Option<String>,
    sso_account_id: Option<String>,
    sso_region: Option<String>,
    sso_role_name: Option<String>,
    sso_start_url: Option<String>,
    sso_endpoint: Option<String>, // Allow custom endpoint for testing
    tokens: Arc<Mutex<HashMap<TokenKey, CachedToken>>>,
}

impl Default for SSOCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SSOCredentialProvider {
    /// Create a new SSO credential provider
    pub fn new() -> Self {
        Self {
            profile: None,
            sso_account_id: None,
            sso_region: None,
            sso_role_name: None,
            sso_start_url: None,
            sso_endpoint: None,
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the profile name to use
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set SSO account ID
    pub fn with_account_id(mut self, account_id: impl Into<String>) -> Self {
        self.sso_account_id = Some(account_id.into());
        self
    }

    /// Set SSO region
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.sso_region = Some(region.into());
        self
    }

    /// Set SSO role name
    pub fn with_role_name(mut self, role_name: impl Into<String>) -> Self {
        self.sso_role_name = Some(role_name.into());
        self
    }

    /// Set SSO start URL
    pub fn with_start_url(mut self, start_url: impl Into<String>) -> Self {
        self.sso_start_url = Some(start_url.into());
        self
    }

    /// Set custom SSO endpoint (for testing)
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sso_endpoint = Some(endpoint.into());
        self
    }

    async fn load_sso_config(&self, ctx: &Context) -> Result<Option<SSOConfig>> {
        // If all fields are provided directly, use them
        if let (Some(account_id), Some(region), Some(role_name), Some(start_url)) = (
            &self.sso_account_id,
            &self.sso_region,
            &self.sso_role_name,
            &self.sso_start_url,
        ) {
            return Ok(Some(SSOConfig {
                sso_account_id: account_id.clone(),
                sso_region: region.clone(),
                sso_role_name: role_name.clone(),
                sso_start_url: start_url.clone(),
                session_name: None,
                config_path: None,
            }));
        }

        let mut shared = crate::SharedConfig::new();
        if let Some(profile) = &self.profile {
            shared = shared.with_profile(profile);
        }
        self.load_from_config_file(ctx, &shared).await
    }

    async fn load_from_config_file(
        &self,
        ctx: &Context,
        shared: &crate::SharedConfig,
    ) -> Result<Option<SSOConfig>> {
        let conf = shared.load_config_file(ctx).await?;
        let profile_section = crate::config::config_section(&shared.profile_name(ctx));
        let Some(section) = conf.section(Some(profile_section)) else {
            return Ok(None);
        };
        if ![
            AWS_SSO_ACCOUNT_ID,
            AWS_SSO_REGION,
            AWS_SSO_ROLE_NAME,
            AWS_SSO_START_URL,
            AWS_SSO_SESSION_NAME,
        ]
        .iter()
        .any(|key| section.contains_key(key))
        {
            return Ok(None);
        }

        let required = |section: &ini::Properties, key: &str| -> Result<String> {
            section
                .get(key)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| Error::config_invalid(format!("missing {key} in SSO configuration")))
        };
        let session_name = section.get(AWS_SSO_SESSION_NAME).map(str::to_owned);
        let session = match &session_name {
            Some(name) => conf
                .section(Some(format!("sso-session {name}")))
                .ok_or_else(|| Error::config_invalid("referenced SSO session not found"))?,
            None => section,
        };
        let region = required(session, AWS_SSO_REGION)?;
        let start_url = required(session, AWS_SSO_START_URL)?;
        if session_name.is_some() {
            for (key, value) in [(AWS_SSO_REGION, &region), (AWS_SSO_START_URL, &start_url)] {
                if section.get(key).is_some_and(|v| v != value) {
                    return Err(Error::config_invalid(format!(
                        "{key} conflicts with named SSO session"
                    )));
                }
            }
        }
        Ok(Some(SSOConfig {
            sso_account_id: required(section, AWS_SSO_ACCOUNT_ID)?,
            sso_region: region,
            sso_role_name: required(section, AWS_SSO_ROLE_NAME)?,
            sso_start_url: start_url,
            session_name,
            config_path: shared.config_file_path(ctx),
        }))
    }

    async fn read_cached_token(ctx: &Context, path: &str) -> Result<Option<CachedToken>> {
        match ctx.file_read(path).await {
            Ok(content) => serde_json::from_slice(&content)
                .map(Some)
                .map_err(|_| login_required("invalid SSO token cache")),
            Err(_) => Ok(None),
        }
    }

    async fn access_token(
        &self,
        ctx: &Context,
        config: &SSOConfig,
        now: impl Fn() -> Timestamp + Send + Sync,
    ) -> Result<String> {
        let key = config.token_key(ctx)?;
        if config.session_name.is_none() {
            let token = Self::read_cached_token(ctx, &key.path)
                .await?
                .ok_or_else(|| login_required("SSO token cache not found"))?;
            return if token.is_valid_at(now())? {
                Ok(token.access_token)
            } else {
                Err(login_required("legacy SSO token has expired"))
            };
        }

        // Hold the provider lock across refresh so clones cannot exchange the
        // same refresh token concurrently, including when the service rotates it.
        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get(&key) {
            if token.is_valid_at(now())? {
                return Ok(token.access_token.clone());
            }
        }
        if let Some(disk) = Self::read_cached_token(ctx, &key.path).await? {
            let replace = match tokens.get(&key) {
                Some(current) => disk.expiration()? > current.expiration()?,
                None => true,
            };
            if replace {
                tokens.insert(key.clone(), disk);
            }
        }
        let token = tokens
            .get_mut(&key)
            .ok_or_else(|| login_required("SSO token cache not found"))?;
        if !token.is_valid_at(now())? {
            self.refresh_token(ctx, config, token, &now).await?;
        }
        if !token.is_valid_at(now())? {
            return Err(login_required("refreshed SSO access token has expired"));
        }
        Ok(token.access_token.clone())
    }

    async fn refresh_token(
        &self,
        ctx: &Context,
        config: &SSOConfig,
        token: &mut CachedToken,
        now: impl Fn() -> Timestamp + Send + Sync,
    ) -> Result<()> {
        let required = |value: &Option<String>| {
            value
                .as_ref()
                .filter(|v| !v.is_empty())
                .cloned()
                .ok_or_else(|| login_required("SSO refresh material is missing"))
        };
        let registration_expiry = required(&token.registration_expires_at)?
            .parse::<Timestamp>()
            .map_err(|_| login_required("invalid SSO registration expiration"))?;
        let started = now();
        if registration_expiry <= started {
            return Err(login_required("SSO client registration has expired"));
        }
        let body = serde_json::json!({
            "grantType": "refresh_token",
            "clientId": required(&token.client_id)?,
            "clientSecret": required(&token.client_secret)?,
            "refreshToken": required(&token.refresh_token)?,
        });
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "https://oidc.{}.amazonaws.com/token",
                config.sso_region
            ))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(bytes::Bytes::from(body.to_string()))
            .map_err(|_| Error::config_invalid("failed to build SSO refresh request"))?;
        // HTTP adapters and server error bodies can contain the submitted secrets.
        let response = ctx.http_send(req).await.map_err(|_| {
            Error::unexpected("SSO token refresh transport failed").set_retryable(true)
        })?;
        if response.status() != StatusCode::OK {
            let status = response.status();
            // CreateToken also reports throttling as HTTP 400. Only recognize
            // the allowlisted code; never retain or expose the error description.
            let slow_down = status == StatusCode::BAD_REQUEST
                && serde_json::from_slice::<RefreshError>(response.body())
                    .is_ok_and(|error| matches!(error.error, RefreshErrorCode::SlowDown));
            if status == StatusCode::TOO_MANY_REQUESTS || slow_down {
                return Err(Error::rate_limited("SSO token refresh was throttled"));
            }
            if status.is_server_error() {
                return Err(
                    Error::unexpected(format!("SSO token refresh returned {status}"))
                        .set_retryable(true),
                );
            }
            return Err(login_required(&format!(
                "SSO token refresh rejected ({status})"
            )));
        }
        let refreshed: RefreshResponse = serde_json::from_slice(response.body())
            .map_err(|_| login_required("invalid SSO token refresh response"))?;
        if refreshed.access_token.is_empty()
            || refreshed.expires_in <= 0
            || refreshed
                .refresh_token
                .as_ref()
                .is_some_and(|v| v.is_empty())
        {
            return Err(login_required("invalid SSO token refresh response"));
        }
        let expires_at = started
            .as_second()
            .checked_add(refreshed.expires_in)
            .and_then(|seconds| Timestamp::from_second(seconds).ok())
            .ok_or_else(|| login_required("invalid SSO token expiration"))?;
        // Commit the complete response before attempting GetRoleCredentials. Its
        // failure must not lose a rotated refresh token or extend token lifetime.
        token.access_token = refreshed.access_token;
        token.expires_at = expires_at.to_string();
        if let Some(refresh_token) = refreshed.refresh_token {
            token.refresh_token = Some(refresh_token);
        }
        Ok(())
    }

    async fn provide_with_clock(
        &self,
        ctx: &Context,
        now: impl Fn() -> Timestamp + Send + Sync,
    ) -> Result<Option<Credential>> {
        let Some(config) = self.load_sso_config(ctx).await? else {
            return Ok(None);
        };
        let token = self.access_token(ctx, &config, now).await?;
        self.get_role_credentials(ctx, &config, &token)
            .await
            .map(Some)
    }

    async fn get_role_credentials(
        &self,
        ctx: &Context,
        config: &SSOConfig,
        access_token: &str,
    ) -> Result<Credential> {
        // Allow endpoint override for testing
        let endpoint = self
            .sso_endpoint
            .clone()
            .or_else(|| ctx.env_var("AWS_SSO_ENDPOINT"))
            .unwrap_or_else(|| {
                format!(
                    "https://portal.sso.{}.amazonaws.com/federation/credentials",
                    config.sso_region
                )
            });

        let params = serde_urlencoded::to_string([
            ("role_name", &config.sso_role_name),
            ("account_id", &config.sso_account_id),
        ])
        .map_err(|e| Error::unexpected(format!("failed to encode query params: {e}")))?;

        let url = format!("{endpoint}?{params}");

        let mut bearer = http::HeaderValue::from_str(access_token)
            .map_err(|_| login_required("invalid SSO access token"))?;
        bearer.set_sensitive(true);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .header("x-amz-sso_bearer_token", bearer)
            .body(bytes::Bytes::new())
            .map_err(|e| Error::unexpected(format!("failed to build request: {e}")))?;

        let resp = ctx
            .http_send(req)
            .await
            .map_err(|_| Error::unexpected("failed to fetch SSO credentials"))?;

        if resp.status() != StatusCode::OK {
            return Err(Error::unexpected(format!(
                "SSO endpoint returned status: {}",
                resp.status()
            )));
        }

        let body = resp.into_body();
        let creds: SSOCredentialResponse = serde_json::from_slice(&body)
            .map_err(|_| Error::unexpected("failed to parse SSO credentials"))?;

        let role_creds = creds.role_credentials;
        let expires_in = Timestamp::from_millisecond(role_creds.expiration)
            .map_err(|e| Error::unexpected(format!("invalid expiration timestamp: {e}")))?;

        Ok(Credential {
            access_key_id: role_creds.access_key_id,
            secret_access_key: role_creds.secret_access_key,
            session_token: Some(role_creds.session_token),
            expires_in: Some(expires_in),
        })
    }
}

#[derive(Debug)]
struct SSOConfig {
    sso_account_id: String,
    sso_region: String,
    sso_role_name: String,
    sso_start_url: String,
    session_name: Option<String>,
    config_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TokenKey {
    path: String,
    config_path: Option<String>,
    session_name: Option<String>,
    start_url: String,
    region: String,
}

impl SSOConfig {
    fn token_key(&self, ctx: &Context) -> Result<TokenKey> {
        let home = ctx
            .home_dir()
            .ok_or_else(|| Error::config_invalid("HOME directory not found"))?;
        let name = self.session_name.as_deref().unwrap_or(&self.sso_start_url);
        let path = home
            .join(".aws")
            .join("sso")
            .join("cache")
            .join(format!("{}.json", hex_sha1(name.as_bytes())));
        Ok(TokenKey {
            path: path.to_string_lossy().into_owned(),
            config_path: self.config_path.clone(),
            session_name: self.session_name.clone(),
            start_url: self.sso_start_url.clone(),
            region: self.sso_region.clone(),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedToken {
    access_token: String,
    expires_at: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    registration_expires_at: Option<String>,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken").finish_non_exhaustive()
    }
}

impl CachedToken {
    fn expiration(&self) -> Result<Timestamp> {
        self.expires_at
            .parse()
            .map_err(|_| login_required("invalid SSO token expiration"))
    }

    fn is_valid_at(&self, now: Timestamp) -> Result<bool> {
        Ok(!self.access_token.is_empty() && self.expiration()? > now)
    }
}

#[derive(Deserialize)]
struct RefreshError {
    error: RefreshErrorCode,
}

#[derive(Deserialize)]
enum RefreshErrorCode {
    #[serde(rename = "slow_down")]
    SlowDown,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResponse {
    access_token: String,
    expires_in: i64,
    refresh_token: Option<String>,
}

fn login_required(reason: &str) -> Error {
    Error::config_invalid(format!(
        "{reason}. Please run 'aws sso login' for the selected profile"
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SSOCredentialResponse {
    role_credentials: RoleCredentials,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: i64,
}
impl ProvideCredential for SSOCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.provide_with_clock(ctx, Timestamp::now).await
    }
}

// Simple SHA1 implementation for cache key generation
fn hex_sha1(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests;
