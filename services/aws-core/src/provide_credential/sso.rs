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

mod session;
use session::{SessionKey, SsoSession, login_required};
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
/// The AWS default provider propagates SSO errors. A custom credential chain
/// retains its own error policy.
#[derive(Debug, Clone)]
pub struct SSOCredentialProvider {
    profile: Option<String>,
    sso_account_id: Option<String>,
    sso_region: Option<String>,
    sso_role_name: Option<String>,
    sso_start_url: Option<String>,
    sso_endpoint: Option<String>, // Allow custom endpoint for testing
    sessions: Arc<Mutex<HashMap<SessionKey, Arc<SsoSession>>>>,
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
            sessions: Arc::new(Mutex::new(HashMap::new())),
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

    async fn access_token(
        &self,
        ctx: &Context,
        config: &SSOConfig,
        now: impl Fn() -> Timestamp + Send + Sync,
    ) -> Result<String> {
        let key = SessionKey::from_config(ctx, config)?;
        if config.session_name.is_none() {
            return session::legacy_access_token(ctx, &key.path, now()).await;
        }
        let session = {
            let mut sessions = self.sessions.lock().await;
            sessions
                .entry(key.clone())
                .or_insert_with(|| Arc::new(SsoSession::new(key)))
                .clone()
        };
        session.access_token(ctx, now).await
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

#[cfg(test)]
mod tests;
