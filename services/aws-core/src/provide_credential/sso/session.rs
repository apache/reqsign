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

//! Session-owned access tokens and OIDC refresh state. Disk cache records are
//! inputs only; refreshed material remains in memory for the session lifetime.

use asyncband::mutex::Mutex;
use http::{Method, Request, StatusCode};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SessionKey {
    pub(super) path: String,
    config_path: Option<String>,
    session_name: Option<String>,
    start_url: String,
    region: String,
}

impl SessionKey {
    pub fn from_config(ctx: &Context, config: &super::SSOConfig) -> Result<Self> {
        let home = ctx
            .home_dir()
            .ok_or_else(|| Error::config_invalid("HOME directory not found"))?;
        let name = config
            .session_name
            .as_deref()
            .unwrap_or(&config.sso_start_url);
        let path = home
            .join(".aws")
            .join("sso")
            .join("cache")
            .join(format!("{}.json", hex_sha1(name.as_bytes())));
        Ok(SessionKey {
            path: path.to_string_lossy().into_owned(),
            config_path: config.config_path.clone(),
            session_name: config.session_name.clone(),
            start_url: config.sso_start_url.clone(),
            region: config.sso_region.clone(),
        })
    }
}

#[derive(Debug)]
pub(super) struct SsoSession {
    key: SessionKey,
    token: Mutex<Option<SessionToken>>,
}

impl SsoSession {
    pub fn new(key: SessionKey) -> Self {
        Self {
            key,
            token: Mutex::new(None),
        }
    }

    pub async fn access_token(
        &self,
        ctx: &Context,
        now: impl Fn() -> Timestamp + Send + Sync,
    ) -> Result<String> {
        // Only this session is locked across I/O. Clones share refresh state,
        // while other sessions can load or refresh their tokens independently.
        let mut state = self.token.lock().await;
        if let Some(token) = state.as_ref() {
            if token.is_valid_at(now()) {
                return Ok(token.access_token.clone());
            }
        }
        if let Some(disk) = SessionToken::read(ctx, &self.key.path).await? {
            if state
                .as_ref()
                .is_none_or(|current| disk.expires_at > current.expires_at)
            {
                *state = Some(disk);
            }
        }
        let token = state
            .as_mut()
            .ok_or_else(|| login_required("SSO token cache not found"))?;
        if !token.is_valid_at(now()) {
            // Replace only on success. Retain rotated material even if a later
            // role exchange fails, and preserve current state on refresh errors.
            *token = token.refresh_token(ctx, &self.key.region, &now).await?;
        }
        if !token.is_valid_at(now()) {
            return Err(login_required("refreshed SSO access token has expired"));
        }
        Ok(token.access_token.clone())
    }
}

pub(super) async fn legacy_access_token(
    ctx: &Context,
    path: &str,
    now: Timestamp,
) -> Result<String> {
    let token = SessionToken::read(ctx, path)
        .await?
        .ok_or_else(|| login_required("SSO token cache not found"))?;
    if !token.is_valid_at(now) {
        return Err(login_required("legacy SSO token has expired"));
    }
    Ok(token.access_token)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedTokenFile {
    access_token: String,
    expires_at: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    registration_expires_at: Option<String>,
}

impl CachedTokenFile {
    fn into_token(self) -> Result<SessionToken> {
        let expires_at = self
            .expires_at
            .parse()
            .map_err(|_| login_required("invalid SSO token expiration"))?;
        // Invalid refresh material must not prevent use of a valid access token.
        let refresh = (|| {
            Some(RefreshMaterial {
                token: self.refresh_token.filter(|s| !s.is_empty())?,
                client_id: self.client_id.filter(|s| !s.is_empty())?,
                client_secret: self.client_secret.filter(|s| !s.is_empty())?,
                expires_at: self.registration_expires_at?.parse().ok()?,
            })
        })();
        Ok(SessionToken {
            access_token: self.access_token,
            expires_at,
            refresh,
        })
    }
}

struct SessionToken {
    access_token: String,
    expires_at: Timestamp,
    refresh: Option<RefreshMaterial>,
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken").finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct RefreshMaterial {
    token: String,
    client_id: String,
    client_secret: String,
    expires_at: Timestamp,
}

impl SessionToken {
    fn is_valid_at(&self, now: Timestamp) -> bool {
        !self.access_token.is_empty() && self.expires_at > now
    }

    async fn read(ctx: &Context, path: &str) -> Result<Option<Self>> {
        let content = match ctx.file_read(path).await {
            Ok(content) => content,
            Err(_) => return Ok(None),
        };
        serde_json::from_slice::<CachedTokenFile>(&content)
            .map_err(|_| login_required("invalid SSO token cache"))?
            .into_token()
            .map(Some)
    }

    async fn refresh_token(
        &self,
        ctx: &Context,
        region: &str,
        now: impl Fn() -> Timestamp + Send + Sync,
    ) -> Result<Self> {
        let material = self
            .refresh
            .as_ref()
            .ok_or_else(|| login_required("SSO refresh material is missing or invalid"))?;
        let started = now();
        if material.expires_at <= started {
            return Err(login_required("SSO client registration has expired"));
        }
        let body = serde_json::json!({
            "grantType": "refresh_token",
            "clientId": material.client_id,
            "clientSecret": material.client_secret,
            "refreshToken": material.token,
        });
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("https://oidc.{}.amazonaws.com/token", region))
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
        let mut material = material.clone();
        if let Some(token) = refreshed.refresh_token {
            material.token = token;
        }
        Ok(Self {
            access_token: refreshed.access_token,
            expires_at,
            refresh: Some(material),
        })
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

pub(super) fn login_required(reason: &str) -> Error {
    Error::config_invalid(format!(
        "{reason}. Please run 'aws sso login' for the selected profile"
    ))
}

// Simple SHA1 implementation for cache key generation
pub(super) fn hex_sha1(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
