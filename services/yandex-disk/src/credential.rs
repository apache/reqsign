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
use std::time::Duration;

use reqsign_core::SigningCredential;
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use reqsign_core::{Error, Result};

/// The OAuth scheme used by the Yandex Disk REST API.
const OAUTH_SCHEME: &str = "OAuth";

/// How early a cached token is refreshed before its expiry.
const TOKEN_REFRESH_BUFFER: Duration = Duration::from_secs(120);

/// An opaque Yandex Disk OAuth access token.
///
/// Yandex Disk issues this token to an OAuth app for a specific user's Disk
/// and does not define a structure that callers can inspect. The value must be
/// non-empty visible ASCII so it can be used as an HTTP header value without
/// extra escaping. [`Debug`] output never contains the token.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken(String);

impl AccessToken {
    /// Create an opaque access token from its wire value.
    ///
    /// The value must be non-empty and contain only visible ASCII characters.
    /// Rejecting other input keeps malformed static values from becoming
    /// request authentication material and keeps redaction from slicing a
    /// non-ASCII string at an invalid byte boundary.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() {
            return Err(Error::config_invalid(
                "Yandex Disk access token must not be empty",
            ));
        }
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::config_invalid(
                "Yandex Disk access token must contain only visible ASCII characters",
            ));
        }

        Ok(Self(token))
    }

    /// Return the token value for request authentication.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AccessToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessToken")
            .field(&Redact::from(&self.0))
            .finish()
    }
}

/// A Yandex Disk credential for the REST API.
///
/// The credential contains the OAuth access token and an optional expiration.
/// Token issuance, refresh, revocation, and the permissions attached to the app
/// stay with the caller and Yandex OAuth. A credential without an expiration is
/// treated as static and is cached for the signer's lifetime. A provider that
/// rotates tokens can return a credential with an expiration so the signer
/// refreshes it. [`Credential::authorization_header_value`] is the supported
/// way to obtain request authentication material.
#[derive(Clone)]
pub struct Credential {
    access_token: AccessToken,
    expires_at: Option<Timestamp>,
}

impl Credential {
    /// Create a credential from an OAuth access token.
    pub fn new(access_token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            access_token: AccessToken::new(access_token)?,
            expires_at: None,
        })
    }

    /// Create a credential from an already validated opaque access token.
    pub fn from_access_token(access_token: AccessToken) -> Self {
        Self {
            access_token,
            expires_at: None,
        }
    }

    /// Set the absolute expiration time for this credential.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set a relative expiration time for this credential.
    ///
    /// The expiration is evaluated when this method is called.
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_at = Some(Timestamp::now() + expires_in);
        self
    }

    /// Return the opaque access token.
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Return the absolute expiration time, if one is known.
    pub fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Build a sensitive `Authorization: OAuth` header value.
    ///
    /// Errors never contain the token.
    pub fn authorization_header_value(&self) -> Result<http::HeaderValue> {
        let mut value: http::HeaderValue = format!("{OAUTH_SCHEME} {}", self.access_token.as_str())
            .parse()
            .map_err(|_| {
                Error::config_invalid("Yandex Disk access token is not a valid HTTP header value")
            })?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_token", &self.access_token)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.expires_at
            .is_none_or(|expires_at| expires_at > Timestamp::now() + TOKEN_REFRESH_BUFFER)
    }

    fn is_valid_at(&self, ts: Timestamp) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > ts)
    }
}
