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

use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use reqsign_core::{Error, Result, SigningCredential};

/// Proactive refresh window used when deciding whether a cached access token
/// should be refreshed.
const TOKEN_REFRESH_WINDOW: Duration = Duration::from_secs(120);

/// An Aliyun Drive Open Platform access token.
///
/// The token authenticates API requests as `Authorization: Bearer <token>`.
/// The drive ID, file paths, and storage API requests are selected by the
/// caller and are not part of the credential.
///
/// The access token is a secret. `Debug` output redacts it, and
/// [`Credential::bearer_header_value`] is the supported way to obtain request
/// authentication material. An optional absolute expiration is kept exactly;
/// [`SigningCredential::is_valid`] applies a small proactive refresh window
/// while [`Credential::is_valid_at`] performs the exact check.
#[derive(Clone)]
pub struct Credential {
    access_token: String,
    expires_at: Option<Timestamp>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_token", &Redact::from(&self.access_token))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential {
    /// Create a credential from an access token with unknown expiration.
    ///
    /// Pass the token itself, not an `Authorization` header value. The token
    /// must be non-empty and usable as an HTTP header value. A token with an
    /// unknown lifetime remains valid until the caller supplies another one or
    /// the service rejects it.
    pub fn new(access_token: impl Into<String>) -> Result<Self> {
        Self::from_parts(access_token, None)
    }

    /// Create a credential from an access token and its absolute expiration.
    pub fn with_expires_at(access_token: impl Into<String>, expires_at: Timestamp) -> Result<Self> {
        Self::from_parts(access_token, Some(expires_at))
    }

    pub(crate) fn from_parts(
        access_token: impl Into<String>,
        expires_at: Option<Timestamp>,
    ) -> Result<Self> {
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

    /// Build a sensitive `Authorization: Bearer` header value.
    ///
    /// Errors never contain the token.
    pub fn bearer_header_value(&self) -> Result<http::HeaderValue> {
        let mut value: http::HeaderValue = format!("Bearer {}", self.access_token)
            .parse()
            .map_err(|_| {
                Error::config_invalid("Aliyun Drive access token is not a valid HTTP header value")
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

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + TOKEN_REFRESH_WINDOW)
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        Credential::is_valid_at(self, timestamp)
    }
}

fn validate_access_token(value: &str) -> Result<()> {
    let invalid = || {
        Error::config_invalid(
            "Aliyun Drive access token must be a non-empty visible ASCII header value",
        )
    };
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
        || http::HeaderValue::from_str(value).is_err()
    {
        return Err(invalid());
    }

    Ok(())
}
