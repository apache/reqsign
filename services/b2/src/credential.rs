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

use reqsign_core::SigningCredential;
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;

/// Refresh the authorization token before it expires so an in-flight request
/// is not rejected while it is being retried.
const REFRESH_WINDOW: Duration = Duration::from_secs(120);

/// Credential returned by the Backblaze B2 Native API account authorization.
///
/// The authorization token authenticates every Native API call other than
/// `b2_authorize_account`. The API and download base URLs are bound to the
/// application key used for the exchange, so they belong to the credential and
/// must not be reconstructed by callers.
///
/// B2 also returns key restrictions such as capabilities and bucket or prefix
/// allow-lists. Those restrictions are enforced by B2 when the token is used and
/// are not needed to sign a request, so they are intentionally not retained.
#[derive(Clone, Default)]
pub struct Credential {
    /// The authorization token used in the Native API `Authorization` header.
    pub authorization_token: String,
    /// The base URL for Native API calls other than uploading and downloading.
    pub api_url: String,
    /// The base URL for downloading files.
    pub download_url: String,
    /// The absolute expiration time of the authorization token.
    ///
    /// B2 caps an authorization token at 24 hours. When the application key has
    /// an earlier expiration timestamp, that earlier deadline is used.
    pub expires_at: Option<Timestamp>,
}

impl Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field(
                "authorization_token",
                &Redact::from(&self.authorization_token),
            )
            .field("api_url", &self.api_url)
            .field("download_url", &self.download_url)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credential {
    /// Create a credential from a Native API authorization token and its base URLs.
    pub fn new(
        authorization_token: impl Into<String>,
        api_url: impl Into<String>,
        download_url: impl Into<String>,
    ) -> Self {
        Self {
            authorization_token: authorization_token.into(),
            api_url: api_url.into(),
            download_url: download_url.into(),
            expires_at: None,
        }
    }

    /// Set the absolute expiration time of the authorization token.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Return whether the credential has enough data to sign Native API calls.
    pub(crate) fn is_complete(&self) -> bool {
        !self.authorization_token.is_empty()
            && !self.api_url.is_empty()
            && !self.download_url.is_empty()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + REFRESH_WINDOW)
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        if !self.is_complete() {
            return false;
        }

        self.expires_at
            .is_none_or(|expires_at| expires_at > timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(expires_at: Option<Timestamp>) -> Credential {
        Credential {
            authorization_token: "authorization-token-value".to_string(),
            api_url: "https://api001.backblazeb2.com".to_string(),
            download_url: "https://f001.backblazeb2.com".to_string(),
            expires_at,
        }
    }

    #[test]
    fn empty_credential_is_invalid() {
        assert!(!Credential::default().is_valid());
    }

    #[test]
    fn missing_endpoint_is_invalid() {
        let mut value = credential(None);
        value.api_url.clear();
        assert!(!value.is_valid());

        let mut value = credential(None);
        value.download_url.clear();
        assert!(!value.is_valid());
    }

    #[test]
    fn credential_without_expiration_is_valid() {
        let value = credential(None);

        assert!(value.is_valid());
        assert!(value.is_valid_at(Timestamp::now() + Duration::from_secs(86_400)));
    }

    #[test]
    fn credential_refreshes_before_expiration_but_stays_usable_until_then() {
        let value = credential(Some(Timestamp::now() + Duration::from_secs(30)));

        // The cached token is refreshed before its actual deadline...
        assert!(!value.is_valid());
        // ...and remains usable for a request that finishes before it.
        assert!(value.is_valid_at(Timestamp::now()));
        assert!(!value.is_valid_at(Timestamp::now() + Duration::from_secs(31)));
    }

    #[test]
    fn debug_redacts_the_authorization_token() {
        let value = credential(None);
        let debug = format!("{value:?}");

        assert!(!debug.contains("authorization-token-value"));
        assert!(debug.contains("https://api001.backblazeb2.com"));
        assert!(debug.contains("https://f001.backblazeb2.com"));
    }
}
