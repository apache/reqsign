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

use reqsign_core::SigningCredential;
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use std::fmt::{Debug, Formatter};
use std::time::Duration;

/// Credential for Volcengine TOS.
#[derive(Clone)]
pub struct Credential {
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: String,
    /// Session token.
    pub session_token: Option<String>,
    /// Absolute expiration time, when known.
    ///
    /// Credentials created by [`Credential::new`] leave this unset. A credential
    /// issued by Volcengine STS carries the exact server-provided `ExpiredTime`.
    pub expires_at: Option<Timestamp>,
}

impl Credential {
    pub fn new(access_key_id: &str, secret_access_key: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            session_token: None,
            expires_at: None,
        }
    }

    pub fn with_session_token(mut self, token: &str) -> Self {
        self.session_token = Some(token.to_string());
        self
    }

    /// Set the absolute expiration time for this credential.
    ///
    /// Use this for temporary credentials that already carry a known server-side
    /// expiration. A credential without an expiration is still accepted when its
    /// access key and secret access key are present.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &Redact::from(&self.access_key_id))
            .field("secret_access_key", &Redact::from(&self.secret_access_key))
            .field("session_token", &Redact::from(&self.session_token))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + Duration::from_secs(120))
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        if self.access_key_id.is_empty() || self.secret_access_key.is_empty() {
            return false;
        }

        self.expires_at
            .is_none_or(|expires_at| expires_at > timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_validity_checks_structure() {
        let credential = Credential::new("", "");

        assert!(!credential.is_valid_at(Timestamp::now()));
    }

    #[test]
    fn separates_cache_freshness_from_exact_validity() {
        let now = Timestamp::now();
        let credential = Credential::new("access-key", "secret-key")
            .with_session_token("token")
            .with_expires_at(now + Duration::from_secs(30));

        assert!(!credential.is_valid());
        assert!(credential.is_valid_at(now + Duration::from_secs(10)));
        assert!(!credential.is_valid_at(now + Duration::from_secs(30)));
    }

    #[test]
    fn constructors_leave_expiration_unknown() {
        let credential = Credential::new("access-key", "secret-key").with_session_token("token");

        assert!(credential.expires_at.is_none());
        assert!(credential.is_valid_at(Timestamp::now() + Duration::from_secs(3600)));
    }

    #[test]
    fn expiration_boundary_uses_authoritative_timestamp() {
        let expires_at: Timestamp = "2030-01-02T12:04:05+08:00".parse().unwrap();
        let credential = Credential::new("access-key", "secret-key")
            .with_session_token("token")
            .with_expires_at(expires_at);

        assert_eq!(
            expires_at,
            "2030-01-02T04:04:05Z"
                .parse::<Timestamp>()
                .expect("timestamp must parse")
        );
        assert!(
            credential.is_valid_at(
                "2030-01-02T04:04:04Z"
                    .parse()
                    .expect("timestamp must parse")
            )
        );
        assert!(
            !credential.is_valid_at(
                "2030-01-02T04:04:05Z"
                    .parse()
                    .expect("timestamp must parse")
            )
        );
    }
}
