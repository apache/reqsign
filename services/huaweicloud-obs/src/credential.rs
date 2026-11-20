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

use std::fmt::{Debug, Formatter};
use std::time::Duration;

use reqsign_core::{SigningCredential, time::Timestamp, utils::Redact};

/// Credential for obs.
#[derive(Clone)]
pub struct Credential {
    /// Access key id for obs
    pub access_key_id: String,
    /// Secret access key for obs
    pub secret_access_key: String,
    /// security_token for obs.
    pub security_token: Option<String>,
    /// Absolute expiration time for this credential.
    ///
    /// `None` means that the credential has no known expiration, preserving the
    /// behavior of credentials configured with [`Credential::new`].
    pub expires_at: Option<Timestamp>,
}

impl Credential {
    /// Create a new credential without a known expiration.
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        security_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            security_token,
            expires_at: None,
        }
    }

    /// Set the absolute expiration time for this credential.
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
            .field(
                "security_token",
                &self.security_token.as_ref().map(Redact::from),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        self.is_valid_at(Timestamp::now() + Duration::from_secs(120))
    }

    fn is_valid_at(&self, timestamp: Timestamp) -> bool {
        !self.access_key_id.is_empty()
            && !self.secret_access_key.is_empty()
            && self
                .expires_at
                .is_none_or(|expires_at| expires_at > timestamp)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use http::Uri;
    use reqsign_core::{Result, SignRequest};

    use super::*;
    use crate::RequestSigner;

    #[test]
    fn rejects_incomplete_signing_keys() {
        let credential = Credential::new(String::new(), String::new(), Some("token".to_string()));

        assert!(!credential.is_valid());
        assert!(!credential.is_valid_at(Timestamp::now()));
    }

    #[test]
    fn separates_cache_freshness_from_exact_validity() {
        let now = Timestamp::now();
        let credential = Credential::new(
            "access-key".to_string(),
            "secret-key".to_string(),
            Some("token".to_string()),
        )
        .with_expires_at(now + Duration::from_secs(30));

        assert!(!credential.is_valid());
        assert!(credential.is_valid_at(now + Duration::from_secs(10)));
        assert!(!credential.is_valid_at(now + Duration::from_secs(30)));
    }

    #[test]
    fn constructor_without_expiry_stays_valid() {
        let credential = Credential::new("access-key".to_string(), "secret-key".to_string(), None);

        assert!(credential.expires_at.is_none());
        assert!(credential.is_valid());
        assert!(credential.is_valid_at(Timestamp::now() + Duration::from_secs(3600)));
    }

    #[test]
    fn debug_redacts_credential_material() {
        let debug = format!(
            "{:?}",
            Credential::new(
                "access-key-middle".to_string(),
                "secret-key-middle".to_string(),
                Some("security-token-middle".to_string()),
            )
            .with_expires_at(Timestamp::now() + Duration::from_secs(60))
        );

        assert!(!debug.contains("access-key-middle"));
        assert!(!debug.contains("secret-key-middle"));
        assert!(!debug.contains("security-token-middle"));
        assert!(debug.contains("expires_at"));
    }

    #[tokio::test]
    async fn expires_at_bounds_header_and_query_signing() -> Result<()> {
        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let request = "https://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt";

        let active = Credential::new(
            "access_key".to_string(),
            "123456".to_string(),
            Some("token".to_string()),
        )
        .with_expires_at(now + Duration::from_secs(10));
        let mut parts = http::Request::get(Uri::from_str(request)?)
            .body(())?
            .into_parts()
            .0;
        signer
            .sign_request(&crate::test_context(), &mut parts, Some(&active), None)
            .await?;

        let mut query_parts = http::Request::get(Uri::from_str(request)?)
            .body(())?
            .into_parts()
            .0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut query_parts,
                Some(&active),
                Some(Duration::from_secs(10)),
            )
            .await
            .expect_err("presigning must not outlive the credential");

        let expired = Credential::new(
            "access_key".to_string(),
            "123456".to_string(),
            Some("token".to_string()),
        )
        .with_expires_at(now);
        let mut expired_parts = http::Request::get(Uri::from_str(request)?)
            .body(())?
            .into_parts()
            .0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut expired_parts,
                Some(&expired),
                None,
            )
            .await
            .expect_err("expired credentials must not sign headers");

        Ok(())
    }
}
