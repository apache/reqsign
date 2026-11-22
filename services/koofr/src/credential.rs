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

use reqsign_core::SigningCredential;
use reqsign_core::utils::Redact;

/// A Koofr access token.
///
/// Koofr returns this token from the documented email and application-specific
/// password exchange. The token is sent as `Authorization: Token token=<token>`.
#[derive(Clone, Default)]
pub struct Credential {
    token: String,
}

impl Credential {
    /// Create a credential from an access token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }

    /// Return the access token.
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("token", &Redact::from(&self.token))
            .finish()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        !self.token.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::time::Timestamp;
    use std::time::Duration;

    #[test]
    fn rejects_empty_token() {
        let credential = Credential::new("");

        assert!(!credential.is_valid());
        assert!(!credential.is_valid_at(Timestamp::now() + Duration::from_secs(3600)));
    }

    #[test]
    fn accepts_non_empty_token_without_expiry() {
        let credential = Credential::new("fabricated-access-token");

        assert!(credential.is_valid());
        assert!(credential.is_valid_at(Timestamp::now() + Duration::from_secs(3600)));
        assert_eq!("fabricated-access-token", credential.token());
    }

    #[test]
    fn debug_redacts_token() {
        let debug = format!("{:?}", Credential::new("fabricated-secret-token-value"));

        assert!(!debug.contains("fabricated-secret-token-value"));
        assert!(debug.contains("token"));
    }
}
