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

/// A Koofr access token.
///
/// Koofr returns this token from the first-party SDK's email and
/// application-specific password exchange. The token is sent as
/// `Authorization: Token token=<token>`.
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

    /// Return whether `token` can be sent as an unquoted authorization parameter.
    ///
    /// Koofr's first-party tokens are ASCII, and its unquoted `token=<token>`
    /// parameter has no quoting or escaping. The same check is used before a
    /// credential enters [`reqsign_core::Signer`]'s cache and when the signer
    /// writes the header, so invalid exchange data never becomes a cached
    /// credential.
    pub(crate) fn is_valid_token(token: &str) -> bool {
        !token.is_empty()
            && token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b',' | b';'))
    }
}

impl Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        Self::is_valid_token(&self.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::time::Timestamp;
    use std::time::Duration;

    #[test]
    fn rejects_tokens_that_cannot_be_unquoted_header_parameters() {
        for token in [
            "",
            " ",
            "fabricated token",
            "fabricated\ttoken",
            "fabricated\ntoken",
            "fabricated, token",
            "fabricated; token",
            "fabricated\"token",
            "密码密码密码",
        ] {
            let credential = Credential::new(token);

            assert!(!credential.is_valid(), "token must be rejected: {token:?}");
            assert!(!credential.is_valid_at(Timestamp::now()));
        }
    }

    #[test]
    fn accepts_confirmed_ascii_token_shapes_without_expiry() {
        for token in [
            "fabricated-token",
            "fabricated-token.1_2-3~",
            "fabricated-token+value=",
        ] {
            let credential = Credential::new(token);

            assert!(credential.is_valid(), "token must be accepted: {token:?}");
            assert!(credential.is_valid_at(Timestamp::now() + Duration::from_secs(3600)));
            assert_eq!(token, credential.token());
        }
    }

    #[test]
    fn debug_redacts_token_and_is_safe_for_unicode() {
        for token in [
            "fabricated-secret-token-value",
            "密码密码密码",
            "🚀abcdef12345",
        ] {
            let debug = format!("{:?}", Credential::new(token));

            assert!(!debug.contains(token));
            assert!(debug.contains("Credential"));
        }
    }
}
