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

use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::Credential;

/// Uses an access token that the caller already obtained.
///
/// Koofr does not return an expiry with the first-party SDK exchange, so a
/// static token is reused until the caller replaces the [`reqsign_core::Signer`]
/// or installs a provider/context that starts a new cache. Koofr rejecting the
/// token does not invalidate the cache automatically.
#[derive(Debug, Clone)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a provider from an existing Koofr access token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            credential: Credential::new(token),
        }
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        if !Credential::is_valid_token(self.credential.token()) {
            return Err(Error::credential_invalid(
                "Koofr static access token is empty or not usable in an unquoted authorization parameter",
            ));
        }

        Ok(Some(self.credential.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn returns_configured_token() {
        let provider = StaticCredentialProvider::new("fabricated-token");
        let credential = provider
            .provide_credential(&Context::new())
            .await
            .expect("static credential must load")
            .expect("credential must be present");

        assert_eq!("fabricated-token", credential.token());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn rejects_invalid_token_before_signer_cache() {
        for token in ["", " ", "fabricated token", "fabricated\t token"] {
            let provider = StaticCredentialProvider::new(token);
            let error = provider
                .provide_credential(&Context::new())
                .await
                .expect_err("invalid static token must be rejected");

            assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        }
    }

    #[test]
    fn debug_redacts_token() {
        let provider = StaticCredentialProvider::new("fabricated-secret-token-value");
        let debug = format!("{provider:?}");

        assert!(!debug.contains("fabricated-secret-token-value"));
    }
}
