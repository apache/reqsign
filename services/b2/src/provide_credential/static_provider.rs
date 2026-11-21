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

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result, SigningCredential};

use crate::credential::Credential;

/// Credential provider that returns an already obtained B2 authorization token.
///
/// Use this provider when the caller obtains the token and its Native API base
/// URLs from elsewhere. The credential must carry a non-empty authorization token,
/// `api_url`, and `download_url`; an expired token is rejected before signing.
#[derive(Clone, Debug)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a provider from a complete B2 credential.
    pub fn new(credential: Credential) -> Self {
        Self { credential }
    }

    fn validate(&self) -> Result<()> {
        if self.credential.authorization_token.is_empty() {
            return Err(Error::config_invalid(
                "static B2 credential has an empty authorization token",
            ));
        }
        validate_endpoint("api_url", &self.credential.api_url)?;
        validate_endpoint("download_url", &self.credential.download_url)?;
        if !self.credential.is_valid_at(Timestamp::now()) {
            return Err(Error::credential_invalid(
                "static B2 credential has expired",
            ));
        }

        Ok(())
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        self.validate()?;
        Ok(Some(self.credential.clone()))
    }
}

fn validate_endpoint(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::config_invalid(format!(
            "static B2 credential has an empty {field}"
        )));
    }

    let uri: http::Uri = value.parse().map_err(|e| {
        Error::config_invalid(format!("static B2 credential has an invalid {field}")).with_source(e)
    })?;
    if uri.scheme().is_none() || uri.authority().is_none() {
        return Err(Error::config_invalid(format!(
            "static B2 credential has a relative {field}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Credential {
        Credential::new(
            "authorization-token-value",
            "https://api001.backblazeb2.com",
            "https://f001.backblazeb2.com",
        )
    }

    #[tokio::test]
    async fn returns_the_supplied_credential() {
        let credential = credential();
        let provider = StaticCredentialProvider::new(credential.clone());

        let loaded = provider
            .provide_credential(&Context::new())
            .await
            .expect("static credential must load")
            .expect("static credential must be present");

        assert_eq!(credential.authorization_token, loaded.authorization_token);
        assert_eq!(credential.api_url, loaded.api_url);
        assert_eq!(credential.download_url, loaded.download_url);
    }

    #[tokio::test]
    async fn rejects_incomplete_credentials() {
        let provider = StaticCredentialProvider::new(Credential::new(
            "",
            "https://api001.backblazeb2.com",
            "",
        ));
        let error = provider
            .provide_credential(&Context::new())
            .await
            .expect_err("incomplete credential must fail");

        assert_eq!(reqsign_core::ErrorKind::ConfigInvalid, error.kind());
    }

    #[tokio::test]
    async fn rejects_an_expired_credential() {
        let credential =
            credential().with_expires_at(Timestamp::now() - std::time::Duration::from_secs(1));
        let provider = StaticCredentialProvider::new(credential);
        let error = provider
            .provide_credential(&Context::new())
            .await
            .expect_err("expired credential must fail");

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
    }
}
