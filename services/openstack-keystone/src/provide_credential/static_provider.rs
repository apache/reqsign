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

use reqsign_core::{Context, ProvideCredential, Result, time::Timestamp};

use crate::credential::{CatalogEntry, Credential};

/// Provider for a pre-issued OpenStack token.
///
/// The token is sent as the `X-Auth-Token` header and no Keystone request is
/// made. A token created outside reqsign does not carry a service catalog, so
/// callers that already have endpoint metadata can attach it with
/// [`with_service_catalog`](Self::with_service_catalog). Otherwise the service
/// endpoint remains caller configuration, as it is for the OpenDAL Swift
/// backend.
///
/// An empty token is treated as an absent credential so a provider chain can
/// continue with another source. An expired token is returned as configured;
/// the signer then rejects it instead of silently selecting a different
/// identity.
#[derive(Clone, Debug, Default)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a provider for the given token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            credential: Credential {
                token: token.into(),
                expires_at: None,
                service_catalog: Vec::new(),
            },
        }
    }

    /// Set the absolute expiration time of the token.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.credential.expires_at = Some(expires_at);
        self
    }

    /// Attach service catalog metadata that the caller already has.
    pub fn with_service_catalog(mut self, service_catalog: Vec<CatalogEntry>) -> Self {
        self.credential.service_catalog = service_catalog;
        self
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        if self.credential.token.is_empty() {
            return Ok(None);
        }

        Ok(Some(self.credential.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn skips_an_empty_token() {
        let credential = StaticCredentialProvider::new("")
            .provide_credential(&Context::new())
            .await
            .expect("provider must succeed");

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn returns_configured_expiration_and_catalog() {
        let expires_at = Timestamp::now() + std::time::Duration::from_secs(3600);
        let provider = StaticCredentialProvider::new("pre-issued-token")
            .with_expires_at(expires_at)
            .with_service_catalog(vec![CatalogEntry {
                service_type: "object-store".to_string(),
                endpoints: vec![crate::Endpoint {
                    interface: "public".to_string(),
                    url: "https://swift.example.com/v1/AUTH_test".to_string(),
                    region_id: Some("RegionOne".to_string()),
                    region: None,
                }],
            }]);

        let credential = provider
            .provide_credential(&Context::new())
            .await
            .expect("provider must succeed")
            .expect("credential must be present");

        assert_eq!(Some(expires_at), credential.expires_at);
        assert_eq!(
            credential.endpoint_in_region("object-store", "public", "RegionOne"),
            Some("https://swift.example.com/v1/AUTH_test")
        );
    }

    #[tokio::test]
    async fn debug_does_not_expose_the_token() {
        let provider = StaticCredentialProvider::new("top-secret-token");

        let debug = format!("{provider:?}");
        assert!(!debug.contains("top-secret-token"), "token leaked: {debug}");
        assert!(debug.contains("***"), "token must be redacted: {debug}");
    }
}
