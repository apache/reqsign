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

use crate::Credential;
use reqsign_core::{Context, ProvideCredential, Result};

/// StaticCredentialProvider provides credentials supplied by the caller.
#[derive(Debug, Clone)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a new provider from a operator name and password.
    pub fn new(operator: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            credential: Credential::new(operator, password),
        }
    }

    /// Create a new provider from a complete credential.
    pub fn with_credential(credential: Credential) -> Self {
        Self { credential }
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(self.credential.clone()))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provides_the_configured_credential() -> anyhow::Result<()> {
        let ctx = crate::test_context();
        let provider = StaticCredentialProvider::new("operator", "password");

        let credential = provider
            .provide_credential(&ctx)
            .await?
            .expect("static provider always returns a credential");

        assert_eq!(credential.operator(), "operator");
        assert_eq!(credential.password(), "password");
        Ok(())
    }
}
