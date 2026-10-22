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

use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

use crate::credential::Credential;

use super::env::EnvCredentialProvider;

/// Default credential provider for OpenStack Keystone.
///
/// Tries credential sources in order:
/// 1. Environment variables (`OS_AUTH_URL`, `OS_USERNAME`, etc.)
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    chain: ProvideCredentialChain<Credential>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder to configure the default credential chain.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new `DefaultCredentialProvider` instance using the default chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
    ///
    /// This allows adding a high-priority credential source that will be tried
    /// before all other providers in the default chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_openstack_keystone::{DefaultCredentialProvider, EnvCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(EnvCredentialProvider::new());
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }
}

/// Builder for `DefaultCredentialProvider`.
///
/// Use `env(provider)` to set the environment provider slot or `no_env()` to
/// remove it from the chain.
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(EnvCredentialProvider::new()),
        }
    }
}

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the environment credential provider slot.
    pub fn env(mut self, provider: EnvCredentialProvider) -> Self {
        self.env = Some(provider);
        self
    }

    /// Remove the environment credential provider slot.
    pub fn no_env(mut self) -> Self {
        self.env = None;
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        let mut chain = ProvideCredentialChain::new();
        if let Some(p) = self.env {
            chain = chain.push(p);
        }
        DefaultCredentialProvider::with_chain(chain)
    }
}

impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provide_credential::env::*;
    use reqsign_core::StaticEnv;
    use std::collections::HashMap;

    fn ctx_with_envs(envs: HashMap<String, String>) -> Context {
        Context::new().with_env(StaticEnv {
            home_dir: None,
            envs,
        })
    }

    #[tokio::test]
    async fn test_default_loader_without_env() {
        let ctx = ctx_with_envs(HashMap::new());

        // Without a mock server the env provider must bail out before doing I/O.
        let credential = DefaultCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .unwrap();

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_builder_no_env_removes_env_provider() {
        let ctx = ctx_with_envs(HashMap::from([
            (
                OS_AUTH_URL.to_string(),
                "http://127.0.0.1:5000/v3".to_string(),
            ),
            (OS_USERNAME.to_string(), "testuser".to_string()),
            (OS_PASSWORD.to_string(), "testpass".to_string()),
        ]));

        let provider = DefaultCredentialProvider::builder().no_env().build();
        assert!(provider.chain.is_empty());

        let credential = provider.provide_credential(&ctx).await.unwrap();
        assert!(credential.is_none());
    }
}
