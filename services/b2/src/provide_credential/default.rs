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

use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};

use crate::credential::Credential;

use super::env::EnvCredentialProvider;

/// Default credential provider for Backblaze B2.
///
/// The default chain discovers a B2 application key from the environment and
/// exchanges it for a Native API authorization token.
///
/// The default source and prepended providers fail closed: a provider error is
/// returned instead of falling through to a lower-priority source. In
/// particular, a retryable `b2_authorize_account` failure reaches the caller
/// with its kind and retryability unchanged. [`DefaultCredentialProvider::with_chain`]
/// keeps the caller-supplied [`ProvideCredentialChain`] and its own error
/// policy. A slot removed with the builder is never re-enabled during `build()`.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = Credential>>>,
    source: CredentialSource,
}

#[derive(Debug)]
enum CredentialSource {
    Default { env: Option<EnvCredentialProvider> },
    Chain(ProvideCredentialChain<Credential>),
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder to assemble the default credential chain.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new default credential provider.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    ///
    /// The supplied chain keeps [`ProvideCredentialChain`]'s error policy: a
    /// provider error is logged and the chain continues to the next provider.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self {
            front: Vec::new(),
            source: CredentialSource::Chain(chain),
        }
    }

    /// Add a credential provider to the front of the chain.
    ///
    /// The prepended provider is tried before the default source. Its errors are
    /// returned instead of falling through to a lower-priority source, so an
    /// explicitly configured invalid credential cannot silently change the
    /// signing identity. A later `push_front` takes precedence over an earlier
    /// one.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_b2::{Credential, DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new().push_front(
    ///     StaticCredentialProvider::new(Credential::new(
    ///         "authorization-token",
    ///         "https://api001.backblazeb2.com",
    ///         "https://f001.backblazeb2.com",
    ///     )),
    /// );
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.front.insert(0, Box::new(provider));
        self
    }

    async fn provide_from_front(&self, ctx: &Context) -> Result<Option<Credential>> {
        for provider in &self.front {
            if let Some(credential) = provider.provide_credential_dyn(ctx).await? {
                return Ok(Some(credential));
            }
        }

        Ok(None)
    }
}

/// Builder for [`DefaultCredentialProvider`].
///
/// The environment slot is enabled by default. Use [`Self::no_env`] to remove
/// it and supply credentials through another provider. Removed slots are not
/// re-enabled during `build()`.
#[derive(Debug)]
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
    /// Create a builder with the documented default slots.
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

    /// Build the default credential provider with the configured slots.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default { env: self.env },
        }
    }
}

impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if let Some(credential) = self.provide_from_front(ctx).await? {
            return Ok(Some(credential));
        }

        match &self.source {
            CredentialSource::Default { env } => match env {
                Some(provider) => provider.provide_credential(ctx).await,
                None => Ok(None),
            },
            CredentialSource::Chain(chain) => chain.provide_credential(ctx).await,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use reqsign_core::{Context, StaticEnv};

    #[tokio::test]
    async fn default_chain_skips_without_environment_credentials() {
        let context = Context::new().with_env(StaticEnv::default());

        let credential = DefaultCredentialProvider::new()
            .provide_credential(&context)
            .await
            .expect("missing environment credentials must not fail");

        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn removing_the_environment_slot_removes_the_default_source() {
        let context = Context::new().with_env(StaticEnv {
            home_dir: None,
            envs: std::collections::HashMap::from([
                (
                    "B2_APPLICATION_KEY_ID".to_string(),
                    "application-key-id".to_string(),
                ),
                (
                    "B2_APPLICATION_KEY".to_string(),
                    "application-key".to_string(),
                ),
            ]),
        });

        let provider = DefaultCredentialProvider::builder().no_env().build();
        let credential = provider
            .provide_credential(&context)
            .await
            .expect("empty chain must not fail");

        assert!(credential.is_none());
    }
}
