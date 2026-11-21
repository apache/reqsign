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
use crate::provide_credential::{
    AnonymousCredentialProvider, EnvCredentialProvider, GhCliCredentialProvider,
};
use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};

/// Default credential provider for GitHub.com.
///
/// The default chain is:
///
/// 1. `GH_TOKEN`, then `GITHUB_TOKEN` through [`Context`] environment access;
/// 2. the stored GitHub.com token from the GitHub CLI, when the context has a
///    command executor;
/// 3. an explicit anonymous credential for public resources.
///
/// The default slots stop at the first error instead of silently selecting a
/// different identity. A malformed environment token, an unusable stored CLI
/// token, or a malformed prepended provider therefore fails the signer. An
/// absent credential is not an error: the anonymous slot is the only fallback.
///
/// [`DefaultCredentialProvider::with_chain`] keeps the caller-supplied
/// [`ProvideCredentialChain`] and its own error policy. Use the builder to
/// replace or remove individual default slots. A removed slot is never
/// re-enabled during `build()`.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = Credential>>>,
    source: CredentialSource,
}

#[derive(Debug)]
enum CredentialSource {
    Default {
        env: Option<EnvCredentialProvider>,
        gh_cli: Option<GhCliCredentialProvider>,
        anonymous: Option<AnonymousCredentialProvider>,
    },
    Chain(ProvideCredentialChain<Credential>),
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder with the documented default slots.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new default provider with the documented chain.
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
    /// The prepended provider is tried before every default source. Its errors
    /// are returned instead of falling through to a lower-priority source, so
    /// an explicitly configured invalid credential cannot silently change the
    /// signing identity.
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

impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if let Some(credential) = self.provide_from_front(ctx).await? {
            return Ok(Some(credential));
        }

        match &self.source {
            CredentialSource::Default {
                env,
                gh_cli,
                anonymous,
            } => {
                if let Some(provider) = env {
                    if let Some(credential) = provider.provide_credential(ctx).await? {
                        return Ok(Some(credential));
                    }
                }
                if let Some(provider) = gh_cli {
                    if let Some(credential) = provider.provide_credential(ctx).await? {
                        return Ok(Some(credential));
                    }
                }
                if let Some(provider) = anonymous {
                    return provider.provide_credential(ctx).await;
                }

                Ok(None)
            }
            CredentialSource::Chain(chain) => chain.provide_credential(ctx).await,
        }
    }
}

/// Builder for [`DefaultCredentialProvider`].
///
/// Use a provider slot method to replace a default, or its matching `no_*`
/// method to remove it. Removed slots are not re-enabled during `build()`.
#[derive(Debug)]
pub struct DefaultCredentialProviderBuilder {
    env: Option<EnvCredentialProvider>,
    gh_cli: Option<GhCliCredentialProvider>,
    anonymous: Option<AnonymousCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(EnvCredentialProvider::new()),
            gh_cli: Some(GhCliCredentialProvider::new()),
            anonymous: Some(AnonymousCredentialProvider::new()),
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

    /// Set the GitHub CLI credential provider slot.
    pub fn gh_cli(mut self, provider: GhCliCredentialProvider) -> Self {
        self.gh_cli = Some(provider);
        self
    }

    /// Remove the GitHub CLI credential provider slot.
    pub fn no_gh_cli(mut self) -> Self {
        self.gh_cli = None;
        self
    }

    /// Set the anonymous credential provider slot.
    pub fn anonymous(mut self, provider: AnonymousCredentialProvider) -> Self {
        self.anonymous = Some(provider);
        self
    }

    /// Remove the anonymous credential provider slot.
    pub fn no_anonymous(mut self) -> Self {
        self.anonymous = None;
        self
    }

    /// Build the provider with the configured slots.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default {
                env: self.env,
                gh_cli: self.gh_cli,
                anonymous: self.anonymous,
            },
        }
    }
}
