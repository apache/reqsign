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
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default credential provider for GitHub.com.
///
/// The default chain is:
///
/// 1. `GH_TOKEN`, then `GITHUB_TOKEN` through [`Context`] environment access;
/// 2. the stored GitHub.com token from `gh auth token`, when the context has a
///    command executor;
/// 3. an explicit anonymous credential for public resources.
///
/// Use the builder to replace or remove individual slots. A removed slot is
/// never re-enabled during `build()`.
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
    /// Create a builder with the documented default slots.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new default provider with the documented chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.chain = self.chain.push_front(provider);
        self
    }
}

impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        self.chain.provide_credential(ctx).await
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
        let mut chain = ProvideCredentialChain::new();
        if let Some(provider) = self.env {
            chain = chain.push(provider);
        }
        if let Some(provider) = self.gh_cli {
            chain = chain.push(provider);
        }
        if let Some(provider) = self.anonymous {
            chain = chain.push(provider);
        }

        DefaultCredentialProvider::with_chain(chain)
    }
}
