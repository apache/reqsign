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
use crate::provide_credential::EnvCredentialProvider;
use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};

/// Default credential provider for Dropbox.
///
/// The default chain reads the access token documented by the official
/// `dbxcli` tool from `DBXCLI_ACCESS_TOKEN` through [`Context`] environment
/// access. Reqsign does not parse `dbxcli` account or team configuration files.
///
/// Refresh-token credentials require explicit client configuration and are
/// available through [`crate::RefreshCredentialProvider`]; they are not part of
/// this ambient chain.
///
/// The default source and prepended providers fail closed: a provider error is
/// returned instead of falling through to a lower-priority source, so an
/// invalid explicitly configured credential cannot silently change the signing
/// identity. [`DefaultCredentialProvider::with_chain`] keeps the caller-supplied
/// [`ProvideCredentialChain`] and its own error policy. A slot removed with the
/// builder is never re-enabled during `build()`.
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
    /// Create a builder with the documented default slots.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder::default()
    }

    /// Create a new default provider with the documented env chain.
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
            CredentialSource::Default { env } => match env {
                Some(provider) => provider.provide_credential(ctx).await,
                None => Ok(None),
            },
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

    /// Build the provider with the configured slots.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default { env: self.env },
        }
    }
}
