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
use crate::provide_credential::ConfigFileCredentialProvider;
use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};

/// Default credential provider for Seafile.
///
/// The default chain reads `server` and `token` from `~/.seafile.conf`, the
/// first-party `seaf-cli` user configuration file, and binds the credential to
/// that deployment. The `server` value is required. This crate documents no
/// environment-variable or login-command contract for Seafile, so those sources
/// are not part of the default chain.
///
/// [`DefaultCredentialProvider::with_chain`] keeps the caller-supplied
/// [`ProvideCredentialChain`] and its own error policy. Use the builder to
/// replace or remove the configuration-file slot. A removed slot is never
/// re-enabled during `build()`.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = Credential>>>,
    source: CredentialSource,
}

#[derive(Debug)]
enum CredentialSource {
    Default {
        config_file: Option<ConfigFileCredentialProvider>,
    },
    Chain(ProvideCredentialChain<Credential>),
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder with the documented default slot.
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
    /// The prepended provider is tried before the default configuration file.
    /// Its errors are returned instead of falling through to a lower-priority
    /// source, so an explicitly configured invalid credential cannot silently
    /// change the signing identity.
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
            CredentialSource::Default { config_file } => match config_file {
                Some(provider) => provider.provide_credential(ctx).await,
                None => Ok(None),
            },
            CredentialSource::Chain(chain) => chain.provide_credential(ctx).await,
        }
    }
}

/// Builder for [`DefaultCredentialProvider`].
///
/// Use [`Self::config_file`] to replace the default configuration-file slot, or
/// [`Self::no_config_file`] to remove it. A removed slot is not re-enabled
/// during `build()`.
#[derive(Debug)]
pub struct DefaultCredentialProviderBuilder {
    config_file: Option<ConfigFileCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            config_file: Some(ConfigFileCredentialProvider::new()),
        }
    }
}

impl DefaultCredentialProviderBuilder {
    /// Create a builder with the documented default slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Seafile CLI configuration-file provider slot.
    pub fn config_file(mut self, provider: ConfigFileCredentialProvider) -> Self {
        self.config_file = Some(provider);
        self
    }

    /// Remove the Seafile CLI configuration-file provider slot.
    pub fn no_config_file(mut self) -> Self {
        self.config_file = None;
        self
    }

    /// Build the provider with the configured slots.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default {
                config_file: self.config_file,
            },
        }
    }
}
