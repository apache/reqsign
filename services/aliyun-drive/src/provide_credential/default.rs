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

/// Default credential provider for Aliyun Drive.
///
/// Aliyun Drive Open Platform documents OAuth authorization and token exchange,
/// but it does not define a CLI, SDK, environment-variable, or local-file
/// credential discovery contract. This crate therefore does not invent an
/// ambient source: the default chain is empty.
///
/// Supply the intended identity explicitly with
/// [`crate::StaticCredentialProvider`] for a caller-managed access token or
/// [`crate::RefreshCredentialProvider`] for a rotating refresh token, either
/// directly in [`reqsign_core::Signer::new`] or through
/// [`DefaultCredentialProvider::push_front`]. Use
/// [`DefaultCredentialProvider::with_chain`] to keep a caller-supplied chain and
/// its own error policy.
///
/// Prepended providers fail closed: an error is returned instead of falling
/// through to a lower-priority source, so an invalid explicitly configured
/// credential cannot silently change the signing identity.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = Credential>>>,
    source: CredentialSource,
}

#[derive(Debug)]
enum CredentialSource {
    Empty,
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
        DefaultCredentialProviderBuilder::new()
    }

    /// Create a new default provider with the documented empty chain.
    pub fn new() -> Self {
        Self {
            front: Vec::new(),
            source: CredentialSource::Empty,
        }
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
    /// returned instead of falling through, so an explicitly configured invalid
    /// credential cannot silently change the signing identity.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_aliyun_drive::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("access-token"));
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

impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if let Some(credential) = self.provide_from_front(ctx).await? {
            return Ok(Some(credential));
        }

        match &self.source {
            CredentialSource::Empty => Ok(None),
            CredentialSource::Chain(chain) => chain.provide_credential(ctx).await,
        }
    }
}

/// Builder for [`DefaultCredentialProvider`].
///
/// Aliyun Drive has no documented ambient credential source, so this builder
/// has no default provider slots. It preserves the uniform product API and
/// builds an empty chain; use [`DefaultCredentialProvider::push_front`] or
/// [`DefaultCredentialProvider::with_chain`] to compose explicit providers.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultCredentialProviderBuilder;

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self
    }

    /// Build the provider with the configured (empty) slots.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider::new()
    }
}
