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

use crate::Credential;

/// Default credential provider for Yandex Disk.
///
/// The default chain is empty. Yandex Disk documents no environment variable,
/// CLI token store, or well-known credential file for OAuth access tokens, so
/// this crate does not infer one. [`DefaultCredentialProvider::new`] therefore
/// yields no credential instead of reading an undocumented source.
///
/// Compose an explicit [`crate::StaticCredentialProvider`] with
/// [`DefaultCredentialProvider::push_front`] or
/// [`DefaultCredentialProvider::with_chain`], or supply a dynamic
/// [`ProvideCredential`] implementation for token rotation.
///
/// Providers added with `push_front` fail closed: an error is returned instead
/// of falling through to the chain. A caller-supplied chain keeps
/// [`ProvideCredentialChain`]'s error policy.
#[derive(Debug)]
pub struct DefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = Credential>>>,
    chain: ProvideCredentialChain<Credential>,
}

impl Default for DefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCredentialProvider {
    /// Create a builder for the default credential provider.
    pub fn builder() -> DefaultCredentialProviderBuilder {
        DefaultCredentialProviderBuilder
    }

    /// Create the default provider with an empty automatic chain.
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
            chain,
        }
    }

    /// Add a credential provider to the front of the chain.
    ///
    /// The prepended provider is tried before the default chain. Its errors are
    /// returned instead of falling through to a lower-priority source, so an
    /// explicitly configured invalid credential cannot silently change the
    /// signing identity.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_yandex_disk::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("yandex-disk-oauth-token"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
    ) -> Self {
        self.front.insert(0, Box::new(provider));
        self
    }
}

impl ProvideCredential for DefaultCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        for provider in &self.front {
            if let Some(credential) = provider.provide_credential_dyn(ctx).await? {
                return Ok(Some(credential));
            }
        }

        self.chain.provide_credential(ctx).await
    }
}

/// Builder for [`DefaultCredentialProvider`].
///
/// The default chain has no automatic slots, so this builder exposes no slot
/// methods. It exists so the default provider follows the repository-wide
/// default-provider API and can gain verified slots without changing its
/// construction contract.
#[derive(Debug, Default)]
pub struct DefaultCredentialProviderBuilder;

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with the empty default state.
    pub fn new() -> Self {
        Self
    }

    /// Build the default provider.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider {
            front: Vec::new(),
            chain: ProvideCredentialChain::new(),
        }
    }
}
