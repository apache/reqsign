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

use crate::blob::{BlobCredential, BlobEnvCredentialProvider};

/// Default credential provider for Vercel Blob.
///
/// The default chain is:
///
/// 1. `BLOB_READ_WRITE_TOKEN` through [`Context`] environment access.
///
/// That is the only ambient source this crate discovers for Blob. Vercel's OIDC
/// and client-token flows need store or operation context in the request, so
/// they are not part of this chain.
///
/// Default slots and prepended providers fail closed: an unusable configured
/// token returns an error instead of silently selecting another identity. An
/// absent credential is not an error and yields `Ok(None)`.
///
/// [`BlobDefaultCredentialProvider::with_chain`] keeps the caller-supplied
/// [`ProvideCredentialChain`] and its own error policy. Use the builder to
/// replace or remove individual default slots. A removed slot is never
/// re-enabled during `build()`.
#[derive(Debug)]
pub struct BlobDefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = BlobCredential>>>,
    source: CredentialSource,
}

#[derive(Debug)]
enum CredentialSource {
    Default {
        env: Option<BlobEnvCredentialProvider>,
    },
    Chain(ProvideCredentialChain<BlobCredential>),
}

impl Default for BlobDefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobDefaultCredentialProvider {
    /// Create a builder with the documented default slots.
    pub fn builder() -> BlobDefaultCredentialProviderBuilder {
        BlobDefaultCredentialProviderBuilder::default()
    }

    /// Create a new default provider with the documented chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    ///
    /// The supplied chain keeps [`ProvideCredentialChain`]'s error policy: a
    /// provider error is logged and the chain continues to the next provider.
    pub fn with_chain(chain: ProvideCredentialChain<BlobCredential>) -> Self {
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
    /// signing identity.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reqsign_vercel::{BlobDefaultCredentialProvider, BlobStaticCredentialProvider};
    ///
    /// let provider = BlobDefaultCredentialProvider::new()
    ///     .push_front(BlobStaticCredentialProvider::new("vercel-blob-token"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = BlobCredential> + 'static,
    ) -> Self {
        self.front.insert(0, Box::new(provider));
        self
    }

    async fn provide_from_front(&self, ctx: &Context) -> Result<Option<BlobCredential>> {
        for provider in &self.front {
            if let Some(credential) = provider.provide_credential_dyn(ctx).await? {
                return Ok(Some(credential));
            }
        }

        Ok(None)
    }
}

impl ProvideCredential for BlobDefaultCredentialProvider {
    type Credential = BlobCredential;

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

/// Builder for [`BlobDefaultCredentialProvider`].
///
/// Use `env(provider)` to set the environment slot or `no_env()` to remove it
/// from the chain, then call `build()`. Removed slots are not re-enabled during
/// `build()`.
///
/// # Examples
///
/// ```no_run
/// use reqsign_vercel::{BlobDefaultCredentialProvider, BlobEnvCredentialProvider};
///
/// let provider = BlobDefaultCredentialProvider::builder()
///     .env(BlobEnvCredentialProvider::new())
///     .build();
///
/// let provider_without_env = BlobDefaultCredentialProvider::builder()
///     .no_env()
///     .build();
/// ```
#[derive(Debug)]
pub struct BlobDefaultCredentialProviderBuilder {
    env: Option<BlobEnvCredentialProvider>,
}

impl Default for BlobDefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(BlobEnvCredentialProvider::new()),
        }
    }
}

impl BlobDefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the environment credential provider slot.
    pub fn env(mut self, provider: BlobEnvCredentialProvider) -> Self {
        self.env = Some(provider);
        self
    }

    /// Remove the environment credential provider slot.
    pub fn no_env(mut self) -> Self {
        self.env = None;
        self
    }

    /// Build the `BlobDefaultCredentialProvider` with the configured slots.
    pub fn build(self) -> BlobDefaultCredentialProvider {
        BlobDefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default { env: self.env },
        }
    }
}
