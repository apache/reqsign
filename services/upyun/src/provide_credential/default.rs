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
use crate::provide_credential::UpxConfigCredentialProvider;
use reqsign_core::{
    Context, ProvideCredential, ProvideCredentialChain, ProvideCredentialDyn, Result,
};

/// Default credential provider for Upyun.
///
/// The default chain reads the current session from the Upyun CLI (`upx`)
/// configuration file at `~/.upx.cfg`. The file is bucket-scoped; configure
/// [`UpxConfigCredentialProvider::with_bucket`] when the request bucket must
/// select its own session. The returned credential carries that bucket, and
/// every signature requires the first segment of the request's wire path to
/// exactly equal it. Use [`DefaultCredentialProvider::push_front`] to supply
/// explicit credentials or another source.
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
    Default {
        upx_config: Option<UpxConfigCredentialProvider>,
    },
    Chain(ProvideCredentialChain<Credential>),
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

    /// Create a new `DefaultCredentialProvider` using the default chain.
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
    /// use reqsign_upyun::{DefaultCredentialProvider, StaticCredentialProvider};
    ///
    /// let provider = DefaultCredentialProvider::new()
    ///     .push_front(StaticCredentialProvider::new("operator", "password"));
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

/// Builder for `DefaultCredentialProvider`.
///
/// Use `upx_config(provider)` to set the Upyun CLI configuration slot or
/// `no_upx_config()` to remove it from the chain. Removed slots are not
/// re-enabled during `build()`.
#[derive(Debug)]
pub struct DefaultCredentialProviderBuilder {
    upx_config: Option<UpxConfigCredentialProvider>,
}

impl Default for DefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            upx_config: Some(UpxConfigCredentialProvider::new()),
        }
    }
}

impl DefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Upyun CLI configuration credential provider slot.
    pub fn upx_config(mut self, provider: UpxConfigCredentialProvider) -> Self {
        self.upx_config = Some(provider);
        self
    }

    /// Remove the Upyun CLI configuration credential provider slot.
    pub fn no_upx_config(mut self) -> Self {
        self.upx_config = None;
        self
    }

    /// Build the `DefaultCredentialProvider` with the configured options.
    pub fn build(self) -> DefaultCredentialProvider {
        DefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default {
                upx_config: self.upx_config,
            },
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
            CredentialSource::Default { upx_config } => match upx_config {
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

    #[tokio::test]
    async fn no_upx_config_removes_the_only_default_slot() -> anyhow::Result<()> {
        let provider = DefaultCredentialProvider::builder().no_upx_config().build();
        let credential = provider.provide_credential(&crate::test_context()).await?;

        assert!(credential.is_none());
        Ok(())
    }
}
