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
use reqsign_core::{Context, ProvideCredential, ProvideCredentialChain, Result};

/// Default credential provider for Upyun.
///
/// The default chain reads the current session from the Upyun CLI (`upx`)
/// configuration file at `~/.upx.cfg`. The file is bucket-scoped; configure
/// [`UpxConfigCredentialProvider::with_bucket`] when the request bucket must
/// select its own session. The returned credential carries that bucket and the
/// request signer rejects requests for another bucket. Use
/// [`DefaultCredentialProvider::push_front`] to supply explicit credentials or
/// another source.
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

    /// Create a new `DefaultCredentialProvider` using the default chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    pub fn with_chain(chain: ProvideCredentialChain<Credential>) -> Self {
        Self { chain }
    }

    /// Add a credential provider to the front of the default chain.
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
        self.chain = self.chain.push_front(provider);
        self
    }
}

/// Builder for `DefaultCredentialProvider`.
///
/// Use `upx_config(provider)` to set the Upyun CLI configuration slot or
/// `no_upx_config()` to remove it from the chain.
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
        let mut chain = ProvideCredentialChain::new();
        if let Some(provider) = self.upx_config {
            chain = chain.push(provider);
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

    #[tokio::test]
    async fn no_upx_config_removes_the_only_default_slot() -> anyhow::Result<()> {
        let provider = DefaultCredentialProvider::builder().no_upx_config().build();
        let credential = provider.provide_credential(&crate::test_context()).await?;

        assert!(credential.is_none());
        Ok(())
    }
}
