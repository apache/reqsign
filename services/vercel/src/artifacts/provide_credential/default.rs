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

use crate::artifacts::{
    ArtifactsCredential, ArtifactsEnvCredentialProvider, ArtifactsVercelEnvCredentialProvider,
};

/// Default credential provider for Vercel Artifacts.
///
/// The default chain is:
///
/// 1. `TURBO_TOKEN` through [`Context`] environment access.
/// 2. `VERCEL_ARTIFACTS_TOKEN` through [`Context`] environment access.
///
/// `TURBO_TOKEN` is the bearer token documented for the Turborepo Remote Cache;
/// Vercel injects `VERCEL_ARTIFACTS_TOKEN` into its build environments. When both
/// are present, `TURBO_TOKEN` is tried first; the Vercel-injected variable is the
/// build-environment fallback.
///
/// The team scope (`TURBO_TEAM`, `TURBO_TEAMID`, `VERCEL_ARTIFACTS_OWNER`) and
/// the cache key select the target cache in the request. They stay with the
/// caller and are never part of the credential.
///
/// Default slots and prepended providers fail closed: an unusable configured
/// token returns an error instead of silently selecting another identity. An
/// absent credential is not an error and yields `Ok(None)`.
///
/// [`ArtifactsDefaultCredentialProvider::with_chain`] keeps the caller-supplied
/// [`ProvideCredentialChain`] and its own error policy. Use the builder to
/// replace or remove individual default slots. A removed slot is never
/// re-enabled during `build()`.
#[derive(Debug)]
pub struct ArtifactsDefaultCredentialProvider {
    front: Vec<Box<dyn ProvideCredentialDyn<Credential = ArtifactsCredential>>>,
    source: CredentialSource,
}

#[derive(Debug)]
enum CredentialSource {
    Default {
        env: Option<ArtifactsEnvCredentialProvider>,
        vercel_env: Option<ArtifactsVercelEnvCredentialProvider>,
    },
    Chain(ProvideCredentialChain<ArtifactsCredential>),
}

impl Default for ArtifactsDefaultCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactsDefaultCredentialProvider {
    /// Create a builder with the documented default slots.
    pub fn builder() -> ArtifactsDefaultCredentialProviderBuilder {
        ArtifactsDefaultCredentialProviderBuilder::default()
    }

    /// Create a new default provider with the documented chain.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create with a custom credential chain.
    ///
    /// The supplied chain keeps [`ProvideCredentialChain`]'s error policy: a
    /// provider error is logged and the chain continues to the next provider.
    pub fn with_chain(chain: ProvideCredentialChain<ArtifactsCredential>) -> Self {
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
    /// use reqsign_vercel::{ArtifactsDefaultCredentialProvider, ArtifactsStaticCredentialProvider};
    ///
    /// let provider = ArtifactsDefaultCredentialProvider::new()
    ///     .push_front(ArtifactsStaticCredentialProvider::new("vercel-artifacts-token"));
    /// ```
    pub fn push_front(
        mut self,
        provider: impl ProvideCredential<Credential = ArtifactsCredential> + 'static,
    ) -> Self {
        self.front.insert(0, Box::new(provider));
        self
    }

    async fn provide_from_front(&self, ctx: &Context) -> Result<Option<ArtifactsCredential>> {
        for provider in &self.front {
            if let Some(credential) = provider.provide_credential_dyn(ctx).await? {
                return Ok(Some(credential));
            }
        }

        Ok(None)
    }
}

impl ProvideCredential for ArtifactsDefaultCredentialProvider {
    type Credential = ArtifactsCredential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        if let Some(credential) = self.provide_from_front(ctx).await? {
            return Ok(Some(credential));
        }

        match &self.source {
            CredentialSource::Default { env, vercel_env } => {
                if let Some(provider) = env {
                    if let Some(credential) = provider.provide_credential(ctx).await? {
                        return Ok(Some(credential));
                    }
                }
                match vercel_env {
                    Some(provider) => provider.provide_credential(ctx).await,
                    None => Ok(None),
                }
            }
            CredentialSource::Chain(chain) => chain.provide_credential(ctx).await,
        }
    }
}

/// Builder for [`ArtifactsDefaultCredentialProvider`].
///
/// Use `env(provider)` to set the `TURBO_TOKEN` slot or `no_env()` to remove it.
/// Use `vercel_env(provider)` to set the `VERCEL_ARTIFACTS_TOKEN` slot or
/// `no_vercel_env()` to remove it. Removed slots are not re-enabled during
/// `build()`.
///
/// # Examples
///
/// ```no_run
/// use reqsign_vercel::{
///     ArtifactsDefaultCredentialProvider, ArtifactsEnvCredentialProvider,
///     ArtifactsVercelEnvCredentialProvider,
/// };
///
/// let provider = ArtifactsDefaultCredentialProvider::builder()
///     .env(ArtifactsEnvCredentialProvider::new())
///     .vercel_env(ArtifactsVercelEnvCredentialProvider::new())
///     .build();
///
/// let turbo_only = ArtifactsDefaultCredentialProvider::builder()
///     .no_vercel_env()
///     .build();
/// ```
#[derive(Debug)]
pub struct ArtifactsDefaultCredentialProviderBuilder {
    env: Option<ArtifactsEnvCredentialProvider>,
    vercel_env: Option<ArtifactsVercelEnvCredentialProvider>,
}

impl Default for ArtifactsDefaultCredentialProviderBuilder {
    fn default() -> Self {
        Self {
            env: Some(ArtifactsEnvCredentialProvider::new()),
            vercel_env: Some(ArtifactsVercelEnvCredentialProvider::new()),
        }
    }
}

impl ArtifactsDefaultCredentialProviderBuilder {
    /// Create a new builder with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `TURBO_TOKEN` environment credential provider slot.
    pub fn env(mut self, provider: ArtifactsEnvCredentialProvider) -> Self {
        self.env = Some(provider);
        self
    }

    /// Remove the `TURBO_TOKEN` environment credential provider slot.
    pub fn no_env(mut self) -> Self {
        self.env = None;
        self
    }

    /// Set the `VERCEL_ARTIFACTS_TOKEN` environment credential provider slot.
    pub fn vercel_env(mut self, provider: ArtifactsVercelEnvCredentialProvider) -> Self {
        self.vercel_env = Some(provider);
        self
    }

    /// Remove the `VERCEL_ARTIFACTS_TOKEN` environment credential provider slot.
    pub fn no_vercel_env(mut self) -> Self {
        self.vercel_env = None;
        self
    }

    /// Build the `ArtifactsDefaultCredentialProvider` with the configured slots.
    pub fn build(self) -> ArtifactsDefaultCredentialProvider {
        ArtifactsDefaultCredentialProvider {
            front: Vec::new(),
            source: CredentialSource::Default {
                env: self.env,
                vercel_env: self.vercel_env,
            },
        }
    }
}
