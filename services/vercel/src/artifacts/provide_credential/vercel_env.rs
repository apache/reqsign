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

use reqsign_core::{Context, ProvideCredential, Result};

use crate::artifacts::ArtifactsCredential;
use crate::bearer::env_token;

/// The artifacts token variable that Vercel injects into its build environment.
pub(crate) const VERCEL_ARTIFACTS_TOKEN: &str = "VERCEL_ARTIFACTS_TOKEN";

/// Loads a Vercel Artifacts token from the Vercel-injected
/// `VERCEL_ARTIFACTS_TOKEN`.
///
/// Vercel provides this token together with `VERCEL_ARTIFACTS_OWNER` during
/// builds. The owner is a team ID used in the request query, so it stays with the
/// caller; this provider discovers only the token.
///
/// A missing or empty variable yields no credential. A present but unusable
/// value fails instead of being treated as absent.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArtifactsVercelEnvCredentialProvider;

impl ArtifactsVercelEnvCredentialProvider {
    /// Create a new Vercel environment credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for ArtifactsVercelEnvCredentialProvider {
    type Credential = ArtifactsCredential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(token) = env_token(ctx, VERCEL_ARTIFACTS_TOKEN, "Vercel Artifacts")? else {
            return Ok(None);
        };

        Ok(Some(ArtifactsCredential::from_bearer_token(token)))
    }
}
