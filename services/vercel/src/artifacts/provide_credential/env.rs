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

/// The bearer token variable documented for the Turborepo Remote Cache.
pub(crate) const TURBO_TOKEN: &str = "TURBO_TOKEN";

/// Loads a Vercel Artifacts token from `TURBO_TOKEN`.
///
/// Turborepo documents `TURBO_TOKEN` as the bearer token for Remote Cache
/// access. `TURBO_TEAM`, `TURBO_TEAMID`, and `VERCEL_ARTIFACTS_OWNER` select the
/// cache scope in the request query and stay with the caller.
///
/// A missing or empty variable yields no credential. A present but unusable
/// value fails instead of being treated as absent.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArtifactsEnvCredentialProvider;

impl ArtifactsEnvCredentialProvider {
    /// Create a new environment credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for ArtifactsEnvCredentialProvider {
    type Credential = ArtifactsCredential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(token) = env_token(ctx, TURBO_TOKEN, "Vercel Artifacts")? else {
            return Ok(None);
        };

        Ok(Some(ArtifactsCredential::from_bearer_token(token)))
    }
}
