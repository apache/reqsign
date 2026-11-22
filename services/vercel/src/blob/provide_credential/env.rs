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

use crate::bearer::env_token;
use crate::blob::BlobCredential;

/// The read-write token variable used by Vercel Blob and `@vercel/blob`.
pub(crate) const BLOB_READ_WRITE_TOKEN: &str = "BLOB_READ_WRITE_TOKEN";

/// Loads a Vercel Blob token from `BLOB_READ_WRITE_TOKEN`.
///
/// Vercel documents this variable as the long-lived static read-write token for
/// code running outside Vercel. A missing or empty variable yields no
/// credential. A present but unusable value fails instead of being treated as
/// absent.
///
/// The Blob store ID, API endpoint, and Vercel OIDC variables are not read here:
/// they select or adjust the operation that the caller constructs.
#[derive(Debug, Default, Clone, Copy)]
pub struct BlobEnvCredentialProvider;

impl BlobEnvCredentialProvider {
    /// Create a new environment credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for BlobEnvCredentialProvider {
    type Credential = BlobCredential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let Some(token) = env_token(ctx, BLOB_READ_WRITE_TOKEN, "Vercel Blob")? else {
            return Ok(None);
        };

        Ok(Some(BlobCredential::from_bearer_token(token)))
    }
}
