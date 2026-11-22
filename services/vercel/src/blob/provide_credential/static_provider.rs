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

use std::fmt::{self, Debug, Formatter};

use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::bearer::BearerToken;
use crate::blob::BlobCredential;

/// Loads an explicit Vercel Blob token.
///
/// Use this provider with [`reqsign_core::Signer::with_credential_provider`] or
/// [`crate::BlobDefaultCredentialProvider::push_front`] to override ambient
/// discovery. The token must be non-empty visible ASCII. An invalid explicit
/// value fails instead of falling back to a lower-priority source. `Debug` output
/// never contains the token.
#[derive(Clone)]
pub struct BlobStaticCredentialProvider {
    token: String,
}

impl Debug for BlobStaticCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobStaticCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl BlobStaticCredentialProvider {
    /// Create a provider from an explicit bearer token.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl ProvideCredential for BlobStaticCredentialProvider {
    type Credential = BlobCredential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        let token = BearerToken::new(self.token.clone(), "Vercel Blob")
            .map_err(|_| Error::config_invalid("static Vercel Blob token is not usable"))?;

        Ok(Some(BlobCredential::from_bearer_token(token)))
    }
}
