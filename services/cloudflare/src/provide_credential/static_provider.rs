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

use crate::credential::Credential;

/// Loads an explicit Cloudflare API token.
///
/// Use this provider with [`reqsign_core::Signer::with_credential_provider`] or
/// [`crate::DefaultCredentialProvider::push_front`] to override ambient
/// discovery. The token must be non-empty visible ASCII. An invalid explicit
/// value fails instead of falling back to a lower-priority source. `Debug` output
/// never contains the token.
#[derive(Clone)]
pub struct StaticCredentialProvider {
    api_token: String,
}

impl Debug for StaticCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl StaticCredentialProvider {
    /// Create a provider from an explicit API token.
    pub fn new(api_token: impl Into<String>) -> Self {
        Self {
            api_token: api_token.into(),
        }
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Credential::new(self.api_token.clone())
            .map(Some)
            .map_err(|_| Error::config_invalid("static Cloudflare API token is not usable"))
    }
}
