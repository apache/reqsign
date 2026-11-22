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
use reqsign_core::{Context, Error, ProvideCredential, Result, SigningCredential};
use std::fmt::{self, Debug, Formatter};

/// Loads an explicitly configured Baidu Netdisk access token.
///
/// The token is supplied by the caller. This provider does not read the
/// environment, a credential file, or an OAuth endpoint, and it does not
/// refresh or persist the token. An empty token is rejected instead of
/// entering the signer's credential cache. `Debug` output never contains the
/// token.
#[derive(Clone)]
pub struct StaticCredentialProvider {
    credential: Credential,
}

impl StaticCredentialProvider {
    /// Create a provider from an explicit Baidu Netdisk access token.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            credential: Credential::new(access_token),
        }
    }
}

impl Debug for StaticCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        if !self.credential.is_valid() {
            return Err(Error::config_invalid(
                "static Baidu Netdisk access token must not be empty",
            ));
        }

        Ok(Some(self.credential.clone()))
    }
}
