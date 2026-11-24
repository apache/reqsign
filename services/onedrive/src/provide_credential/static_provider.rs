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
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, Result};
use reqsign_oauth2::AccessToken;
use std::fmt::{self, Debug, Formatter};

/// Loads an explicit Microsoft Graph access token.
///
/// Without an explicit expiration the token is treated as having an unknown
/// lifetime. Use [`StaticCredentialProvider::with_expires_at`] when the caller
/// knows the absolute expiration.
#[derive(Clone)]
pub struct StaticCredentialProvider {
    access_token: String,
    expires_at: Option<Timestamp>,
}

impl Debug for StaticCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl StaticCredentialProvider {
    /// Create a provider from an access token with unknown expiration.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            expires_at: None,
        }
    }

    /// Set the absolute expiration time reported with the token.
    pub fn with_expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        let access_token =
            AccessToken::new(self.access_token.clone(), self.expires_at).map_err(|_| {
                reqsign_core::Error::config_invalid(
                    "static OneDrive access token is not a usable header value",
                )
            })?;
        Ok(Some(Credential::new(access_token)))
    }
}
