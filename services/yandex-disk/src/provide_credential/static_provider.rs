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
use std::time::Duration;

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::Credential;

/// Loads an explicit Yandex Disk OAuth access token.
///
/// Use this provider with [`reqsign_core::Signer::with_credential_provider`] or
/// [`crate::DefaultCredentialProvider::push_front`]. An invalid explicit value
/// fails instead of falling back to another source. `Debug` output never
/// contains the token.
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
    /// Create a provider from an explicit OAuth access token.
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

    /// Set a relative expiration time reported with the token.
    ///
    /// The expiration is evaluated when this method is called.
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_at = Some(Timestamp::now() + expires_in);
        self
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        let credential = Credential::new(self.access_token.clone()).map_err(|err| {
            Error::config_invalid("static Yandex Disk access token is not usable").with_source(err)
        })?;
        let credential = match self.expires_at {
            Some(expires_at) => credential.with_expires_at(expires_at),
            None => credential,
        };

        Ok(Some(credential))
    }
}
