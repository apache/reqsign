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

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::credential::Credential;

/// Loads an explicit Aliyun Drive access token.
///
/// Use this provider when the caller already holds an access token and manages
/// its renewal. Without an explicit expiration the token is treated as having
/// an unknown lifetime; use [`StaticCredentialProvider::with_expires_at`] when
/// the caller knows the absolute expiration.
///
/// An invalid explicit value fails instead of falling back to another source.
/// `Debug` output never contains the token.
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

    /// Create a provider from an access token with a known absolute expiration.
    pub fn with_expires_at(access_token: impl Into<String>, expires_at: Timestamp) -> Self {
        Self {
            access_token: access_token.into(),
            expires_at: Some(expires_at),
        }
    }
}

impl ProvideCredential for StaticCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Credential::from_parts(self.access_token.clone(), self.expires_at)
            .map(Some)
            .map_err(|_| Error::config_invalid("static Aliyun Drive access token is not usable"))
    }
}
