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
use crate::constants::DROPBOX_TOKEN_ENDPOINT;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use reqsign_oauth2::RefreshTokenGrant;
use std::fmt::{self, Debug, Formatter};

/// Exchanges a Dropbox OAuth 2.0 refresh token for an access token.
///
/// The provider uses Dropbox's documented token endpoint by default and sends
/// the client ID and secret in the RFC 6749 form body. Clones share the latest
/// refresh token and serialize exchanges.
///
/// Dropbox access tokens are expected to carry an expiration. A successful
/// token response without `expires_in`, or with an expiration that is already
/// past, is rejected rather than cached as a token with an unknown lifetime.
#[derive(Clone)]
pub struct RefreshCredentialProvider {
    grant: RefreshTokenGrant,
}

impl Debug for RefreshCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl RefreshCredentialProvider {
    /// Create a provider for an explicit Dropbox OAuth 2.0 application.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> Result<Self> {
        let grant = RefreshTokenGrant::new(
            DROPBOX_TOKEN_ENDPOINT,
            client_id,
            Some(client_secret.into()),
            refresh_token,
            None,
        )?;
        Ok(Self { grant })
    }

    /// Replace the token endpoint while preserving the latest refresh token.
    ///
    /// The endpoint must be an absolute HTTPS URI with a host and without
    /// userinfo or a fragment. The caller owns this explicit trust decision.
    pub fn with_token_endpoint(mut self, token_endpoint: impl Into<String>) -> Result<Self> {
        self.grant = self.grant.with_token_endpoint(token_endpoint)?;
        Ok(self)
    }
}

impl ProvideCredential for RefreshCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let access_token = self.grant.refresh(ctx).await?;

        if access_token.expires_at().is_none() {
            return Err(Error::credential_invalid(
                "Dropbox token response omitted expires_in required for refresh credentials",
            ));
        }
        if !access_token.is_valid_at(Timestamp::now()) {
            return Err(Error::credential_invalid(
                "Dropbox token response is not currently valid",
            ));
        }

        Ok(Some(Credential::new(access_token)))
    }
}
