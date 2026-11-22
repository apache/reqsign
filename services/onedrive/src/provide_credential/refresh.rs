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
use crate::constants::{DEFAULT_TENANT, ENTRA_AUTH_ENDPOINT, ENTRA_TOKEN_PATH};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use reqsign_oauth2::RefreshTokenGrant;
use std::fmt::{self, Debug, Formatter};

/// Exchanges a Microsoft Entra user refresh token for a Microsoft Graph access
/// token.
///
/// The default endpoint is the global Microsoft Entra v2.0 token endpoint for
/// the `common` tenant, and the exchange carries no client secret. That is the
/// public-client flow: Microsoft documents that public clients cannot hold a
/// client secret. A confidential client adds its secret with
/// [`RefreshCredentialProviderBuilder::client_secret`] before the exchange.
///
/// Clones share the latest refresh token and serialize exchanges. Microsoft
/// returns a new refresh token with a successful exchange and requires the
/// client to discard the previous one, so the exchange is serialized and the
/// returned refresh token is committed before the next caller runs.
///
/// A Microsoft Graph token response carries `expires_in`. A successful response
/// that omits it, or whose token is already past, is rejected rather than
/// cached as a token with an unknown lifetime; a returned refresh token from
/// that response is still committed.
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
    /// Create a public-client provider from a client ID and refresh token.
    ///
    /// The exchange sends no client secret. Use
    /// [`RefreshCredentialProvider::builder`] for a confidential client secret,
    /// another tenant, an explicit scope, or a national-cloud token endpoint.
    pub fn new(client_id: impl Into<String>, refresh_token: impl Into<String>) -> Result<Self> {
        Self::builder(client_id, refresh_token).build()
    }

    /// Create a builder for an explicit Microsoft Entra application.
    ///
    /// Configuration is applied once in [`RefreshCredentialProviderBuilder::build`].
    /// A built provider never rewrites its grant, so a refresh token rotated by
    /// Microsoft is not lost to a later configuration change.
    pub fn builder(
        client_id: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> RefreshCredentialProviderBuilder {
        RefreshCredentialProviderBuilder {
            client_id: client_id.into(),
            client_secret: None,
            refresh_token: refresh_token.into(),
            endpoint: TokenEndpoint::Tenant(DEFAULT_TENANT.to_string()),
            scope: None,
        }
    }
}

impl ProvideCredential for RefreshCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let access_token = self.grant.refresh(ctx).await?;

        if access_token.expires_at().is_none() {
            return Err(Error::credential_invalid(
                "OneDrive token response omitted expires_in required for refresh credentials",
            ));
        }
        if !access_token.is_valid_at(Timestamp::now()) {
            return Err(Error::credential_invalid(
                "OneDrive token response is not currently valid",
            ));
        }

        Ok(Some(Credential::new(access_token)))
    }
}

/// Builder for [`RefreshCredentialProvider`].
///
/// Every method is optional and returns the builder, so the documented public
/// client flow is just [`RefreshCredentialProvider::new`]. Validation happens
/// in [`RefreshCredentialProviderBuilder::build`].
pub struct RefreshCredentialProviderBuilder {
    client_id: String,
    client_secret: Option<String>,
    refresh_token: String,
    endpoint: TokenEndpoint,
    scope: Option<String>,
}

impl Debug for RefreshCredentialProviderBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshCredentialProviderBuilder")
            .finish_non_exhaustive()
    }
}

impl RefreshCredentialProviderBuilder {
    /// Add the application secret for a confidential client.
    ///
    /// Microsoft requires the secret for web apps, web APIs, and daemons, and
    /// documents that it must not be used from a public client such as a
    /// native app, because a public client cannot store it reliably.
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Select the Microsoft Entra tenant segment of the default endpoint.
    ///
    /// Microsoft documents `common`, `organizations`, `consumers`, or a tenant
    /// identifier such as a domain name or GUID. The default is `common`.
    /// Calling this method or [`RefreshCredentialProviderBuilder::token_endpoint`]
    /// last wins.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.endpoint = TokenEndpoint::Tenant(tenant.into());
        self
    }

    /// Replace the whole token endpoint.
    ///
    /// Use this for a national cloud, whose Microsoft Entra authentication
    /// endpoint differs from the global service, or for another trusted HTTPS
    /// endpoint. The endpoint must be an absolute HTTPS URI with a host and
    /// without userinfo or a fragment. Calling this method or
    /// [`RefreshCredentialProviderBuilder::tenant`] last wins.
    pub fn token_endpoint(mut self, token_endpoint: impl Into<String>) -> Self {
        self.endpoint = TokenEndpoint::Explicit(token_endpoint.into());
        self
    }

    /// Request an explicit scope on the refresh exchange.
    ///
    /// By default the exchange omits `scope`, which keeps the access token
    /// limited to the scopes the original grant received. When set, Microsoft
    /// requires the value to be equivalent to or a subset of that original
    /// grant. The value is a space-separated list from one resource; the
    /// Microsoft Graph OneDrive flows use `offline_access Files.ReadWrite`.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Validate the configuration and create the provider.
    pub fn build(self) -> Result<RefreshCredentialProvider> {
        let token_endpoint = match self.endpoint {
            TokenEndpoint::Tenant(tenant) => tenant_token_endpoint(&tenant)?,
            TokenEndpoint::Explicit(token_endpoint) => token_endpoint,
        };

        let grant = RefreshTokenGrant::new(
            token_endpoint,
            self.client_id,
            self.client_secret,
            self.refresh_token,
            self.scope,
        )?;

        Ok(RefreshCredentialProvider { grant })
    }
}

/// Which Microsoft Entra token endpoint a builder selects.
enum TokenEndpoint {
    /// The global service endpoint for one tenant segment.
    Tenant(String),
    /// A complete caller-supplied endpoint.
    Explicit(String),
}

/// Build the global Microsoft Entra v2.0 token endpoint for one tenant.
fn tenant_token_endpoint(tenant: &str) -> Result<String> {
    let invalid = || {
        Error::config_invalid(
            "OneDrive tenant must be common, organizations, consumers, or a tenant identifier such as a domain name or GUID",
        )
    };

    if tenant.is_empty()
        || tenant.starts_with('-')
        || tenant.ends_with('-')
        || tenant.starts_with('.')
        || tenant.ends_with('.')
        || tenant.contains("..")
        || !tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        return Err(invalid());
    }

    Ok(format!("{ENTRA_AUTH_ENDPOINT}/{tenant}{ENTRA_TOKEN_PATH}"))
}
