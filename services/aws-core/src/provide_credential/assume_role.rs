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

use std::fmt::{Debug, Formatter};

use reqsign_core::{Context, ProvideCredential, Result, Signer};

use crate::Credential;
use crate::assume_role::{AssumeRoleGrant, AssumeRoleOperation};
use crate::provide_credential::sts_endpoint::resolve_sts_endpoint;

/// Loads credentials through one fixed AWS STS `AssumeRole` flow.
///
/// The STS endpoint follows the AWS SDKs' endpoint settings: an endpoint set with
/// [`Self::with_sts_endpoint`], then `AWS_ENDPOINT_URL_STS`, `AWS_ENDPOINT_URL`, the selected
/// profile's `sts` service `endpoint_url` and its global `endpoint_url`, and finally the
/// regional or partition default. The global `AWS_ENDPOINT_URL` and profile `endpoint_url`
/// therefore also redirect STS; set `AWS_ENDPOINT_URL_STS` (or the profile's `sts` service
/// endpoint) to send STS elsewhere, or set `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` (or the
/// profile's `ignore_configured_endpoint_urls = true`) to ignore every configured endpoint
/// except the explicit one. The STS signer signs for the region it was built with, whatever
/// the endpoint.
///
/// Use [`reqsign_core::Granter`] with the SigV4 crate's explicit AssumeRole
/// granter when the source credential and grant are supplied per vending
/// operation.
pub struct AssumeRoleCredentialProvider {
    grant: AssumeRoleGrant,
    duration_seconds: Option<u32>,
    region: Option<String>,
    use_regional_sts_endpoint: bool,
    sts_endpoint: Option<String>,
    sts_signer: Signer<Credential>,
}

impl Debug for AssumeRoleCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl AssumeRoleCredentialProvider {
    /// Create a new fixed-flow AssumeRole credential provider.
    pub fn new(role_arn: String, sts_signer: Signer<Credential>) -> Self {
        Self {
            grant: AssumeRoleGrant::new(role_arn, "reqsign"),
            duration_seconds: Some(3_600),
            region: None,
            use_regional_sts_endpoint: false,
            sts_endpoint: None,
            sts_signer,
        }
    }

    /// Set the role session name.
    pub fn with_role_session_name(mut self, name: String) -> Self {
        self.grant.role_session_name = name;
        self
    }

    /// Set the external ID.
    pub fn with_external_id(mut self, id: String) -> Self {
        self.grant.external_id = Some(id);
        self
    }

    /// Set the duration in seconds.
    pub fn with_duration_seconds(mut self, seconds: u32) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Set the session policy.
    pub fn with_policy(mut self, policy: String) -> Self {
        self.grant.policy = Some(policy);
        self
    }

    /// Set the session policy ARNs.
    pub fn with_policy_arns(mut self, policy_arns: Vec<String>) -> Self {
        self.grant.policy_arns = policy_arns;
        self
    }

    /// Set the session tags.
    pub fn with_tags(mut self, tags: Vec<(String, String)>) -> Self {
        self.grant.tags = tags;
        self
    }

    /// Set the region used to select a regional STS endpoint.
    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    /// Use a regional STS endpoint.
    pub fn with_regional_sts_endpoint(mut self) -> Self {
        self.use_regional_sts_endpoint = true;
        self
    }

    /// Send the STS request to this endpoint, for example `https://sts.example.com:8443`.
    ///
    /// This takes precedence over every environment and profile endpoint setting, including
    /// `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS`. The URL needs an `https` or `http` scheme and a
    /// host, and no path or query.
    ///
    /// An `http://` endpoint sends the signed request, and receives the temporary
    /// credentials, in cleartext. Use it only on a network you trust to carry them.
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = Some(endpoint.into());
        self
    }

    /// Set the MFA serial number.
    pub fn with_mfa_serial(mut self, serial_number: String) -> Self {
        self.grant.serial_number = Some(serial_number);
        self
    }

    /// Set the MFA token code.
    pub fn with_mfa_code(mut self, token_code: String) -> Self {
        self.grant.token_code = Some(token_code);
        self
    }

    /// Create a fixed-flow provider from AWS environment variables.
    pub fn from_env(ctx: &Context, sts_signer: Signer<Credential>) -> Option<Self> {
        let role_arn = ctx.env_var("AWS_ROLE_ARN")?;
        let mut provider = Self::new(role_arn, sts_signer);

        if let Some(name) = ctx.env_var("AWS_ROLE_SESSION_NAME") {
            provider = provider.with_role_session_name(name);
        }
        if let Some(id) = ctx.env_var("AWS_EXTERNAL_ID") {
            provider = provider.with_external_id(id);
        }
        if let Some(region) = ctx.env_var("AWS_REGION") {
            provider = provider.with_region(region);
        }
        if ctx.env_var("AWS_STS_REGIONAL_ENDPOINTS").as_deref() == Some("regional") {
            provider = provider.with_regional_sts_endpoint();
        }

        Some(provider)
    }
}

impl ProvideCredential for AssumeRoleCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        match self.region.as_deref() {
            Some(region) => self.grant.validate_for_region(region)?,
            None => self.grant.validate_for_partition("aws")?,
        }
        let endpoint = resolve_sts_endpoint(
            ctx,
            self.sts_endpoint.as_deref(),
            self.region.as_deref(),
            self.use_regional_sts_endpoint,
        )
        .await?;
        let operation =
            AssumeRoleOperation::with_endpoint(endpoint, &self.grant, self.duration_seconds)?;
        operation.execute(ctx, &self.sts_signer).await.map(Some)
    }
}
