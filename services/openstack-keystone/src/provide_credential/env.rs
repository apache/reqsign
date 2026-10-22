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

use log::debug;

use reqsign_core::{Context, ProvideCredential, Result};

use crate::credential::Credential;

use super::keystone::KeystoneCredentialProvider;

/// Environment variable names for OpenStack credentials.
///
/// Reqsign reads the names the OpenStack command line tools and SDKs use, so an
/// environment that already authenticates against Keystone works as is.
pub(crate) const OS_AUTH_URL: &str = "OS_AUTH_URL";
pub(crate) const OS_USERNAME: &str = "OS_USERNAME";
pub(crate) const OS_PASSWORD: &str = "OS_PASSWORD";
pub(crate) const OS_USER_DOMAIN_NAME: &str = "OS_USER_DOMAIN_NAME";
pub(crate) const OS_PROJECT_NAME: &str = "OS_PROJECT_NAME";
pub(crate) const OS_PROJECT_DOMAIN_NAME: &str = "OS_PROJECT_DOMAIN_NAME";

/// Credential provider that reads OpenStack credentials from environment variables
/// and authenticates via Keystone v3.
///
/// Required environment variables:
/// - `OS_AUTH_URL` — Keystone v3 identity URL (e.g. `https://keystone.example.com/v3`)
/// - `OS_USERNAME` — OpenStack username
/// - `OS_PASSWORD` — OpenStack password
///
/// Optional environment variables:
/// - `OS_USER_DOMAIN_NAME` — User domain name (defaults to "Default")
/// - `OS_PROJECT_NAME` — Project name for scoped tokens
/// - `OS_PROJECT_DOMAIN_NAME` — Project domain name (defaults to user domain)
#[derive(Debug, Default)]
pub struct EnvCredentialProvider;

impl EnvCredentialProvider {
    /// Create a new EnvCredentialProvider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let auth_url = match ctx.env_var(OS_AUTH_URL) {
            Some(v) if !v.is_empty() => v,
            _ => {
                debug!("{OS_AUTH_URL} not set, skipping env credential provider");
                return Ok(None);
            }
        };

        let username = match ctx.env_var(OS_USERNAME) {
            Some(v) if !v.is_empty() => v,
            _ => {
                debug!("{OS_USERNAME} not set, skipping env credential provider");
                return Ok(None);
            }
        };

        let password = match ctx.env_var(OS_PASSWORD) {
            Some(v) if !v.is_empty() => v,
            _ => {
                debug!("{OS_PASSWORD} not set, skipping env credential provider");
                return Ok(None);
            }
        };

        let domain_name = ctx
            .env_var(OS_USER_DOMAIN_NAME)
            .unwrap_or_else(|| "Default".to_string());

        let project_domain_name = ctx
            .env_var(OS_PROJECT_DOMAIN_NAME)
            .unwrap_or_else(|| domain_name.clone());

        debug!("loaded OpenStack credentials from environment for user: {username}");

        let mut provider = KeystoneCredentialProvider::new(&auth_url)
            .with_username(&username)
            .with_password(&password)
            .with_user_domain_name(&domain_name);

        if let Some(project_name) = ctx.env_var(OS_PROJECT_NAME) {
            if !project_name.is_empty() {
                provider = provider
                    .with_project_name(&project_name)
                    .with_project_domain_name(&project_domain_name);
            }
        }

        provider.provide_credential(ctx).await
    }
}
