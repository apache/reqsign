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

use std::collections::HashSet;

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::assume_role::{AssumeRoleOperation, regional_sts_endpoint};
use crate::signing::{SigV4SigningOptions, sign_request_parts};
use crate::{
    AssumeRoleGrant, Credential, Profile, ProfileCredentialProvider, SSOCredentialProvider,
    SharedConfig,
};

const AWS_ACCESS_KEY_ID: &str = "aws_access_key_id";
const AWS_CREDENTIAL_SOURCE: &str = "credential_source";
const AWS_ROLE_ARN: &str = "role_arn";
const AWS_ROLE_SESSION_NAME: &str = "role_session_name";
const AWS_SECRET_ACCESS_KEY: &str = "aws_secret_access_key";
const AWS_SOURCE_PROFILE: &str = "source_profile";
const AWS_EXTERNAL_ID: &str = "external_id";
const AWS_DURATION_SECONDS: &str = "duration_seconds";
const DEFAULT_ROLE_SESSION_NAME: &str = "reqsign";

/// Resolves the selected AWS shared profile as an assume-role credential graph.
///
/// The graph is read from `source_profile` references until a profile with
/// static credentials or SSO configuration is reached. Each role transition is
/// returned by an STS `AssumeRole` call signed with the previous hop's
/// credential.
///
/// The default provider runs this provider after the environment and static
/// profile slots and before the independent SSO slot. Disabling the profile
/// slot removes the graph, while disabling the SSO slot prevents a graph from
/// using an SSO source.
#[derive(Debug, Clone)]
pub(crate) struct AssumeRoleChainCredentialProvider {
    profile: ProfileCredentialProvider,
    sso: Option<SSOCredentialProvider>,
}

impl AssumeRoleChainCredentialProvider {
    pub(crate) fn new(
        profile: ProfileCredentialProvider,
        sso: Option<SSOCredentialProvider>,
    ) -> Self {
        Self { profile, sso }
    }

    async fn source_credential(
        &self,
        ctx: &Context,
        shared: &SharedConfig,
        profile: &Profile,
    ) -> Result<Credential> {
        if profile.get(AWS_ACCESS_KEY_ID).is_some() && profile.get(AWS_SECRET_ACCESS_KEY).is_some()
        {
            return self
                .profile
                .clone()
                .with_profile(profile.name())
                .provide_credential(ctx)
                .await?
                .ok_or_else(|| {
                    Error::config_invalid(format!(
                        "AWS role profile source '{}' has incomplete static credentials",
                        profile.name()
                    ))
                });
        }

        if has_sso_configuration(profile) {
            let Some(sso) = &self.sso else {
                return Err(Error::config_invalid(format!(
                    "AWS role profile source '{}' requires SSO, but the SSO provider is disabled",
                    profile.name()
                )));
            };
            return sso
                .clone()
                .with_shared_config(shared.clone())
                .provide_credential_for_profile(ctx, profile.name())
                .await?
                .ok_or_else(|| {
                    Error::config_invalid(format!(
                        "AWS role profile source '{}' does not provide SSO credentials",
                        profile.name()
                    ))
                });
        }

        Err(Error::config_invalid(format!(
            "AWS role profile source '{}' does not provide static credentials or SSO configuration",
            profile.name()
        )))
    }
}

impl ProvideCredential for AssumeRoleChainCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let shared = self.profile.shared_config();
        let selected = match shared.load(ctx).await {
            Ok(selected) => selected,
            // The shared profile slot already permits a malformed profile to
            // fall through to later providers. Do not change that policy when
            // the selected profile cannot be read well enough to identify a
            // role graph.
            Err(_) => return Ok(None),
        };
        if selected.get(AWS_ROLE_ARN).is_none() {
            return Ok(None);
        }

        let region = selected.region().map(str::to_owned).ok_or_else(|| {
            Error::config_invalid(format!(
                "AWS role profile '{}' requires a region for STS",
                selected.name()
            ))
        })?;
        let mut operations = Vec::new();
        let mut seen = HashSet::new();
        let mut current = selected;
        let mut current_name = current.name().to_owned();

        loop {
            if !seen.insert(current_name.clone()) {
                return Err(Error::config_invalid(format!(
                    "AWS profile role chain contains a cycle at '{current_name}'"
                )));
            }

            let Some(role_arn) = current.get(AWS_ROLE_ARN) else {
                break;
            };
            let source_profile = current.get(AWS_SOURCE_PROFILE);
            let credential_source = current.get(AWS_CREDENTIAL_SOURCE);
            if source_profile.is_some() && credential_source.is_some() {
                return Err(Error::config_invalid(format!(
                    "AWS role profile '{current_name}' cannot set both source_profile and credential_source"
                )));
            }
            if credential_source.is_some() {
                return Err(Error::config_invalid(format!(
                    "AWS role profile '{current_name}' uses credential_source, which is not supported; set source_profile"
                )));
            }
            let Some(source_profile) = source_profile else {
                return Err(Error::config_invalid(format!(
                    "AWS role profile '{current_name}' requires source_profile"
                )));
            };

            let grant = role_grant(&current, role_arn)?;
            let endpoint = regional_sts_endpoint(&region, &grant)?;
            let operation = AssumeRoleOperation::new(endpoint, &grant, role_duration(&current)?)?;
            operations.push(operation);

            current_name = source_profile.to_owned();
            current = shared.load_profile(ctx, &current_name).await?;
            if current.is_empty() {
                return Err(Error::config_invalid(format!(
                    "AWS profile role chain references missing source profile '{current_name}'"
                )));
            }
        }

        let crypto = ctx.crypto_provider()?;
        let mut credential = self.source_credential(ctx, &shared, &current).await?;
        for operation in operations.into_iter().rev() {
            let request = operation.build_request(crypto)?;
            let (mut parts, body) = request.into_parts();
            sign_request_parts(
                crypto,
                &mut parts,
                &credential,
                None,
                Timestamp::now(),
                SigV4SigningOptions {
                    service: "sts",
                    region: &region,
                    percent_encoding_mode: crate::PercentEncodingMode::Single,
                    uses_s3_express_session_token: false,
                    excluded_headers: &[],
                },
            )?;
            credential = operation
                .send(ctx, http::Request::from_parts(parts, body))
                .await?;
        }
        Ok(Some(credential))
    }
}

fn role_grant(profile: &Profile, role_arn: &str) -> Result<AssumeRoleGrant> {
    let role_session_name = profile
        .get(AWS_ROLE_SESSION_NAME)
        .unwrap_or(DEFAULT_ROLE_SESSION_NAME);
    let mut grant = AssumeRoleGrant::new(role_arn.to_owned(), role_session_name);
    if let Some(id) = profile.get(AWS_EXTERNAL_ID) {
        grant = grant.with_external_id(id.to_owned());
    }
    Ok(grant)
}

fn role_duration(profile: &Profile) -> Result<Option<u32>> {
    let Some(value) = profile.get(AWS_DURATION_SECONDS) else {
        return Ok(None);
    };
    let seconds = value.parse::<u32>().map_err(|_| {
        Error::config_invalid(format!(
            "AWS role profile '{}' has an invalid duration_seconds",
            profile.name()
        ))
    })?;
    if !(900..=43_200).contains(&seconds) {
        return Err(Error::config_invalid(format!(
            "AWS role profile '{}' duration_seconds must be between 900 and 43200",
            profile.name()
        )));
    }
    Ok(Some(seconds))
}

fn has_sso_configuration(profile: &Profile) -> bool {
    [
        "sso_session",
        "sso_start_url",
        "sso_region",
        "sso_account_id",
        "sso_role_name",
    ]
    .iter()
    .any(|key| profile.get(key).is_some())
}

#[cfg(test)]
mod tests;
