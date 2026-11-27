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
use std::fmt;

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use super::assume_role_with_web_identity::WEB_IDENTITY_TOKEN_FILE;
use crate::assume_role::{AssumeRoleOperation, regional_sts_endpoint};
use crate::signing::{SigV4SigningOptions, sign_request_parts};
use crate::{
    AssumeRoleGrant, AssumeRoleWithWebIdentityCredentialProvider, Credential,
    ECSCredentialProvider, IMDSv2CredentialProvider, ProcessCredentialProvider, Profile,
    ProfileCredentialProvider, SSOCredentialProvider, SharedConfig,
};

const AWS_ACCESS_KEY_ID: &str = "aws_access_key_id";
const AWS_CREDENTIAL_SOURCE: &str = "credential_source";
const AWS_ROLE_ARN: &str = "role_arn";
const AWS_ROLE_SESSION_NAME: &str = "role_session_name";
const AWS_SECRET_ACCESS_KEY: &str = "aws_secret_access_key";
const AWS_SOURCE_PROFILE: &str = "source_profile";
const AWS_EXTERNAL_ID: &str = "external_id";
const AWS_DURATION_SECONDS: &str = "duration_seconds";
const ENVIRONMENT_SOURCE: &str = "Environment";
const DEFAULT_ROLE_SESSION_NAME: &str = "reqsign";

/// Resolves role profiles with the configured slots from the default provider.
pub(crate) struct AssumeRoleChainCredentialProvider {
    profile: ProfileCredentialProvider,
    sso: Option<SSOCredentialProvider>,
    web_identity: Option<AssumeRoleWithWebIdentityCredentialProvider>,
    process: Option<ProcessCredentialProvider>,
    ecs: Option<ECSCredentialProvider>,
    imds: Option<IMDSv2CredentialProvider>,
}

impl fmt::Debug for AssumeRoleChainCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssumeRoleChainCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl AssumeRoleChainCredentialProvider {
    pub(crate) fn new(
        profile: ProfileCredentialProvider,
        sso: Option<SSOCredentialProvider>,
        web_identity: Option<AssumeRoleWithWebIdentityCredentialProvider>,
        process: Option<ProcessCredentialProvider>,
        ecs: Option<ECSCredentialProvider>,
        imds: Option<IMDSv2CredentialProvider>,
    ) -> Self {
        Self {
            profile,
            sso,
            web_identity,
            process,
            ecs,
            imds,
        }
    }

    async fn profile_source_credential(
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

        if profile.get("credential_process").is_some() {
            let Some(process) = &self.process else {
                return Err(Error::config_invalid(format!(
                    "AWS role profile source '{}' requires credential_process, but the process provider is disabled",
                    profile.name()
                )));
            };
            return process
                .provide_credential_for_profile(ctx, shared, profile.name())
                .await;
        }

        Err(Error::config_invalid(format!(
            "AWS role profile source '{}' does not provide static credentials, SSO configuration, or credential_process",
            profile.name()
        )))
    }

    async fn named_source_credential(
        &self,
        ctx: &Context,
        profile: &Profile,
        source: &str,
        env_enabled: bool,
        environment: Option<&Credential>,
    ) -> Result<Credential> {
        match source {
            ENVIRONMENT_SOURCE if !env_enabled => Err(disabled_source(profile, source, "env")),
            ENVIRONMENT_SOURCE => environment
                .cloned()
                .ok_or_else(|| missing_source(profile, source)),
            "Ec2InstanceMetadata" => {
                let imds = self
                    .imds
                    .as_ref()
                    .ok_or_else(|| disabled_source(profile, source, "imds"))?;
                imds.provide_credential(ctx)
                    .await?
                    .ok_or_else(|| missing_source(profile, source))
            }
            "EcsContainer" => {
                let ecs = self
                    .ecs
                    .as_ref()
                    .ok_or_else(|| disabled_source(profile, source, "ecs"))?;
                ecs.provide_credential(ctx)
                    .await?
                    .ok_or_else(|| missing_source(profile, source))
            }
            _ => Err(Error::config_invalid(format!(
                "AWS role profile '{}' has an unsupported credential_source",
                profile.name()
            ))),
        }
    }

    pub(super) async fn provide_credential(
        &self,
        ctx: &Context,
        env_enabled: bool,
        environment: Option<&Credential>,
    ) -> Result<Option<Credential>> {
        // Ambient profile selection keeps the ordinary environment-first path.
        if environment.is_some() && !self.profile.has_explicit_profile() {
            return Ok(None);
        }

        let shared = self.profile.shared_config();
        let Ok(selected) = shared.load(ctx).await else {
            // Until a role profile is identified, shared config does not own
            // credential selection. Keep the ordinary discovery behavior.
            return Ok(None);
        };
        if selected.get(AWS_ROLE_ARN).is_none() {
            return Ok(None);
        }

        if selected.get(WEB_IDENTITY_TOKEN_FILE).is_some()
            && selected.get(AWS_SOURCE_PROFILE).is_none()
            && selected.get(AWS_CREDENTIAL_SOURCE).is_none()
        {
            if environment.is_some() {
                return Ok(None);
            }
            let web_identity = self
                .web_identity
                .as_ref()
                .ok_or_else(|| disabled_source(&selected, "web identity", "web_identity"))?;
            let credential = web_identity
                .provide_credential_with_config(ctx, &shared)
                .await?
                .ok_or_else(|| missing_source(&selected, "web identity"))?;
            return Ok(Some(credential));
        }

        let (roles, leaf) = match load_role_path(ctx, &shared, selected).await {
            Ok(path) => path,
            // Traversal ends at a declared credential_source. An error here
            // means no such source was reached, so environment still wins.
            Err(_) if environment.is_some() => return Ok(None),
            Err(error) => return Err(error),
        };
        let credential_source = leaf
            .get(AWS_CREDENTIAL_SOURCE)
            .filter(|_| leaf.get(AWS_ROLE_ARN).is_some());
        if environment.is_some() && credential_source != Some(ENVIRONMENT_SOURCE) {
            return Ok(None);
        }

        let selected = roles.first().unwrap_or(&leaf);
        let region = selected.region().ok_or_else(|| {
            Error::config_invalid(format!(
                "AWS role profile '{}' requires a region for STS",
                selected.name()
            ))
        })?;
        let mut operations = Vec::new();
        for role in roles.iter().chain(std::iter::once(&leaf)) {
            let Some(role_arn) = role.get(AWS_ROLE_ARN) else {
                break;
            };
            match (
                role.get(AWS_SOURCE_PROFILE),
                role.get(AWS_CREDENTIAL_SOURCE),
            ) {
                (Some(_), Some(_)) => {
                    return Err(Error::config_invalid(format!(
                        "AWS role profile '{}' cannot set both source_profile and credential_source",
                        role.name()
                    )));
                }
                (None, None) => {
                    return Err(Error::config_invalid(format!(
                        "AWS role profile '{}' requires source_profile or credential_source",
                        role.name()
                    )));
                }
                _ => {}
            }

            let grant = role_grant(role, role_arn);
            let endpoint = regional_sts_endpoint(region, &grant)?;
            let operation = AssumeRoleOperation::new(endpoint, &grant, role_duration(role)?)?;
            operations.push(operation);
        }

        let crypto = ctx.crypto_provider()?;
        let mut credential = match credential_source {
            Some(source) => {
                self.named_source_credential(ctx, &leaf, source, env_enabled, environment)
                    .await?
            }
            None => self.profile_source_credential(ctx, &shared, &leaf).await?,
        };
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
                    region,
                    percent_encoding_mode: crate::PercentEncodingMode::Single,
                    uses_s3_express_session_token: false,
                },
            )?;
            credential = operation
                .send(ctx, http::Request::from_parts(parts, body))
                .await?;
        }
        Ok(Some(credential))
    }
}

async fn load_role_path(
    ctx: &Context,
    shared: &SharedConfig,
    mut leaf: Profile,
) -> Result<(Vec<Profile>, Profile)> {
    let mut roles = Vec::new();
    let mut seen = HashSet::from([leaf.name().to_owned()]);
    while leaf.get(AWS_ROLE_ARN).is_some() && leaf.get(AWS_CREDENTIAL_SOURCE).is_none() {
        let Some(source_profile) = leaf.get(AWS_SOURCE_PROFILE) else {
            break;
        };
        if !seen.insert(source_profile.to_owned()) {
            return Err(Error::config_invalid(format!(
                "AWS profile role chain contains a cycle at '{source_profile}'"
            )));
        }
        let next = shared.load_profile(ctx, source_profile).await?;
        if next.is_empty() {
            return Err(Error::config_invalid(format!(
                "AWS profile role chain references missing source profile '{source_profile}'"
            )));
        }
        roles.push(leaf);
        leaf = next;
    }
    Ok((roles, leaf))
}

fn disabled_source(profile: &Profile, source: &str, slot: &str) -> Error {
    Error::config_invalid(format!(
        "AWS role profile '{}' requires {source}, but the {slot} provider is disabled",
        profile.name()
    ))
}

fn missing_source(profile: &Profile, source: &str) -> Error {
    Error::config_invalid(format!(
        "AWS role profile '{}' requires {source} credentials, but none were found",
        profile.name()
    ))
}

fn role_grant(profile: &Profile, role_arn: &str) -> AssumeRoleGrant {
    let role_session_name = profile
        .get(AWS_ROLE_SESSION_NAME)
        .unwrap_or(DEFAULT_ROLE_SESSION_NAME);
    let mut grant = AssumeRoleGrant::new(role_arn.to_owned(), role_session_name);
    if let Some(id) = profile.get(AWS_EXTERNAL_ID) {
        grant = grant.with_external_id(id.to_owned());
    }
    grant
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
