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

use crate::IMDSv2RegionProvider;
use ini::{Ini, ParseOption};
use reqsign_core::{Context, Error, Result};
use std::collections::HashMap;
use std::fmt;

/// Loads AWS shared configuration without acquiring credentials or making HTTP requests.
///
/// Selection precedence is explicit profile/path, the corresponding `AWS_PROFILE`,
/// `AWS_CONFIG_FILE`, or `AWS_SHARED_CREDENTIALS_FILE` environment variable, then
/// `default`, `~/.aws/config`, or `~/.aws/credentials`. Named config sections use
/// `[profile name]`; credentials sections use `[name]`. A named profile does not
/// inherit `[default]`. Credentials-file properties override config-file properties
/// individually, while properties present in only one file are retained.
///
/// Unreadable files (including missing files) and unavailable home directories are
/// treated as absent, as in the credential providers. Malformed readable files are
/// errors. No credential processes, SSO sessions, or role chains are executed.
#[derive(Clone, Debug, Default)]
pub struct SharedConfig {
    profile: Option<String>,
    config_file: Option<String>,
    credentials_file: Option<String>,
    region: Option<String>,
    endpoint_url: Option<String>,
    imds: Option<IMDSv2RegionProvider>,
}

impl SharedConfig {
    /// Create a loader. Metadata discovery is disabled by default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select a profile, overriding `AWS_PROFILE`.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Override `AWS_CONFIG_FILE` and the default config path.
    pub fn with_config_file(mut self, path: impl Into<String>) -> Self {
        self.config_file = Some(path.into());
        self
    }

    /// Override `AWS_SHARED_CREDENTIALS_FILE` and the default credentials path.
    pub fn with_credentials_file(mut self, path: impl Into<String>) -> Self {
        self.credentials_file = Some(path.into());
        self
    }

    /// Override region environment variables and profile settings.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Override `AWS_ENDPOINT_URL` and the profile's global `endpoint_url`.
    pub fn with_endpoint_url(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_url = Some(endpoint.into());
        self
    }

    /// Enable metadata fallback for [`Self::resolve_region`] only.
    pub fn with_imds(mut self, provider: IMDSv2RegionProvider) -> Self {
        self.imds = Some(provider);
        self
    }

    pub(crate) fn profile_name(&self, ctx: &Context) -> String {
        self.profile
            .clone()
            .or_else(|| ctx.env_var("AWS_PROFILE"))
            .unwrap_or_else(|| "default".into())
    }

    fn configured_region(&self, ctx: &Context) -> Option<String> {
        self.region
            .clone()
            .or_else(|| ctx.env_var("AWS_REGION"))
            .or_else(|| ctx.env_var("AWS_DEFAULT_REGION"))
    }

    pub(crate) async fn load_config_file(&self, ctx: &Context) -> Result<Ini> {
        read_ini(
            ctx,
            self.config_file.as_deref(),
            "AWS_CONFIG_FILE",
            "~/.aws/config",
        )
        .await
    }

    pub(crate) async fn load_credentials_file(&self, ctx: &Context) -> Result<Ini> {
        read_ini(
            ctx,
            self.credentials_file.as_deref(),
            "AWS_SHARED_CREDENTIALS_FILE",
            "~/.aws/credentials",
        )
        .await
    }

    /// Read and merge the selected profile. This never contacts IMDS, even when enabled.
    ///
    /// Region precedence: explicit override, `AWS_REGION`, `AWS_DEFAULT_REGION`,
    /// merged profile. Endpoint precedence: explicit override, `AWS_ENDPOINT_URL`,
    /// merged profile. Missing values remain `None`; no application defaults are added.
    /// Service-specific endpoint settings and endpoint rules are not resolved.
    pub async fn load(&self, ctx: &Context) -> Result<Profile> {
        let name = self.profile_name(ctx);
        let config = self.load_config_file(ctx).await?;
        let credentials = self.load_credentials_file(ctx).await?;
        let mut properties = HashMap::new();
        for section in [
            config.section(Some(config_section(&name))),
            credentials.section(Some(&name)),
        ]
        .into_iter()
        .flatten()
        {
            properties.extend(section.iter().map(|(k, v)| (k.to_owned(), v.to_owned())));
        }
        let region = self
            .configured_region(ctx)
            .or_else(|| properties.get("region").cloned());
        let endpoint_url = self
            .endpoint_url
            .clone()
            .or_else(|| ctx.env_var("AWS_ENDPOINT_URL"))
            .or_else(|| properties.get("endpoint_url").cloned());
        Ok(Profile {
            name,
            properties,
            region,
            endpoint_url,
        })
    }

    /// Resolve region independently of credentials, optionally falling back to IMDSv2.
    ///
    /// Explicit/environment regions skip file reads. A profile region skips metadata.
    /// Disabled discovery or an absent region returns `None`; configuration, metadata,
    /// and timeout errors are returned to the caller without an application fallback.
    pub async fn resolve_region(&self, ctx: &Context) -> Result<Option<String>> {
        if let Some(region) = self.configured_region(ctx) {
            return Ok(Some(region));
        }
        if let Some(region) = self.load(ctx).await?.region {
            return Ok(Some(region));
        }
        match &self.imds {
            Some(imds) => imds.resolve_region(ctx).await,
            None => Ok(None),
        }
    }
}

/// A selected AWS profile with resolved region and global endpoint settings.
///
/// Raw properties may contain secrets. Debug output omits all property values.
#[derive(Clone)]
pub struct Profile {
    name: String,
    properties: HashMap<String, String>,
    region: Option<String>,
    endpoint_url: Option<String>,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Profile {
    /// Selected profile name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Merged file property, before explicit or environment overrides.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(String::as_str)
    }
    /// Region after explicit and environment overrides, without metadata discovery.
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }
    /// Global endpoint after explicit and environment overrides. No service rules are applied.
    pub fn endpoint_url(&self) -> Option<&str> {
        self.endpoint_url.as_deref()
    }
}

pub(crate) fn config_section(profile: &str) -> String {
    if profile == "default" {
        "default".into()
    } else {
        format!("profile {profile}")
    }
}

async fn read_ini(ctx: &Context, explicit: Option<&str>, env: &str, default: &str) -> Result<Ini> {
    let path = explicit
        .map(str::to_owned)
        .or_else(|| ctx.env_var(env))
        .unwrap_or_else(|| default.into());
    let Some(path) = ctx.expand_home_dir(&path) else {
        return Ok(Ini::new());
    };
    let Ok(content) = ctx.file_read(&path).await else {
        return Ok(Ini::new());
    };
    let content = std::str::from_utf8(&content)
        .map_err(|_| Error::config_invalid("AWS shared configuration is not UTF-8"))?;
    // AWS values, especially credential_process commands, contain literal quotes and backslashes.
    // Keep nested service settings distinct from top-level profile properties.
    Ini::load_from_str_opt(
        content,
        ParseOption {
            enabled_quote: false,
            enabled_escape: false,
            enabled_indented_mutiline_value: true,
            ..Default::default()
        },
    )
    .map_err(|_| Error::config_invalid("failed to parse AWS shared configuration"))
}
