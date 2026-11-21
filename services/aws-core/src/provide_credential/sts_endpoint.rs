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

//! STS endpoint selection for the AssumeRole and AssumeRoleWithWebIdentity providers.
//!
//! Precedence follows the AWS SDKs' endpoint settings
//! (<https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html>):
//!
//! 1. the endpoint configured explicitly on the provider;
//! 2. `AWS_ENDPOINT_URL_STS`;
//! 3. `AWS_ENDPOINT_URL`;
//! 4. `endpoint_url` under `sts` in the `[services ...]` section the selected profile names;
//! 5. the selected profile's `endpoint_url`;
//! 6. the regional or partition default (`sts.amazonaws.com`, `sts.<region>.<suffix>`, ...).
//!
//! `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS`, or else the profile's
//! `ignore_configured_endpoint_urls`, set to `true` skips steps 2 to 5. The explicit
//! endpoint still applies.

use std::fmt;

use reqsign_core::{Context, Error, Result};

use crate::SharedConfig;
use crate::provide_credential::utils::sts_endpoint;

/// The service key of STS in a `[services ...]` section and in `AWS_ENDPOINT_URL_<SERVICE>`.
const STS_SERVICE_KEY: &str = "sts";

/// Where an STS request is sent: a scheme and an authority, with no path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StsEndpoint {
    base: String,
}

impl StsEndpoint {
    /// The standard HTTPS endpoint for a host name returned by [`sts_endpoint`].
    pub(crate) fn https(authority: &str) -> Self {
        Self {
            base: format!("https://{authority}"),
        }
    }

    /// Parse a configured endpoint URL.
    ///
    /// The URL must use `http` or `https`, name a host (a port is allowed), and carry no
    /// user information, path, query, or fragment. A single trailing `/` is accepted.
    pub(crate) fn parse(url: &str, source: &str) -> Result<Self> {
        let invalid = || {
            Error::config_invalid("AWS STS endpoint URL is invalid")
                .with_context(format!("source: {source}"))
                .with_context("hint: use a URL such as https://sts.example.com or https://sts.example.com:8443")
        };
        let uri: http::Uri = url.trim().parse().map_err(|_| invalid())?;
        let scheme = uri.scheme_str().ok_or_else(invalid)?;
        if scheme != "https" && scheme != "http" {
            return Err(invalid());
        }
        let authority = uri.authority().ok_or_else(invalid)?;
        if authority.host().is_empty() || authority.as_str().contains('@') {
            return Err(invalid());
        }
        if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
            return Err(invalid());
        }
        Ok(Self {
            base: format!("{scheme}://{}", authority.as_str()),
        })
    }

    /// The URL an STS request is sent to.
    pub(crate) fn url(&self) -> String {
        format!("{}/", self.base)
    }
}

impl fmt::Display for StsEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base)
    }
}

/// Resolve the STS endpoint for one request. See the module documentation for the precedence.
///
/// Configuration that is not needed is not read: an explicit endpoint reads nothing, and
/// `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` skips the shared config file.
pub(crate) async fn resolve_sts_endpoint(
    ctx: &Context,
    explicit: Option<&str>,
    region: Option<&str>,
    use_regional: bool,
) -> Result<StsEndpoint> {
    if let Some(url) = explicit {
        return StsEndpoint::parse(url, "explicit provider endpoint");
    }
    if let Some(url) = configured_sts_endpoint(ctx).await? {
        return Ok(url);
    }
    sts_endpoint(region, use_regional).map(|authority| StsEndpoint::https(&authority))
}

async fn configured_sts_endpoint(ctx: &Context) -> Result<Option<StsEndpoint>> {
    let env_ignore = parse_ignore(
        ctx.env_var("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"),
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
    )?;
    if env_ignore == Some(true) {
        return Ok(None);
    }
    let profile = SharedConfig::new()
        .load_endpoint_settings(ctx, STS_SERVICE_KEY)
        .await?;
    let ignore = match env_ignore {
        Some(ignore) => ignore,
        None => parse_ignore(
            profile.ignore_configured_endpoint_urls.clone(),
            "profile ignore_configured_endpoint_urls",
        )?
        .unwrap_or(false),
    };
    if ignore {
        return Ok(None);
    }
    let candidates = [
        (ctx.env_var("AWS_ENDPOINT_URL_STS"), "AWS_ENDPOINT_URL_STS"),
        (ctx.env_var("AWS_ENDPOINT_URL"), "AWS_ENDPOINT_URL"),
        (
            profile.service_endpoint_url,
            "profile services sts endpoint_url",
        ),
        (profile.endpoint_url, "profile endpoint_url"),
    ];
    for (value, source) in candidates {
        if let Some(url) = value.filter(|url| !url.trim().is_empty()) {
            return StsEndpoint::parse(&url, source).map(Some);
        }
    }
    Ok(None)
}

/// Parse an ignore setting. Unset or empty is `None`; other values must be `true` or `false`,
/// in any case.
fn parse_ignore(value: Option<String>, source: &str) -> Result<Option<bool>> {
    let Some(value) = value.map(|value| value.trim().to_ascii_lowercase()) else {
        return Ok(None);
    };
    match value.as_str() {
        "" => Ok(None),
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(Error::config_invalid(
            "ignore configured endpoint URLs setting must be true or false",
        )
        .with_context(format!("source: {source}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use reqsign_core::{ErrorKind, FileRead, StaticEnv};

    use super::*;

    const CONFIG_PATH: &str = "/home/test/.aws/config";

    /// Serves one shared config file and records every path read.
    #[derive(Clone, Debug, Default)]
    struct ConfigFile {
        content: Option<String>,
        reads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl ConfigFile {
        fn new(content: &str) -> Self {
            Self {
                content: Some(content.to_owned()),
                ..Self::default()
            }
        }

        fn reads(&self) -> Vec<String> {
            self.reads.lock().unwrap().clone()
        }
    }

    impl FileRead for ConfigFile {
        async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
            self.reads.lock().unwrap().push(path.to_owned());
            match (&self.content, path) {
                (Some(content), CONFIG_PATH) => Ok(content.clone().into_bytes()),
                _ => Err(Error::config_invalid("file not found")),
            }
        }
    }

    fn context(envs: &[(&str, &str)], config: ConfigFile) -> Context {
        crate::test_context()
            .with_file_read(config)
            .with_env(StaticEnv {
                home_dir: Some(PathBuf::from("/home/test")),
                envs: envs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect::<HashMap<_, _>>(),
            })
    }

    const FULL_PROFILE: &str = "\
[default]
endpoint_url = https://profile-global.example.com
services = local

[services local]
sts =
  endpoint_url = https://profile-sts.example.com
";

    const ALL_ENVS: [(&str, &str); 2] = [
        ("AWS_ENDPOINT_URL_STS", "https://env-sts.example.com"),
        ("AWS_ENDPOINT_URL", "https://env-global.example.com"),
    ];

    async fn resolve(ctx: &Context, explicit: Option<&str>) -> String {
        resolve_sts_endpoint(ctx, explicit, None, false)
            .await
            .expect("endpoint must resolve")
            .url()
    }

    #[tokio::test]
    async fn defaults_are_unchanged_without_endpoint_settings() {
        let ctx = context(&[], ConfigFile::default());
        assert_eq!(resolve(&ctx, None).await, "https://sts.amazonaws.com/");
        let regional = resolve_sts_endpoint(&ctx, None, Some("eu-west-1"), true)
            .await
            .expect("regional endpoint must resolve");
        assert_eq!(regional.url(), "https://sts.eu-west-1.amazonaws.com/");
        let china = resolve_sts_endpoint(&ctx, None, Some("cn-north-1"), false)
            .await
            .expect("China endpoint must resolve");
        assert_eq!(china.url(), "https://sts.amazonaws.com.cn/");

        // A profile without endpoint settings changes nothing either.
        let ctx = context(&[], ConfigFile::new("[default]\nregion = us-west-2\n"));
        assert_eq!(resolve(&ctx, None).await, "https://sts.amazonaws.com/");
    }

    #[tokio::test]
    async fn precedence_follows_the_aws_sdk_endpoint_settings() {
        let config = ConfigFile::new(FULL_PROFILE);
        let ctx = context(&ALL_ENVS, config.clone());
        assert_eq!(
            resolve(&ctx, Some("https://explicit.example.com")).await,
            "https://explicit.example.com/"
        );
        assert!(
            config.reads().is_empty(),
            "an explicit endpoint must not read the shared config"
        );
        assert_eq!(resolve(&ctx, None).await, "https://env-sts.example.com/");

        let ctx = context(&ALL_ENVS[1..], ConfigFile::new(FULL_PROFILE));
        assert_eq!(resolve(&ctx, None).await, "https://env-global.example.com/");

        let ctx = context(&[], ConfigFile::new(FULL_PROFILE));
        assert_eq!(
            resolve(&ctx, None).await,
            "https://profile-sts.example.com/"
        );

        let ctx = context(
            &[],
            ConfigFile::new("[default]\nendpoint_url = https://profile-global.example.com\n"),
        );
        assert_eq!(
            resolve(&ctx, None).await,
            "https://profile-global.example.com/"
        );
    }

    #[tokio::test]
    async fn the_selected_profile_and_its_services_section_are_used() {
        let config = "\
[default]
endpoint_url = https://default.example.com

[profile dev]
services = dev-services

[services dev-services]
s3 =
  endpoint_url = https://s3-only.example.com
sts =
  region = us-west-2
  endpoint_url = https://dev-sts.example.com
";
        let ctx = context(&[("AWS_PROFILE", "dev")], ConfigFile::new(config));
        assert_eq!(resolve(&ctx, None).await, "https://dev-sts.example.com/");

        // Another service's endpoint never applies to STS.
        let config = "\
[default]
services = s3-only

[services s3-only]
s3 =
  endpoint_url = https://s3-only.example.com
";
        let ctx = context(&[], ConfigFile::new(config));
        assert_eq!(resolve(&ctx, None).await, "https://sts.amazonaws.com/");
    }

    #[tokio::test]
    async fn ignore_settings_skip_environment_and_profile_but_not_explicit() {
        let mut envs = ALL_ENVS.to_vec();
        envs.push(("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "TRUE"));
        let config = ConfigFile::new(FULL_PROFILE);
        let ctx = context(&envs, config.clone());
        assert_eq!(resolve(&ctx, None).await, "https://sts.amazonaws.com/");
        assert!(
            config.reads().is_empty(),
            "ignoring by environment must not read the shared config"
        );
        assert_eq!(
            resolve(&ctx, Some("https://explicit.example.com")).await,
            "https://explicit.example.com/"
        );

        let ignored_profile = format!(
            "{FULL_PROFILE}\n[profile ignoring]\nignore_configured_endpoint_urls = true\nendpoint_url = https://x.example.com\n"
        );
        let ctx = context(
            &[("AWS_PROFILE", "ignoring"), ALL_ENVS[0], ALL_ENVS[1]],
            ConfigFile::new(&ignored_profile),
        );
        assert_eq!(resolve(&ctx, None).await, "https://sts.amazonaws.com/");
        assert_eq!(
            resolve(&ctx, Some("http://explicit.example.com:8080")).await,
            "http://explicit.example.com:8080/"
        );

        // The environment setting wins over the profile's, in both directions.
        let ctx = context(
            &[
                ("AWS_PROFILE", "ignoring"),
                ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false"),
                ALL_ENVS[0],
            ],
            ConfigFile::new(&ignored_profile),
        );
        assert_eq!(resolve(&ctx, None).await, "https://env-sts.example.com/");
    }

    #[tokio::test]
    async fn http_and_ports_are_allowed_when_configured() {
        let ctx = context(
            &[("AWS_ENDPOINT_URL_STS", "http://sts.internal:8333")],
            ConfigFile::default(),
        );
        assert_eq!(resolve(&ctx, None).await, "http://sts.internal:8333/");

        let ctx = context(&[], ConfigFile::default());
        for (input, expected) in [
            ("https://sts.example.com/", "https://sts.example.com/"),
            (
                "https://sts.example.com:8443",
                "https://sts.example.com:8443/",
            ),
            ("http://127.0.0.1:9000", "http://127.0.0.1:9000/"),
            ("http://[::1]:9000", "http://[::1]:9000/"),
        ] {
            assert_eq!(resolve(&ctx, Some(input)).await, expected, "{input}");
        }
    }

    #[tokio::test]
    async fn invalid_endpoint_settings_are_rejected() {
        let ctx = context(&[], ConfigFile::default());
        for input in [
            "sts.example.com",
            "ftp://sts.example.com",
            "https://user:pass@sts.example.com",
            "https://sts.example.com/prefix",
            "https://sts.example.com/?a=b",
            "https://",
        ] {
            let err = resolve_sts_endpoint(&ctx, Some(input), None, false)
                .await
                .expect_err(input);
            assert_eq!(err.kind(), ErrorKind::ConfigInvalid, "{input}");
            assert!(
                !format!("{err:?}").contains("pass"),
                "errors must not echo the configured URL: {input}"
            );
        }

        let ctx = context(
            &[("AWS_ENDPOINT_URL_STS", "not a url")],
            ConfigFile::default(),
        );
        let err = resolve_sts_endpoint(&ctx, None, None, false)
            .await
            .expect_err("an invalid environment endpoint must not fall through");
        assert!(format!("{err:?}").contains("AWS_ENDPOINT_URL_STS"));

        let ctx = context(
            &[("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "yes")],
            ConfigFile::default(),
        );
        let err = resolve_sts_endpoint(&ctx, None, None, false)
            .await
            .expect_err("an invalid ignore setting must be rejected");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    }
}
