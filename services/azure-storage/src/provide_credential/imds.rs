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
use bytes::Bytes;
use http::{HeaderValue, Request, Uri};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

const VM_IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const STORAGE_RESOURCE: &str = "https://storage.azure.com/";

/// Load a Microsoft Entra bearer token from an Azure managed identity endpoint.
///
/// Endpoint selection uses the first of [`Self::with_endpoint`], `AZBLOB_ENDPOINT`,
/// `AZURE_IMDS_ENDPOINT`, App Service / Functions / Container Apps (`IDENTITY_ENDPOINT`
/// and `IDENTITY_HEADER`), legacy App Service / Functions (`MSI_ENDPOINT` and
/// `MSI_SECRET`), and Azure VM IMDS. An incomplete pair for the selected platform
/// returns a configuration error before sending a request. Empty values in the
/// platform pairs are treated as unset.
///
/// Set `AZURE_OBJECT_ID`, `AZURE_CLIENT_ID`, or `AZURE_MSI_RESOURCE_ID`
/// (alias `AZURE_MSI_RES_ID`) to select a user-assigned identity, in that order.
/// The legacy protocol supports selection by client ID only.
///
/// The HTTP transport supplied in the [`Context`] controls redirect handling.
///
/// See the [App Service REST endpoint reference](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity#rest-endpoint-reference).
#[derive(Default, Clone)]
pub struct ImdsCredentialProvider {
    endpoint: Option<String>,
    resource: Option<String>,
}

impl fmt::Debug for ImdsCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImdsCredentialProvider")
            .finish_non_exhaustive()
    }
}

impl ImdsCredentialProvider {
    /// Create a managed identity credential provider for the Azure Storage resource.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use an explicit endpoint with the VM IMDS protocol.
    ///
    /// This takes precedence over endpoint discovery. Like the environment IMDS
    /// overrides, it uses `AZURE_MSI_SECRET` as `X-IDENTITY-HEADER` when set.
    /// The provider supplies the API version, resource, and identity query
    /// parameters.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set the resource URI sent in the token request.
    ///
    /// The URI is passed as the `resource` query value, including any trailing
    /// slash. The default is `https://storage.azure.com/`.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }
}

impl ProvideCredential for ImdsCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let resource = self.resource.as_deref().unwrap_or(STORAGE_RESOURCE);
        if resource.trim().is_empty() {
            return Err(Error::config_invalid(
                "Azure managed identity resource is empty",
            ));
        }

        let envs = ctx.env_vars();
        let endpoint = ManagedIdentityEndpoint::resolve(self.endpoint.as_deref(), &envs)?;
        let request = endpoint.build_request(resource, &envs)?;
        let response = ctx.http_send(request).await.map_err(|err| {
            // Transport errors can contain request or response data.
            Error::new(err.kind(), "failed to send Azure managed identity request")
                .set_retryable(err.is_retryable())
        })?;

        if !response.status().is_success() {
            return Err(
                Error::credential_invalid("Azure managed identity token request failed")
                    .with_context(format!("http_status: {}", response.status())),
            );
        }

        let response: AccessTokenResponse = serde_json::from_slice(response.body())
            .map_err(|_| Error::unexpected("failed to parse Azure managed identity response"))?;
        if response.access_token.is_empty() {
            return Err(Error::credential_invalid(
                "Azure managed identity access token is empty",
            ));
        }
        let expires_at = response.expires_on.timestamp(endpoint).ok_or_else(|| {
            Error::unexpected("invalid expires_on in Azure managed identity response")
        })?;

        Ok(Some(Credential::BearerToken {
            token: response.access_token,
            expires_in: Some(expires_at),
        }))
    }
}

#[derive(Clone, Copy)]
enum ManagedIdentityEndpoint<'a> {
    Imds {
        url: &'a str,
        secret: Option<&'a str>,
    },
    AppService {
        url: &'a str,
        secret: &'a str,
    },
    LegacyAppService {
        url: &'a str,
        secret: &'a str,
    },
}

impl<'a> ManagedIdentityEndpoint<'a> {
    fn resolve(override_url: Option<&'a str>, envs: &'a HashMap<String, String>) -> Result<Self> {
        let override_url = override_url.filter(|url| !url.is_empty()).or_else(|| {
            envs.get("AZBLOB_ENDPOINT")
                .or_else(|| envs.get("AZURE_IMDS_ENDPOINT"))
                .map(String::as_str)
                .filter(|url| !url.is_empty())
        });
        if let Some(url) = override_url {
            return Ok(Self::Imds {
                url,
                secret: env_value(envs, "AZURE_MSI_SECRET"),
            });
        }

        match (
            env_value(envs, "IDENTITY_ENDPOINT"),
            env_value(envs, "IDENTITY_HEADER"),
        ) {
            (Some(url), Some(secret)) => {
                if env_value(envs, "IDENTITY_SERVER_THUMBPRINT").is_some() {
                    return Err(Error::config_invalid(
                        "Azure Service Fabric managed identity is unsupported",
                    ));
                }
                return Ok(Self::AppService { url, secret });
            }
            (None, None) => {}
            _ => {
                return Err(Error::config_invalid(
                    "Azure managed identity requires both IDENTITY_ENDPOINT and IDENTITY_HEADER",
                ));
            }
        }

        match (
            env_value(envs, "MSI_ENDPOINT"),
            env_value(envs, "MSI_SECRET"),
        ) {
            (Some(url), Some(secret)) => Ok(Self::LegacyAppService { url, secret }),
            (None, None) => Ok(Self::Imds {
                url: VM_IMDS_ENDPOINT,
                secret: None,
            }),
            _ => Err(Error::config_invalid(
                "Azure managed identity requires both MSI_ENDPOINT and MSI_SECRET",
            )),
        }
    }

    fn build_request(
        self,
        resource: &str,
        envs: &HashMap<String, String>,
    ) -> Result<Request<Bytes>> {
        let (url, version, secret_header) = match self {
            Self::Imds { url, secret } => (
                url,
                "2018-02-01",
                secret.map(|value| ("x-identity-header", "AZURE_MSI_SECRET", value)),
            ),
            Self::AppService { url, secret } => (
                url,
                "2019-08-01",
                Some(("x-identity-header", "IDENTITY_HEADER", secret)),
            ),
            Self::LegacyAppService { url, secret } => {
                (url, "2017-09-01", Some(("secret", "MSI_SECRET", secret)))
            }
        };

        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("api-version", version)
            .append_pair("resource", resource);
        if let Some((name, value)) = self.identity_selector(envs)? {
            query.append_pair(name, value);
        }

        let uri = request_uri(url, &query.finish())?;
        let mut request = Request::get(uri)
            .body(Bytes::new())
            .map_err(|_| Error::config_invalid("failed to build Azure managed identity request"))?;
        if matches!(self, Self::Imds { .. }) {
            request
                .headers_mut()
                .insert("metadata", HeaderValue::from_static("true"));
        }
        if let Some((name, variable, value)) = secret_header {
            let mut header = HeaderValue::from_str(value)
                .ok()
                .filter(|_| !value.trim().is_empty())
                .ok_or_else(|| {
                    Error::config_invalid(format!(
                        "invalid Azure managed identity header in {variable}"
                    ))
                })?;
            header.set_sensitive(true);
            request.headers_mut().insert(name, header);
        }
        Ok(request)
    }

    fn identity_selector(
        self,
        envs: &HashMap<String, String>,
    ) -> Result<Option<(&'static str, &str)>> {
        let object_id = env_value(envs, "AZURE_OBJECT_ID");
        let client_id = env_value(envs, "AZURE_CLIENT_ID");
        let resource_id = envs
            .get("AZURE_MSI_RESOURCE_ID")
            .or_else(|| envs.get("AZURE_MSI_RES_ID"))
            .map(String::as_str)
            .filter(|value| !value.is_empty());
        let legacy = matches!(self, Self::LegacyAppService { .. });

        match (object_id, client_id, resource_id) {
            (Some(value), _, _) if !legacy => Ok(Some(("object_id", value))),
            (None, Some(value), _) => {
                Ok(Some((if legacy { "clientid" } else { "client_id" }, value)))
            }
            (None, None, Some(value)) if !legacy => {
                let name = if matches!(self, Self::AppService { .. }) {
                    "mi_res_id"
                } else {
                    "msi_res_id"
                };
                Ok(Some((name, value)))
            }
            (None, None, None) => Ok(None),
            _ => Err(Error::config_invalid(
                "legacy Azure managed identity selects user-assigned identities by AZURE_CLIENT_ID",
            )),
        }
    }
}

fn env_value<'a>(envs: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    envs.get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn request_uri(endpoint: &str, query: &str) -> Result<Uri> {
    let invalid_endpoint = || Error::config_invalid("invalid Azure managed identity endpoint URL");
    let endpoint_uri: Uri = endpoint.parse().map_err(|_| invalid_endpoint())?;
    if !matches!(endpoint_uri.scheme_str(), Some("http" | "https"))
        || endpoint_uri.host().is_none_or(str::is_empty)
        || endpoint_uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || endpoint.contains('#')
    {
        return Err(invalid_endpoint());
    }

    let separator = match endpoint_uri.query() {
        None => "?",
        Some("") => "",
        Some(existing) => {
            let reserved = [
                "api-version",
                "resource",
                "client_id",
                "clientid",
                "object_id",
                "principal_id",
                "mi_res_id",
                "msi_res_id",
            ];
            if form_urlencoded::parse(existing.as_bytes()).any(|(name, _)| {
                reserved
                    .iter()
                    .any(|param| name.eq_ignore_ascii_case(param))
            }) {
                return Err(Error::config_invalid(
                    "Azure managed identity endpoint URL contains a reserved query parameter",
                ));
            }
            "&"
        }
    };
    format!("{endpoint_uri}{separator}{query}")
        .parse()
        .map_err(|_| invalid_endpoint())
}

#[derive(serde::Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_on: Expiration,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Expiration {
    Seconds(i64),
    Text(String),
}

impl Expiration {
    fn timestamp(&self, endpoint: ManagedIdentityEndpoint<'_>) -> Option<Timestamp> {
        let value = match self {
            Self::Seconds(seconds) => return Timestamp::from_second(*seconds).ok(),
            Self::Text(value) => value,
        };
        if let Ok(seconds) = value.parse::<i64>() {
            return Timestamp::from_second(seconds).ok();
        }
        match endpoint {
            ManagedIdentityEndpoint::Imds { .. } if value.is_empty() => {
                Timestamp::now().checked_add(Duration::from_secs(600))
            }
            ManagedIdentityEndpoint::LegacyAppService { .. } => parse_legacy_expiration(value),
            _ => None,
        }
    }
}

fn parse_legacy_expiration(value: &str) -> Option<Timestamp> {
    // Linux emits a 24-hour clock; Windows adds a meridiem. Both are UTC.
    let mut fields = value.strip_suffix(" +00:00")?.split_ascii_whitespace();
    let (month, date) = fields.next()?.split_once('/')?;
    let (day, year) = date.split_once('/')?;
    let (hour, clock) = fields.next()?.split_once(':')?;
    let (minute, second) = clock.split_once(':')?;
    let hour: u8 = hour.parse().ok()?;
    let minute: u8 = minute.parse().ok()?;
    let second: u8 = second.parse().ok()?;
    // The legacy App Service REST example also uses 00 with a meridiem.
    let hour = match (fields.next(), hour) {
        (None, hour) => hour,
        (Some("AM"), 0..=12) => hour % 12,
        (Some("PM"), 0..=12) => hour % 12 + 12,
        _ => return None,
    };
    if fields.next().is_some() {
        return None;
    }
    let month: u8 = month.parse().ok()?;
    let day: u8 = day.parse().ok()?;
    let year: u16 = year.parse().ok()?;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
        .parse()
        .ok()
}
