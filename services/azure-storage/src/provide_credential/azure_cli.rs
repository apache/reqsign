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

use crate::credential::Credential;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, ProvideCredential, Result};
use serde::Deserialize;
use serde::de::DeserializeOwned;

const STORAGE_RESOURCE: &str = "https://storage.azure.com/";
const STORAGE_SCOPE: &str = "https://storage.azure.com/.default";

/// Load a storage bearer token from an existing Azure CLI session.
///
/// This provider runs `az account get-access-token` through the context's
/// command executor. It passes `--resource https://storage.azure.com/` and
/// uses a non-blank `AZURE_TENANT_ID` from the context as `--tenant`.
/// Azure CLI supports tenant selection for user and service principal accounts.
#[derive(Clone, Debug, Default)]
pub struct AzureCliCredentialProvider {}

impl AzureCliCredentialProvider {
    /// Create a provider using the storage resource and context tenant.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tenant passed to Azure CLI, overriding `AZURE_TENANT_ID`.
    pub fn with_tenant_id(
        self,
        tenant_id: impl Into<String>,
    ) -> ConfiguredAzureCliCredentialProvider {
        ConfiguredAzureCliCredentialProvider::default().with_tenant_id(tenant_id)
    }

    /// Request the given scope with `--scope`.
    pub fn with_scope(self, scope: impl Into<String>) -> ConfiguredAzureCliCredentialProvider {
        ConfiguredAzureCliCredentialProvider::default().with_scope(scope)
    }

    /// Request the given resource with `--resource`.
    pub fn with_resource(
        self,
        resource: impl Into<String>,
    ) -> ConfiguredAzureCliCredentialProvider {
        ConfiguredAzureCliCredentialProvider::default().with_resource(resource)
    }
}

impl ProvideCredential for AzureCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        ConfiguredAzureCliCredentialProvider::default()
            .provide_credential(ctx)
            .await
    }
}

/// Load a bearer token from Azure CLI with an explicit tenant or token target.
///
/// Use this provider directly with `Signer::new` or in a custom credential chain.
/// The last call to [`Self::with_scope`] or [`Self::with_resource`] selects
/// the target. Values are passed verbatim as individual command arguments.
///
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # fn example() {
/// use reqsign_azure_storage::{AzureCliCredentialProvider, RequestSigner};
/// use reqsign_command_execute_tokio::TokioCommandExecute;
/// use reqsign_core::{Context, Signer};
///
/// let ctx = Context::new().with_command_execute(TokioCommandExecute);
/// let provider = AzureCliCredentialProvider::new()
///     .with_tenant_id("contoso.onmicrosoft.com")
///     .with_scope("https://storage.azure.com/.default");
/// let signer = Signer::new(ctx, provider, RequestSigner::new());
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct ConfiguredAzureCliCredentialProvider {
    tenant_id: Option<String>,
    target: Option<AzureCliTarget>,
}

#[derive(Clone, Debug)]
enum AzureCliTarget {
    Scope(String),
    Resource(String),
}

impl ConfiguredAzureCliCredentialProvider {
    /// Set the tenant passed to Azure CLI, overriding `AZURE_TENANT_ID`.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Request the given scope with `--scope`, replacing any configured resource.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.target = Some(AzureCliTarget::Scope(scope.into()));
        self
    }

    /// Request the given resource with `--resource`, replacing any configured scope.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.target = Some(AzureCliTarget::Resource(resource.into()));
        self
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureCliToken {
    access_token: String,
    expires_on: Option<String>,
    #[serde(rename = "expires_on")]
    expires_on_timestamp: Option<i64>,
    #[allow(dead_code)]
    subscription: Option<String>,
    #[allow(dead_code)]
    tenant: Option<String>,
    #[allow(dead_code)]
    token_type: String,
}

impl ProvideCredential for ConfiguredAzureCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let (target_flag, target) = match &self.target {
            Some(AzureCliTarget::Scope(scope)) => ("--scope", scope.as_str()),
            Some(AzureCliTarget::Resource(resource)) => ("--resource", resource.as_str()),
            None => ("--resource", STORAGE_RESOURCE),
        };
        if target.trim().is_empty() {
            return Err(Error::config_invalid(format!(
                "Azure CLI {target_flag} must not be blank"
            )));
        }

        let tenant_id = self.tenant_id.clone().or_else(|| {
            ctx.env_var("AZURE_TENANT_ID")
                .filter(|tenant_id| !tenant_id.trim().is_empty())
        });
        let mut args = vec![
            "account",
            "get-access-token",
            target_flag,
            target,
            "--output",
            "json",
        ];
        if let Some(tenant_id) = tenant_id.as_deref() {
            if tenant_id.trim().is_empty() {
                return Err(Error::config_invalid(
                    "Azure CLI tenant ID must not be blank",
                ));
            }
            args.extend(["--tenant", tenant_id]);
        }
        let token: AzureCliToken = execute_token_command(ctx, "az", &args).await?;

        // Azure CLI recommends the UTC epoch field. Older versions only have expiresOn.
        let expires_on = if let Some(timestamp) = token.expires_on_timestamp {
            Timestamp::from_second(timestamp).ok()
        } else if let Some(expires_str) = token.expires_on {
            Timestamp::parse_datetime_utc(&expires_str).ok()
        } else {
            None
        };

        Ok(Some(Credential::with_bearer_token(
            &token.access_token,
            expires_on,
        )))
    }
}

/// Load a bearer token from an existing Azure Developer CLI (`azd`) session.
///
/// Use this provider explicitly with a context that has a command executor.
/// It runs `azd auth token` with `--no-prompt` and requires a token with an
/// absolute expiration time. The default scope is `https://storage.azure.com/.default`.
///
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # fn example() {
/// use reqsign_azure_storage::{AzureDeveloperCliCredentialProvider, RequestSigner};
/// use reqsign_command_execute_tokio::TokioCommandExecute;
/// use reqsign_core::{Context, Signer};
///
/// let ctx = Context::new().with_command_execute(TokioCommandExecute);
/// let signer = Signer::new(
///     ctx,
///     AzureDeveloperCliCredentialProvider::new(),
///     RequestSigner::new(),
/// );
/// # }
/// ```
#[derive(Clone, Debug, Default)]
pub struct AzureDeveloperCliCredentialProvider {
    scope: Option<String>,
}

impl AzureDeveloperCliCredentialProvider {
    /// Create a provider for the Azure Storage scope.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the scope passed to `azd auth token`.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureDeveloperCliToken {
    token: String,
    expires_on: String,
}

impl ProvideCredential for AzureDeveloperCliCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let scope = self.scope.as_deref().unwrap_or(STORAGE_SCOPE);
        if scope.trim().is_empty() {
            return Err(Error::config_invalid(
                "Azure Developer CLI scope must not be blank",
            ));
        }
        let args = [
            "auth",
            "token",
            "--scope",
            scope,
            "--output",
            "json",
            "--no-prompt",
        ];
        let token: AzureDeveloperCliToken = execute_token_command(ctx, "azd", &args).await?;
        let expires_on: Timestamp = token.expires_on.parse().map_err(|_| {
            Error::unexpected("invalid expiresOn timestamp in Azure Developer CLI token output")
        })?;
        if token.token.is_empty() {
            return Err(Error::credential_invalid(
                "Azure Developer CLI returned an empty token",
            ));
        }
        Ok(Some(Credential::with_bearer_token(
            &token.token,
            Some(expires_on),
        )))
    }
}

async fn execute_token_command<T: DeserializeOwned>(
    ctx: &Context,
    program: &str,
    args: &[&str],
) -> Result<T> {
    let output = ctx.command_execute(program, args).await?;
    if !output.success() {
        return Err(
            Error::credential_invalid(format!("{program} token command failed"))
                .with_context(format!("exit status: {}", output.status)),
        );
    }

    // Both the command output and the deserializer's error can contain token material.
    serde_json::from_slice(&output.stdout)
        .map_err(|_| Error::unexpected(format!("failed to parse {program} token output")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redacted_real_azure_cli_response() {
        let response = include_bytes!("../../tests/fixtures/azure_cli_token_response.json");
        let token: AzureCliToken = serde_json::from_slice(response).unwrap();
        assert_eq!(token.access_token, "REDACTED");
        assert_eq!(token.expires_on_timestamp, Some(1788423131));
        assert_eq!(token.token_type, "Bearer");
    }
}
