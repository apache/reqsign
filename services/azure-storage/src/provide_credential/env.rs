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

use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::credential::Credential;

/// Load Shared Key, SAS, or bearer credentials from the context environment.
///
/// For Shared Key, the account name is selected from `AZBLOB_ACCOUNT_NAME`,
/// `AZURE_STORAGE_ACCOUNT_NAME`, and `AZURE_STORAGE_ACCOUNT` in that order.
///
/// When dedicated variables provide no credential, this provider reads
/// `AZURE_STORAGE_CONNECTION_STRING` for either `AccountName` and `AccountKey`
/// or `SharedAccessSignature`. Connection string setting names are case-insensitive.
/// The caller selects the request endpoint. Invalid strings and the
/// `UseDevelopmentStorage=true` shortcut return
/// [`ConfigInvalid`](reqsign_core::ErrorKind::ConfigInvalid).
#[derive(Clone, Debug, Default)]
pub struct EnvCredentialProvider {}

impl EnvCredentialProvider {
    pub fn new() -> Self {
        Self {}
    }
}
impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let envs = ctx.env_vars();

        // Try to get account name from multiple possible env vars
        let account_name = envs
            .get("AZBLOB_ACCOUNT_NAME")
            .or_else(|| envs.get("AZURE_STORAGE_ACCOUNT_NAME"))
            .or_else(|| envs.get("AZURE_STORAGE_ACCOUNT"))
            .cloned();

        // Check for account key
        if let Some(account_key) = envs
            .get("AZBLOB_ACCOUNT_KEY")
            .or_else(|| envs.get("AZURE_STORAGE_ACCOUNT_KEY"))
        {
            if let Some(account_name) = account_name {
                return Ok(Some(Credential::with_shared_key(
                    &account_name,
                    account_key,
                )));
            }
        }

        // Check for SAS token
        if let Some(sas_token) = envs.get("AZURE_STORAGE_SAS_TOKEN") {
            return Ok(Some(Credential::with_sas_token(sas_token)));
        }

        // Check for bearer token
        if let Some(bearer_token) = envs.get("AZURE_STORAGE_BEARER_TOKEN") {
            return Ok(Some(Credential::with_bearer_token(bearer_token, None)));
        }

        envs.get("AZURE_STORAGE_CONNECTION_STRING")
            .map(|value| parse_connection_string(value))
            .transpose()
    }
}

fn parse_connection_string(connection_string: &str) -> Result<Credential> {
    let mut account_name = None;
    let mut account_key = None;
    let mut sas_token = None;
    let mut development_storage = None;

    for setting in connection_string
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (name, value) = setting
            .split_once('=')
            .filter(|(name, _)| !name.trim().is_empty())
            .ok_or_else(|| {
                Error::config_invalid(
                    "AZURE_STORAGE_CONNECTION_STRING settings must have the form name=value",
                )
            })?;
        let credential_setting = match name.trim().to_ascii_lowercase().as_str() {
            "accountname" => &mut account_name,
            "accountkey" => &mut account_key,
            "sharedaccesssignature" => &mut sas_token,
            "usedevelopmentstorage" => &mut development_storage,
            _ => continue,
        };
        let value = value.trim();
        if value.is_empty() || credential_setting.replace(value).is_some() {
            return Err(Error::config_invalid(
                "AZURE_STORAGE_CONNECTION_STRING contains an empty or repeated setting",
            ));
        }
    }

    if let Some(value) = development_storage {
        if value.eq_ignore_ascii_case("true") {
            return Err(Error::config_invalid(
                "UseDevelopmentStorage=true is unsupported in AZURE_STORAGE_CONNECTION_STRING",
            ));
        }
        if !value.eq_ignore_ascii_case("false") {
            return Err(Error::config_invalid(
                "AZURE_STORAGE_CONNECTION_STRING requires true or false for UseDevelopmentStorage",
            ));
        }
    }

    match (account_name, account_key, sas_token) {
        (Some(account_name), Some(account_key), None) => {
            Ok(Credential::with_shared_key(account_name, account_key))
        }
        (_, None, Some(sas_token)) if sas_token != "?" => Ok(Credential::with_sas_token(sas_token)),
        _ => Err(Error::config_invalid(
            "AZURE_STORAGE_CONNECTION_STRING requires either AccountName and AccountKey or SharedAccessSignature",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DefaultCredentialProvider, RequestSigner};
    use reqsign_core::{ErrorKind, Signer, StaticEnv};

    fn env_context(envs: &[(&str, &str)]) -> Context {
        Context::new().with_env(StaticEnv {
            envs: envs
                .iter()
                .map(|&(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn shared_key_uses_the_account_alias_after_the_existing_names() {
        let cases = [
            (
                &[
                    ("AZBLOB_ACCOUNT_NAME", "legacy-account"),
                    ("AZBLOB_ACCOUNT_KEY", "legacy-key"),
                    ("AZURE_STORAGE_ACCOUNT_NAME", "explicit-account"),
                ][..],
                "legacy-account",
                "legacy-key",
            ),
            (
                &[("AZURE_STORAGE_ACCOUNT_NAME", "explicit-account")][..],
                "explicit-account",
                "example-key",
            ),
            (&[][..], "alias-account", "example-key"),
        ];
        let provider = EnvCredentialProvider::new();
        for (account_overrides, expected_name, expected_key) in cases {
            let envs = [
                ("AZURE_STORAGE_ACCOUNT", "alias-account"),
                ("AZURE_STORAGE_ACCOUNT_KEY", "example-key"),
                ("AZURE_STORAGE_SAS_TOKEN", "example-sas"),
                ("AZURE_STORAGE_BEARER_TOKEN", "example-bearer"),
                ("AZURE_STORAGE_CONNECTION_STRING", "malformed-setting"),
            ]
            .into_iter()
            .chain(account_overrides.iter().copied())
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
            let ctx = Context::new().with_env(StaticEnv {
                envs,
                ..Default::default()
            });
            let Some(Credential::SharedKey {
                account_name,
                account_key,
            }) = provider.provide_credential(&ctx).await.unwrap()
            else {
                panic!("expected a Shared Key credential");
            };
            assert_eq!(account_name, expected_name);
            assert_eq!(account_key, expected_key);
        }
    }

    #[tokio::test]
    async fn dedicated_sas_and_bearer_precede_the_connection_string() {
        let mut env = StaticEnv {
            envs: [
                ("AZURE_STORAGE_ACCOUNT".into(), "alias-account".into()),
                ("AZURE_STORAGE_SAS_TOKEN".into(), "example-sas".into()),
                ("AZURE_STORAGE_BEARER_TOKEN".into(), "example-bearer".into()),
                (
                    "AZURE_STORAGE_CONNECTION_STRING".into(),
                    "AccountName=fallback;AccountKey=YWJjZA==;UseDevelopmentStorage=false".into(),
                ),
            ]
            .into(),
            ..Default::default()
        };
        let provider = EnvCredentialProvider::new();
        let ctx = Context::new().with_env(env.clone());
        let Some(Credential::SasToken { token, .. }) =
            provider.provide_credential(&ctx).await.unwrap()
        else {
            panic!("expected a SAS token");
        };
        assert_eq!(token, "example-sas");

        env.envs.remove("AZURE_STORAGE_SAS_TOKEN");
        let ctx = Context::new().with_env(env.clone());
        let Some(Credential::BearerToken { token, .. }) =
            provider.provide_credential(&ctx).await.unwrap()
        else {
            panic!("expected a bearer token");
        };
        assert_eq!(token, "example-bearer");

        env.envs.remove("AZURE_STORAGE_BEARER_TOKEN");
        let ctx = Context::new().with_env(env.clone());
        let Some(Credential::SharedKey { account_name, .. }) =
            provider.provide_credential(&ctx).await.unwrap()
        else {
            panic!("expected a Shared Key credential from the connection string");
        };
        assert_eq!(account_name, "fallback");

        env.envs.remove("AZURE_STORAGE_CONNECTION_STRING");
        let ctx = Context::new().with_env(env);
        assert!(provider.provide_credential(&ctx).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn connection_string_loads_a_padded_shared_key_independent_of_endpoints() {
        let ctx = env_context(&[
            ("AZURE_STORAGE_ACCOUNT_NAME", "dedicated-name-without-key"),
            (
                "AZURE_STORAGE_CONNECTION_STRING",
                "BlobEndpoint=not an endpoint;DefaultEndpointsProtocol=ignored;EndpointSuffix=; \
                 accountname = exampleaccount ; AccountKey = YWJjZA== ;",
            ),
        ]);
        let credential = EnvCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .unwrap()
            .expect("connection string should provide a credential");
        assert!(!format!("{credential:?}").contains("YWJjZA=="));
        let Credential::SharedKey {
            account_name,
            account_key,
        } = credential
        else {
            panic!("expected a Shared Key credential");
        };
        assert_eq!(account_name, "exampleaccount");
        assert_eq!(account_key, "YWJjZA==");
    }

    #[tokio::test]
    async fn connection_string_sas_signs_the_caller_uri_with_the_original_query_bytes() {
        let ctx = env_context(&[(
            "AZURE_STORAGE_CONNECTION_STRING",
            "BlobEndpoint=https://ignored.example.test;AccountName=ignoredaccount;\
             SharedAccessSignature=?sv=2025-01-05&sp=r&sig=example%2Bsignature%3Bvalue==",
        )]);
        let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner::new());
        let credential = signer.credential_for(None).await.unwrap();
        assert!(!format!("{credential:?}").contains("example%2Bsignature"));
        let (mut request, _) =
            http::Request::get("https://chosen.example.test/container/blob?comp=metadata")
                .body(())
                .unwrap()
                .into_parts();
        signer
            .sign_with_credential(&mut request, &credential, None)
            .await
            .unwrap();
        assert_eq!(
            request.uri,
            "https://chosen.example.test/container/blob?comp=metadata&sv=2025-01-05&sp=r&sig=example%2Bsignature%3Bvalue==",
        );
    }

    #[tokio::test]
    async fn malformed_connection_strings_return_redacted_config_errors() {
        let provider = EnvCredentialProvider::new();
        for value in [
            "",
            "secret-marker-without-an-equals-sign",
            "=secret-marker",
            "AccountKey=secret-marker",
            "AccountName=exampleaccount;AccountKey= ",
            "AccountName=exampleaccount;AccountKey=secret-marker;accountkey=duplicate",
            "SharedAccessSignature=?",
            "UseDevelopmentStorage=secret-marker",
            "AccountName=exampleaccount;AccountKey=secret-marker;SharedAccessSignature=sig=example",
        ] {
            let ctx = env_context(&[("AZURE_STORAGE_CONNECTION_STRING", value)]);
            let error = provider.provide_credential(&ctx).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
            assert!(
                error
                    .to_string()
                    .contains("AZURE_STORAGE_CONNECTION_STRING")
            );
            assert!(!error.to_string().contains("secret-marker"));
            assert!(!format!("{error:?}").contains("secret-marker"));
        }
    }

    #[tokio::test]
    async fn development_storage_shortcut_is_explicitly_unsupported() {
        let ctx = env_context(&[(
            "AZURE_STORAGE_CONNECTION_STRING",
            "UseDevelopmentStorage=true;DevelopmentStorageProxyUri=https://proxy.example.test/?sig=secret-marker",
        )]);
        let error = EnvCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(error.to_string().contains("UseDevelopmentStorage=true"));
        assert!(error.to_string().contains("unsupported"));
        assert!(!format!("{error:?}").contains("secret-marker"));
    }
}
