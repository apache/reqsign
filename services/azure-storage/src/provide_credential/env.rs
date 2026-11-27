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

use reqsign_core::{Context, ProvideCredential};

use crate::credential::Credential;

/// Load Shared Key, SAS, or bearer credentials from the context environment.
///
/// For Shared Key, the account name is selected from `AZBLOB_ACCOUNT_NAME`,
/// `AZURE_STORAGE_ACCOUNT_NAME`, and `AZURE_STORAGE_ACCOUNT` in that order.
#[derive(Clone, Debug, Default)]
pub struct EnvCredentialProvider {}

impl EnvCredentialProvider {
    pub fn new() -> Self {
        Self {}
    }
}
impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(
        &self,
        ctx: &Context,
    ) -> Result<Option<Self::Credential>, reqsign_core::Error> {
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

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::StaticEnv;

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
    async fn the_account_alias_without_a_key_leaves_sas_and_bearer_selection_intact() {
        let mut env = StaticEnv {
            envs: [
                ("AZURE_STORAGE_ACCOUNT".into(), "alias-account".into()),
                ("AZURE_STORAGE_SAS_TOKEN".into(), "example-sas".into()),
                ("AZURE_STORAGE_BEARER_TOKEN".into(), "example-bearer".into()),
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
        let ctx = Context::new().with_env(env);
        assert!(provider.provide_credential(&ctx).await.unwrap().is_none());
    }
}
