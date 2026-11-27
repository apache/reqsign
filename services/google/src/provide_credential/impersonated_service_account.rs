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

use std::time::Duration;

use log::debug;
use reqsign_core::{Context, Error, ProvideCredential, Result};

use crate::constants::IAM_SCOPE;
use crate::credential::{
    Credential, ImpersonatedServiceAccount, ImpersonationSource, Token,
    parse_service_account_impersonation_url,
};
use crate::service_account_impersonation::generate_access_token;

use super::{
    AuthorizedUserCredentialProvider, ExternalAccountCredentialProvider,
    ServiceAccountTokenCredentialProvider,
};

/// The maximum impersonated token lifetime allowed, 1 hour.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// Exchanges an ADC impersonation source and issues a token for its target service account.
#[derive(Debug, Clone)]
pub(super) struct ImpersonatedServiceAccountCredentialProvider {
    impersonated_service_account: ImpersonatedServiceAccount,
    target_scope: String,
}

impl ImpersonatedServiceAccountCredentialProvider {
    pub(super) fn new(
        impersonated_service_account: ImpersonatedServiceAccount,
        target_scope: String,
    ) -> Self {
        Self {
            impersonated_service_account,
            target_scope,
        }
    }

    async fn source_token(&self, ctx: &Context) -> Result<Token> {
        let credential = match &self.impersonated_service_account.source_credentials {
            ImpersonationSource::AuthorizedUser(source) => {
                AuthorizedUserCredentialProvider::new(source.clone())
                    .provide_credential(ctx)
                    .await
            }
            ImpersonationSource::ServiceAccount(source) => {
                ServiceAccountTokenCredentialProvider::new(source.clone())
                    .with_scope(IAM_SCOPE)
                    .provide_credential(ctx)
                    .await
            }
            ImpersonationSource::ExternalAccount(source) => {
                ExternalAccountCredentialProvider::new(source.clone())
                    .with_scope(IAM_SCOPE)
                    .provide_credential(ctx)
                    .await
            }
            ImpersonationSource::ImpersonatedServiceAccount => {
                return Err(Error::config_invalid(
                    "nested impersonated_service_account source_credentials are unsupported. Use delegates to specify the delegation chain",
                ));
            }
        }?;
        credential
            .and_then(|credential| credential.token)
            .ok_or_else(|| {
                Error::credential_invalid(
                    "impersonation source did not provide an OAuth access token",
                )
            })
    }
}

impl ProvideCredential for ImpersonatedServiceAccountCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let source_token = self.source_token(ctx).await?;

        debug!("generating access token for impersonated service account");
        let endpoint = &self
            .impersonated_service_account
            .service_account_impersonation_url;
        let access_token = generate_access_token(
            ctx,
            endpoint,
            &source_token.access_token,
            std::slice::from_ref(&self.target_scope),
            Some(&self.impersonated_service_account.delegates),
            Some(MAX_LIFETIME),
        )
        .await?;

        let credential = Credential::with_token(access_token);
        Ok(Some(
            match parse_service_account_impersonation_url(endpoint) {
                Ok(signer_email) => credential.with_signer_email(signer_email),
                Err(_) => credential,
            },
        ))
    }
}
