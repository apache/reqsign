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

use super::account_authorize::AccountAuthorizationCredentialProvider;

/// Environment variable names used by the official B2 command line tools.
pub(crate) const B2_APPLICATION_KEY_ID: &str = "B2_APPLICATION_KEY_ID";
pub(crate) const B2_APPLICATION_KEY: &str = "B2_APPLICATION_KEY";

/// Credential provider that reads a B2 application key from the environment and
/// exchanges it for a Native API authorization token.
///
/// Both `B2_APPLICATION_KEY_ID` and `B2_APPLICATION_KEY` are required. Missing
/// or empty values skip this provider without sending a request.
#[derive(Debug, Default)]
pub struct EnvCredentialProvider;

impl EnvCredentialProvider {
    /// Create a new environment credential provider.
    pub fn new() -> Self {
        Self
    }
}

impl ProvideCredential for EnvCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(&self, ctx: &Context) -> Result<Option<Self::Credential>> {
        let application_key_id = match ctx.env_var(B2_APPLICATION_KEY_ID) {
            Some(value) if !value.is_empty() => value,
            _ => {
                debug!("{B2_APPLICATION_KEY_ID} not set, skipping B2 environment provider");
                return Ok(None);
            }
        };
        let application_key = match ctx.env_var(B2_APPLICATION_KEY) {
            Some(value) if !value.is_empty() => value,
            _ => {
                debug!("{B2_APPLICATION_KEY} not set, skipping B2 environment provider");
                return Ok(None);
            }
        };

        debug!("loaded B2 application key from environment");
        AccountAuthorizationCredentialProvider::new(application_key_id, application_key)
            .provide_credential(ctx)
            .await
    }
}
