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
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential};
use std::time::Duration;

/// Signs Microsoft Graph requests with a Bearer access token.
///
/// Header authentication only. It inserts a sensitive `Authorization` header
/// and does not modify the URI or any other header. Microsoft Graph documents
/// the `Authorization` header as the way to present an access token, and this
/// signer does not implement query authentication, so `expires_in` is rejected.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        Timestamp::now()
    }

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        if expires_in.is_some() {
            return Err(Error::request_invalid(
                "OneDrive signing does not support expires_in",
            ));
        }

        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("OneDrive credential is required for request signing")
        })?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "OneDrive credential is not valid for the requested signing operation",
            ));
        }

        let authorization = credential.access_token().bearer_header_value()?;
        req.headers
            .insert(http::header::AUTHORIZATION, authorization);

        Ok(())
    }
}
