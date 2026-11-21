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

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential};

use crate::Credential;

/// Signs Yandex Disk REST API requests with an OAuth access token.
///
/// Header authentication only. It inserts a sensitive `Authorization: OAuth`
/// header and leaves the URI and every other header unchanged. The caller owns
/// the API host, API version, resource path, query parameters, and any upload
/// or download URL returned by Yandex Disk. Query authentication and
/// `expires_in` are not supported and are rejected.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // Header signing is immediate, so an expiring credential must be usable
        // now. A credential without an expiry is static and needs no clock.
        if credential.expires_at().is_some() {
            Timestamp::now()
        } else {
            Timestamp::default()
        }
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
                "Yandex Disk signing does not support expires_in",
            ));
        }

        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("Yandex Disk credential is required for request signing")
        })?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Yandex Disk credential is not valid for the requested signing operation",
            ));
        }
        let authorization = credential.authorization_header_value()?;

        req.headers
            .insert(http::header::AUTHORIZATION, authorization);

        Ok(())
    }
}
