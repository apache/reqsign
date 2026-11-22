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

/// Signs GitHub.com REST API requests with a bearer token.
///
/// Header authentication only. It inserts a sensitive `Authorization: Bearer`
/// header when the credential is a token and removes any existing
/// `Authorization` header for an explicit anonymous credential, so a reused
/// request cannot carry stale authentication material. Other headers and the
/// URI are unchanged. It does not add `User-Agent` (GitHub requires the caller
/// to send one), `Accept`, or `X-GitHub-Api-Version`. Query authentication and
/// `expires_in` are not supported and are rejected.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // GitHub credentials carry no expiration in this crate and the signer
        // writes no protocol time, so signing has no clock dependency.
        Timestamp::default()
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
                "GitHub signing does not support expires_in",
            ));
        }

        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("GitHub credential is required for request signing")
        })?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "GitHub credential is not valid for the requested signing operation",
            ));
        }

        match credential.bearer_header_value()? {
            Some(authorization) => {
                req.headers
                    .insert(http::header::AUTHORIZATION, authorization);
            }
            None => {
                req.headers.remove(http::header::AUTHORIZATION);
            }
        }

        Ok(())
    }
}
