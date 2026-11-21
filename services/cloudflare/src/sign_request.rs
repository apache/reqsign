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

use crate::credential::Credential;

/// Signs Cloudflare API requests with an API token.
///
/// Header authentication only: it inserts a sensitive `Authorization: Bearer`
/// header and leaves the URI and every other header unchanged, so the caller
/// keeps ownership of the resource URL, `Content-Type`, and any request body
/// encoding. The Cloudflare API has no query authentication, so `expires_in` is
/// rejected.
///
/// Cloudflare API tokens carry no expiry that Reqsign can read, and signing
/// writes no protocol time, so signing has no clock dependency.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // A Cloudflare API token's optional expiry is assigned in the dashboard
        // and is not readable from the token, so there is no protocol deadline to
        // derive here. Returning a constant keeps signing free of a clock read,
        // which also keeps `wasm32-unknown-unknown` working without a JavaScript
        // clock.
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
                "Cloudflare signing does not support expires_in",
            ));
        }

        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("Cloudflare API token is required for request signing")
        })?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Cloudflare credential is not valid for the requested signing operation",
            ));
        }

        req.headers.insert(
            http::header::AUTHORIZATION,
            credential.bearer_header_value()?,
        );

        Ok(())
    }
}
