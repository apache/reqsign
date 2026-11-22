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

/// Signs Baidu Netdisk Open Platform requests with an access token.
///
/// Query authentication only. The signer removes any existing `access_token`
/// query parameters and appends one form-encoded `access_token` parameter, so
/// signing the same request again does not leave stale authentication. It
/// preserves the raw representation and order of unrelated query parameters
/// and leaves every header unchanged. The caller owns the API host, method,
/// path, other query parameters, headers (including `User-Agent`), and body.
///
/// A Baidu access token is an opaque static value in this crate. Signing has
/// no protocol time and no separate presign lifetime, so `expires_in` is
/// rejected.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestSigner;

impl RequestSigner {
    /// Create a new Baidu Netdisk request signer.
    pub const fn new() -> Self {
        Self
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // The credential has no tracked expiry and the signer writes no protocol
        // time, so signing needs no clock.
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
                "Baidu Netdisk signing does not support expires_in",
            ));
        }

        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("Baidu Netdisk credential is required for request signing")
        })?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Baidu Netdisk credential is not valid for the requested signing operation",
            ));
        }

        req.uri = append_access_token(&req.uri, credential.access_token())?;
        Ok(())
    }
}

fn append_access_token(uri: &http::Uri, access_token: &str) -> Result<http::Uri> {
    let mut query = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| {
            form_urlencoded::parse(pair.as_bytes())
                .next()
                .is_none_or(|(name, _)| name != "access_token")
        })
        .collect::<Vec<_>>()
        .join("&");

    if !query.is_empty() && !query.ends_with('&') {
        query.push('&');
    }
    query.push_str(
        &form_urlencoded::Serializer::new(String::new())
            .append_pair("access_token", access_token)
            .finish(),
    );

    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(format!("{path}?{query}").parse().map_err(|e| {
        Error::request_invalid("failed to encode Baidu Netdisk access token into the request URI")
            .with_source(e)
    })?);
    http::Uri::from_parts(parts).map_err(|e| {
        Error::request_invalid("failed to build the authenticated Baidu Netdisk request URI")
            .with_source(e)
    })
}
