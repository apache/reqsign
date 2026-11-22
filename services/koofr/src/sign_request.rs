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

use http::HeaderValue;
use http::header::AUTHORIZATION;
use reqsign_core::{Error, Result, SignRequest, SigningCredential};

use crate::Credential;

/// Adds Koofr access-token authentication to a request.
///
/// The signer inserts a sensitive `Authorization: Token token=<token>` header
/// and leaves the request URI unchanged. `expires_in` is ignored because the
/// documented token exchange does not report an expiry.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestSigner;

impl RequestSigner {
    /// Create a new Koofr request signer.
    pub const fn new() -> Self {
        Self
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &reqsign_core::Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(credential) = credential else {
            return Ok(());
        };

        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Koofr access token is empty and cannot sign the request",
            ));
        }

        let mut value = HeaderValue::from_str(&format!("Token token={}", credential.token()))
            .map_err(|err| {
                Error::credential_invalid("Koofr access token is not a valid HTTP header value")
                    .with_source(err)
            })?;
        value.set_sensitive(true);

        req.headers.insert(AUTHORIZATION, value);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use reqsign_core::Context;

    use super::*;

    fn request_parts() -> http::request::Parts {
        http::Request::builder()
            .method(http::Method::GET)
            .uri("https://app.koofr.net/api/v2/mounts/primary/files/list?path=%2Fdata&limit=10")
            .header("x-request-id", "fabricated-request")
            .body(())
            .expect("request must build")
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn inserts_sensitive_token_header_without_changing_uri() {
        let mut parts = request_parts();
        let original_uri = parts.uri.clone();
        let credential = Credential::new("fabricated-token");

        RequestSigner
            .sign_request(&Context::new(), &mut parts, Some(&credential), None)
            .await
            .expect("signing must succeed");

        assert_eq!(original_uri, parts.uri);
        assert_eq!("fabricated-request", parts.headers["x-request-id"]);
        assert_eq!("Token token=fabricated-token", parts.headers[AUTHORIZATION]);
        assert!(parts.headers[AUTHORIZATION].is_sensitive());
    }

    #[tokio::test]
    async fn no_credential_leaves_request_unchanged() {
        let mut parts = request_parts();
        let original = parts.clone();

        RequestSigner
            .sign_request(&Context::new(), &mut parts, None, None)
            .await
            .expect("missing credential is not a signing failure");

        assert_eq!(original.uri, parts.uri);
        assert_eq!(original.headers, parts.headers);
    }

    #[tokio::test]
    async fn empty_token_fails_without_mutating_request() {
        let mut parts = request_parts();
        let original = parts.clone();
        let credential = Credential::new("");

        let error = RequestSigner
            .sign_request(&Context::new(), &mut parts, Some(&credential), None)
            .await
            .expect_err("empty token must fail");

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        assert_eq!(original.uri, parts.uri);
        assert_eq!(original.headers, parts.headers);
    }
}
