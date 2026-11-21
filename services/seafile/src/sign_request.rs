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

/// Signs Seafile API requests with an account or repository API token.
///
/// Header authentication only. It inserts a sensitive
/// `Authorization: Token <token>` header and does not modify the URI or any
/// other header. Seafile has no query authentication, so `expires_in` is
/// rejected rather than silently ignored.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        // Seafile tokens have no protocol time and no expiration, so signing
        // has no clock dependency.
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
                "Seafile signing does not support expires_in",
            ));
        }

        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("Seafile credential is required for request signing")
        })?;
        let required_until = self.required_valid_until(credential, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "Seafile credential is not valid for the requested signing operation",
            ));
        }

        req.headers.insert(
            http::header::AUTHORIZATION,
            credential.authorization_header_value()?,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Credential {
        Credential::new("seafile-token-value").expect("token must be valid")
    }

    fn request() -> http::request::Parts {
        http::Request::get("https://files.example.com/api2/repos/?x=%2F")
            .header("x-caller", "value")
            .body(())
            .expect("request must build")
            .into_parts()
            .0
    }

    #[tokio::test]
    async fn inserts_a_sensitive_token_header_and_preserves_the_request() {
        let signer = RequestSigner;
        let context = Context::new();
        let credential = credential();
        let original = request();
        let mut parts = original.clone();

        signer
            .sign_request(&context, &mut parts, Some(&credential), None)
            .await
            .expect("signing must succeed");

        let authorization = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .expect("authorization header must be present");
        assert_eq!(authorization, "Token seafile-token-value");
        assert!(authorization.is_sensitive());
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.headers["x-caller"], "value");
    }

    #[tokio::test]
    async fn rejects_expires_in_without_mutating_the_request() {
        let signer = RequestSigner;
        let context = Context::new();
        let credential = credential();
        let original = request();
        let mut parts = original.clone();

        let error = signer
            .sign_request(
                &context,
                &mut parts,
                Some(&credential),
                Some(Duration::from_secs(60)),
            )
            .await
            .expect_err("expires_in must be rejected");

        assert_eq!(reqsign_core::ErrorKind::RequestInvalid, error.kind());
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
    }

    #[tokio::test]
    async fn rejects_a_missing_credential_without_mutating_the_request() {
        let signer = RequestSigner;
        let context = Context::new();
        let original = request();
        let mut parts = original.clone();

        let error = signer
            .sign_request(&context, &mut parts, None, None)
            .await
            .expect_err("a Seafile credential is required");

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
    }
}
