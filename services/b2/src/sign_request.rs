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

use http::header;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential};

use crate::credential::Credential;

/// RequestSigner for the Backblaze B2 Native API.
///
/// Inserts the account authorization token as a sensitive `Authorization`
/// header. The token is sent as-is; B2 Native API calls do not use a bearer
/// prefix.
///
/// Only the request head is changed. Upload URL creation, download
/// authorization, and the S3-compatible API are caller responsibilities and may
/// require a different authorization value.
#[derive(Debug, Default)]
pub struct RequestSigner;

impl SignRequest for RequestSigner {
    type Credential = Credential;

    async fn sign_request(
        &self,
        _ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(credential) = credential else {
            return Ok(());
        };

        if !credential.is_complete() {
            return Err(Error::credential_invalid(
                "B2 credential is missing its authorization token or Native API endpoints",
            ));
        }

        let required_until = Timestamp::now() + expires_in.unwrap_or_default();
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "B2 authorization token expires before the requested operation deadline",
            ));
        }

        let mut value: http::HeaderValue = credential.authorization_token.parse().map_err(|e| {
            Error::credential_invalid("B2 authorization token cannot be encoded as a header value")
                .with_source(e)
        })?;
        value.set_sensitive(true);

        req.headers.insert(header::AUTHORIZATION, value);

        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn credential() -> Credential {
        Credential::new(
            "authorization-token-value",
            "https://api001.backblazeb2.com",
            "https://f001.backblazeb2.com",
        )
    }

    #[tokio::test]
    async fn inserts_a_sensitive_native_api_authorization_header() {
        let signer = RequestSigner;
        let context = Context::new();
        let credential = credential();
        let mut parts = http::Request::get(
            "https://api001.backblazeb2.com/b2api/v4/b2_list_buckets?accountId=account",
        )
        .header("x-caller", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

        signer
            .sign_request(&context, &mut parts, Some(&credential), None)
            .await
            .expect("signing must succeed");

        let authorization = parts
            .headers
            .get(header::AUTHORIZATION)
            .expect("authorization header must be present");
        assert_eq!("authorization-token-value", authorization);
        assert!(authorization.is_sensitive());
        assert_eq!(
            "https://api001.backblazeb2.com/b2api/v4/b2_list_buckets?accountId=account",
            parts.uri.to_string()
        );
        assert_eq!("value", parts.headers["x-caller"]);
    }

    #[tokio::test]
    async fn rejects_an_expired_credential_without_changing_the_request() {
        let signer = RequestSigner;
        let context = Context::new();
        let credential = credential().with_expires_at(Timestamp::now() - Duration::from_secs(1));
        let mut parts =
            http::Request::get("https://api001.backblazeb2.com/b2api/v4/b2_list_buckets")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        let original = parts.clone();

        let error = signer
            .sign_request(&context, &mut parts, Some(&credential), None)
            .await
            .expect_err("expired credential must fail");

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        assert_eq!(original.uri, parts.uri);
        assert_eq!(original.headers, parts.headers);
    }

    #[tokio::test]
    async fn rejects_an_incomplete_credential_without_changing_the_request() {
        let signer = RequestSigner;
        let context = Context::new();
        let credential = Credential::new(
            "authorization-token-value",
            "",
            "https://f001.backblazeb2.com",
        );
        let mut parts =
            http::Request::get("https://api001.backblazeb2.com/b2api/v4/b2_list_buckets")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        let original = parts.clone();

        let error = signer
            .sign_request(&context, &mut parts, Some(&credential), None)
            .await
            .expect_err("incomplete credential must fail");

        assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
        assert_eq!(original.uri, parts.uri);
        assert_eq!(original.headers, parts.headers);
    }

    #[tokio::test]
    async fn missing_credential_leaves_the_request_unchanged() {
        let signer = RequestSigner;
        let context = Context::new();
        let mut parts =
            http::Request::get("https://api001.backblazeb2.com/b2api/v4/b2_list_buckets")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;

        signer
            .sign_request(&context, &mut parts, None, None)
            .await
            .expect("missing credential must be a no-op");

        assert!(!parts.headers.contains_key(header::AUTHORIZATION));
    }
}
