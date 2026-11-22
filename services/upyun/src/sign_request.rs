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
use http::HeaderValue;
use http::header::{AUTHORIZATION, DATE};
use reqsign_core::hash::base64_encode;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential, SigningRequest};
use std::time::Duration;

const CONTENT_MD5: &str = "content-md5";

/// RequestSigner signs Upyun REST API requests with the UPYUN header scheme.
///
/// The signature covers the request method, the wire path, the `Date` header,
/// and the `Content-MD5` header when it is present and non-empty. The signer
/// inserts `Date` and `Authorization` and preserves the request path and query
/// exactly as supplied by the caller.
///
/// A credential scoped to a bucket is accepted only when the first segment of
/// the request's wire path exactly equals that bucket. This check runs on every
/// signature, including when [`Signer`](reqsign_core::Signer) reuses a cached
/// credential. Explicit static credentials are unscoped unless the caller sets
/// a bucket.
///
/// The signed URI is the wire path exactly as supplied. The signer does not
/// decode, normalize, or rebuild it, and makes no claim about path rewriting by
/// a proxy or server.
///
/// `expires_in` is ignored. Upyun validates the header signature for 30 minutes
/// from the signed `Date`; the signer does not create presigned URLs or token
/// credentials.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestSigner {
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a new Upyun request signer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take the current time to sign requests. Only use this
    /// function for testing.
    pub fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    fn get_time(&self) -> Timestamp {
        self.time.unwrap_or_else(Timestamp::now)
    }

    fn required_valid_until_at(
        &self,
        signing_time: Timestamp,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        signing_time + expires_in.unwrap_or_default()
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        self.required_valid_until_at(self.get_time(), expires_in)
    }

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(credential) = credential else {
            return Ok(());
        };
        if credential.operator.is_empty() || credential.password.is_empty() {
            return Err(Error::credential_invalid(
                "Upyun operator and password must both be non-empty",
            ));
        }

        let signing_time = self.get_time();
        if !credential.is_valid_at(self.required_valid_until_at(signing_time, expires_in)) {
            return Err(Error::credential_invalid(
                "Upyun credential is not valid for the requested signing operation",
            ));
        }

        let provider = ctx.crypto_provider()?;
        let date = signing_time.format_http_date();

        let mut signing_req = SigningRequest::build(req)?;
        if let Some(bucket) = credential.bucket.as_deref() {
            let path_bucket = signing_req
                .path
                .strip_prefix('/')
                .and_then(|path| path.split('/').next());
            if path_bucket != Some(bucket) {
                return Err(Error::credential_invalid(
                    "Upyun credential is scoped to a different bucket",
                ));
            }
        }

        let content_md5 = match signing_req.headers.get(CONTENT_MD5) {
            Some(value) => {
                let value = value.to_str().map_err(|e| {
                    Error::request_invalid("Content-MD5 header is not valid ASCII").with_source(e)
                })?;
                (!value.is_empty()).then_some(value)
            }
            None => None,
        };

        let mut elements = vec![
            signing_req.method.as_str(),
            signing_req.path.as_str(),
            date.as_str(),
        ];
        if let Some(content_md5) = content_md5 {
            elements.push(content_md5);
        }
        let string_to_sign = elements.join("&");

        let signing_key = hex::encode(provider.md5(credential.password.as_bytes())?);
        let signature =
            base64_encode(&provider.hmac_sha1(signing_key.as_bytes(), string_to_sign.as_bytes())?);

        let date = HeaderValue::from_str(&date)?;
        let authorization =
            HeaderValue::from_str(&format!("UPYUN {}:{signature}", credential.operator))?;

        signing_req.headers.insert(DATE, date);
        signing_req.headers.insert(AUTHORIZATION, authorization);
        signing_req.apply(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::crypto::CryptoProvider;
    use reqsign_core::{Context, ErrorKind};

    fn test_context() -> Context {
        Context::new().with_crypto(reqsign_crypto_rustcrypto::RustCryptoProvider::new())
    }

    fn signing_time() -> Timestamp {
        "2016-11-09T14:26:58Z".parse().expect("timestamp parses")
    }

    #[tokio::test]
    async fn signs_the_published_upyun_example() -> anyhow::Result<()> {
        let signer = RequestSigner::new().with_time(signing_time());
        let credential = Credential::new("operator123", "password123");
        let mut req = http::Request::put("https://v0.api.upyun.com/upyun-temp/demo.jpg")
            .header(CONTENT_MD5, "7ac66c0f148de9519b8bd264312c4d64")
            .body(())?
            .into_parts()
            .0;

        signer
            .sign_request(&test_context(), &mut req, Some(&credential), None)
            .await?;

        assert_eq!(
            req.headers[DATE], "Wed, 09 Nov 2016 14:26:58 GMT",
            "the Date header must match the signed timestamp"
        );
        assert_eq!(
            req.headers[AUTHORIZATION],
            "UPYUN operator123:YUaAZX+WNAcJdNGHS5SBlITME5A="
        );
        Ok(())
    }

    #[tokio::test]
    async fn omits_an_absent_content_md5() -> anyhow::Result<()> {
        let signer = RequestSigner::new().with_time(signing_time());
        let credential = Credential::new("operator123", "password123");
        let mut req = http::Request::get("https://v0.api.upyun.com/bucket/object.txt")
            .body(())?
            .into_parts()
            .0;

        signer
            .sign_request(&test_context(), &mut req, Some(&credential), None)
            .await?;

        assert_eq!(
            req.headers[AUTHORIZATION],
            "UPYUN operator123:Z+dxL3crZ5d1xQ79GDhvH9qyTdI="
        );
        Ok(())
    }

    #[tokio::test]
    async fn signs_the_wire_path_without_decoding_it() -> anyhow::Result<()> {
        let signer = RequestSigner::new().with_time(signing_time());
        let credential = Credential::new("operator123", "password123");
        let mut req = http::Request::get("https://v0.api.upyun.com/bucket/demo%20file.txt")
            .body(())?
            .into_parts()
            .0;

        signer
            .sign_request(&test_context(), &mut req, Some(&credential), None)
            .await?;

        assert_eq!(
            req.headers[AUTHORIZATION],
            "UPYUN operator123:jrQiupCLfC0gKVOqBhCjrMTR1UQ="
        );
        Ok(())
    }

    #[tokio::test]
    async fn signs_with_a_unicode_secret() -> anyhow::Result<()> {
        let signer = RequestSigner::new().with_time(signing_time());
        let credential = Credential::new("operator123", "密码密码密码");
        let mut req = http::Request::get("https://v0.api.upyun.com/upyun-temp/unicode.txt")
            .body(())?
            .into_parts()
            .0;

        signer
            .sign_request(&test_context(), &mut req, Some(&credential), None)
            .await?;

        assert_eq!(
            req.headers[AUTHORIZATION],
            "UPYUN operator123:/rFZWp4VVax46218SmJaVrVT9pE="
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_credentials_before_signing() -> anyhow::Result<()> {
        let signer = RequestSigner::new().with_time(signing_time());

        for credential in [
            Credential::default(),
            Credential::new("operator123", "password123").with_bucket(""),
        ] {
            let mut req = http::Request::get("https://v0.api.upyun.com/")
                .body(())?
                .into_parts()
                .0;
            let original = req.clone();

            let err = signer
                .sign_request(&Context::new(), &mut req, Some(&credential), None)
                .await
                .expect_err("invalid credentials must not reach signing");

            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            assert_eq!(req.uri, original.uri);
            assert_eq!(req.headers, original.headers);
        }
        Ok(())
    }

    #[derive(Debug)]
    struct MissingMd5Provider;

    impl CryptoProvider for MissingMd5Provider {
        fn sha1(&self, _: &[u8]) -> Result<[u8; 20]> {
            Ok([0; 20])
        }

        fn sha256(&self, _: &[u8]) -> Result<[u8; 32]> {
            Ok([0; 32])
        }

        fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> Result<[u8; 20]> {
            Ok([0; 20])
        }

        fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> Result<[u8; 32]> {
            Ok([0; 32])
        }
    }

    #[tokio::test]
    async fn fails_closed_when_md5_is_unavailable() -> anyhow::Result<()> {
        let signer = RequestSigner::new().with_time(signing_time());
        let credential = Credential::new("operator123", "password123");
        let mut req = http::Request::put("https://v0.api.upyun.com/upyun-temp/demo.jpg")
            .body(())?
            .into_parts()
            .0;
        let original = req.clone();

        let err = signer
            .sign_request(
                &Context::new().with_crypto(MissingMd5Provider),
                &mut req,
                Some(&credential),
                None,
            )
            .await
            .expect_err("a provider without MD5 must not sign");

        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert_eq!(req.uri, original.uri);
        assert_eq!(req.headers, original.headers);
        Ok(())
    }
}
