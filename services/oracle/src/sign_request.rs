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
use base64::{Engine as _, engine::general_purpose};
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, DATE};
use http::request::Parts;
use http::{HeaderMap, HeaderName, Method};
use log::debug;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential, SigningRequest};
use std::fmt::Write;
use std::time::Duration;

const X_CONTENT_SHA256: &str = "x-content-sha256";

/// RequestSigner that implements Oracle Cloud Infrastructure API signing.
///
/// API private key files may contain unencrypted PKCS#1 or PKCS#8 PEM keys.
///
/// The signing string always covers `date`, `(request-target)`, and `host`.
/// For `POST`, `PUT`, and `PATCH` requests it also covers `content-length`,
/// `content-type`, and `x-content-sha256` when the caller supplies them.
/// Reqsign does not read the request body or compute `x-content-sha256`; callers
/// must prepare the body headers before signing. Other methods keep the bodyless
/// signing contract, and Object Storage `PutObject` and `UploadPart` PUT requests
/// may omit body metadata as OCI permits.
///
/// - [Oracle Cloud Infrastructure API Signing](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm)
#[derive(Debug)]
pub struct RequestSigner {}

impl RequestSigner {
    /// Create a new builder for Oracle signer.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RequestSigner {
    fn default() -> Self {
        Self::new()
    }
}
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
        ctx: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        _expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };

        let now = Timestamp::now();
        if !cred.is_valid_at(now) {
            return Err(reqsign_core::Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }

        let request_target = req
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_string();
        let mut signing_req = SigningRequest::build(req)?;

        // Construct string to sign
        let (string_to_sign, signed_headers) =
            build_signing_input(&signing_req, &request_target, now)?;

        debug!("string to sign: {}", string_to_sign);

        // Read private key from file. Both unencrypted PKCS#8 and PKCS#1 PEM
        // keys are accepted by the configured CryptoProvider.
        let private_key_content = ctx.file_read_as_string(&cred.key_file).await?;
        let provider = ctx.crypto_provider()?;
        let signature = provider
            .rsa_pkcs1v15_sha256_sign(private_key_content.as_bytes(), string_to_sign.as_bytes())?;
        let encoded_signature = general_purpose::STANDARD.encode(signature);

        // Set headers
        signing_req
            .headers
            .insert(DATE, now.format_http_date().parse()?);

        // Build authorization header
        let mut auth_value = String::new();
        write!(auth_value, "Signature version=\"1\",")?;
        write!(auth_value, "headers=\"{signed_headers}\",")?;
        write!(
            auth_value,
            "keyId=\"{}/{}/{}\",",
            cred.tenancy, cred.user, cred.fingerprint
        )?;
        write!(auth_value, "algorithm=\"rsa-sha256\",")?;
        write!(auth_value, "signature=\"{encoded_signature}\"")?;

        signing_req
            .headers
            .insert(AUTHORIZATION, auth_value.parse()?);

        signing_req.apply(req)
    }
}

fn build_signing_input(
    request: &SigningRequest,
    request_target: &str,
    now: Timestamp,
) -> Result<(String, String)> {
    let mut lines = vec![
        format!("date: {}", now.format_http_date()),
        format!(
            "(request-target): {} {}",
            request.method.as_str().to_lowercase(),
            request_target
        ),
        format!("host: {}", request.authority),
    ];
    let mut signed_headers = String::from("date (request-target) host");

    if method_carries_body(&request.method) {
        let body_headers = [
            CONTENT_LENGTH,
            CONTENT_TYPE,
            HeaderName::from_static(X_CONTENT_SHA256),
        ];
        for name in body_headers {
            let Some(value) = single_header_value(&request.headers, &name)? else {
                continue;
            };
            lines.push(format!("{}: {}", name.as_str(), value));
            signed_headers.push(' ');
            signed_headers.push_str(name.as_str());
        }
    }

    Ok((lines.join("\n"), signed_headers))
}

fn method_carries_body(method: &Method) -> bool {
    method == Method::POST || method == Method::PUT || method == Method::PATCH
}

fn single_header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::request_invalid(format!(
            "request contains multiple values for signed header {}",
            name.as_str()
        )));
    }

    value.to_str().map(Some).map_err(|err| {
        Error::request_invalid(format!(
            "request header {} is not valid ASCII",
            name.as_str()
        ))
        .with_source(err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqsign_core::FileRead;

    const RAW_QUERY: &str = "slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

    #[derive(Debug)]
    struct StaticFileRead(Vec<u8>);

    impl FileRead for StaticFileRead {
        async fn file_read(&self, _path: &str) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    fn credential() -> Credential {
        Credential {
            tenancy: "tenancy".to_string(),
            user: "user".to_string(),
            key_file: "key.pem".to_string(),
            fingerprint: "fingerprint".to_string(),
            expires_in: None,
        }
    }

    #[tokio::test]
    async fn request_target_and_wire_uri_preserve_raw_query() -> Result<()> {
        let original_uri = format!("https://example.com/object%2Fname?{RAW_QUERY}");
        let mut canonical_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        let signing_req = SigningRequest::build(&mut canonical_parts)?;
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let (string_to_sign, signed_headers) = build_signing_input(
            &signing_req,
            canonical_parts.uri.path_and_query().unwrap().as_str(),
            now,
        )?;
        assert_eq!(signed_headers, "date (request-target) host");
        assert!(
            string_to_sign.contains(&format!("(request-target): get /object%2Fname?{RAW_QUERY}"))
        );

        let ctx = crate::test_context().with_file_read(StaticFileRead(
            include_str!("../tests/fixtures/rsa-2048-pkcs8.pem")
                .as_bytes()
                .to_vec(),
        ));
        let mut parts = http::Request::get(&original_uri).body(())?.into_parts().0;

        RequestSigner::new()
            .sign_request(&ctx, &mut parts, Some(&credential()), None)
            .await?;

        assert_eq!(parts.uri.to_string(), original_uri);
        assert!(parts.headers.contains_key(AUTHORIZATION));
        Ok(())
    }

    #[tokio::test]
    async fn invalid_private_key_leaves_request_unchanged() -> Result<()> {
        let original_uri = format!("https://example.com/object?{RAW_QUERY}");
        let ctx = crate::test_context().with_file_read(StaticFileRead(b"invalid".to_vec()));
        let mut parts = http::Request::get(&original_uri)
            .header("x-original", "value")
            .body(())?
            .into_parts()
            .0;
        let original = parts.clone();

        assert!(
            RequestSigner::new()
                .sign_request(&ctx, &mut parts, Some(&credential()), None)
                .await
                .is_err()
        );
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
        Ok(())
    }
}
