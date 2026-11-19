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

//! JWT encoding helpers.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use crate::crypto;
use crate::{Error, Result};

/// Encode a JWS compact JWT using an RSA private key in PKCS#8 or PKCS#1 PEM
/// format.
///
/// RS256 is RSA PKCS#1 v1.5 with SHA-256. The caller owns the JWT header and
/// claims shape so service-specific fields such as `x5t` stay service-local.
/// Signing is performed by the installed [`crypto::CryptoProvider`].
pub fn encode_rs256_pem<H, C>(header: &H, claims: &C, private_key_pem: &[u8]) -> Result<String>
where
    H: Serialize,
    C: Serialize,
{
    let encoded_header = encode_json(header)?;
    let encoded_claims = encode_json(claims)?;
    let signing_input = format!("{encoded_header}.{encoded_claims}");

    let signature = crypto::require_default()?
        .rsa_pkcs1v15_sha256_sign(private_key_pem, signing_input.as_bytes())?;

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn encode_json<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    let json = serde_json::to_vec(value)
        .map_err(|e| Error::unexpected("failed to serialize JWT JSON").with_source(e))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::install_default;
    use crate::test_support::TestCryptoProvider;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    use rsa::rand_core::OsRng;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;
    use serde_json::json;

    #[derive(Serialize)]
    struct Header<'a> {
        alg: &'a str,
        typ: &'a str,
        x5t: &'a str,
    }

    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: u64,
    }

    fn private_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 1024).expect("test RSA key generation must work")
    }

    fn verify(header: &Header<'_>, claims: &Claims<'_>, jwt: &str, pem: &[u8]) {
        let parts = jwt.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);

        let header_value: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .expect("JWT header must decode"),
        )
        .expect("JWT header must be JSON");
        assert_eq!(
            header_value,
            json!({
                "alg": header.alg,
                "typ": header.typ,
                "x5t": header.x5t
            })
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(parts[1])
                .expect("JWT claims must decode"),
            serde_json::to_vec(claims).expect("claims must serialize")
        );

        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("JWT signature must decode");
        let signature = Signature::try_from(signature.as_slice())
            .expect("JWT signature must be a PKCS#1 v1.5 signature");
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(pem).expect("PEM must be UTF-8"))
                .or_else(|_| {
                    RsaPrivateKey::from_pkcs1_pem(
                        std::str::from_utf8(pem).expect("PEM must be UTF-8"),
                    )
                })
                .expect("test PEM must parse");
        let verifying_key = VerifyingKey::<Sha256>::new(private_key.to_public_key());
        verifying_key
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("JWT signature must verify");
    }

    #[test]
    fn encode_rs256_pem_keeps_jws_shape_and_verifiable_signature() {
        let _ = install_default(TestCryptoProvider);
        let private_key = private_key();
        let header = Header {
            alg: "RS256",
            typ: "JWT",
            x5t: "thumbprint",
        };
        let claims = Claims {
            iss: "client",
            sub: "client",
            aud: "https://example.com/token",
            exp: 1,
        };

        for pem in [
            private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("test key must encode as PKCS#8"),
            private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("test key must encode as PKCS#1"),
        ] {
            let jwt = encode_rs256_pem(&header, &claims, pem.as_bytes())
                .expect("JWT encoding must succeed");
            verify(&header, &claims, &jwt, pem.as_bytes());
        }
    }

    #[test]
    fn encode_rs256_pem_rejects_malformed_key_material() {
        let _ = install_default(TestCryptoProvider);
        let err = encode_rs256_pem(
            &Header {
                alg: "RS256",
                typ: "JWT",
                x5t: "thumbprint",
            },
            &Claims {
                iss: "client",
                sub: "client",
                aud: "https://example.com/token",
                exp: 1,
            },
            b"not a private key",
        )
        .expect_err("malformed private key must fail");

        assert_eq!(err.kind(), crate::ErrorKind::CredentialInvalid);
    }
}
