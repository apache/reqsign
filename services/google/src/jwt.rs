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

//! Private RS256 JWS formatting for Google service-account exchanges.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::{Error, Result};
use serde::Serialize;

/// Encode a compact RS256 JWS using the selected provider.
pub(crate) fn encode_rs256<H, C>(
    provider: &dyn CryptoProvider,
    header: &H,
    claims: &C,
    private_key_pem: &[u8],
) -> Result<String>
where
    H: Serialize,
    C: Serialize,
{
    let encoded_header = encode_json(header)?;
    let encoded_claims = encode_json(claims)?;
    let signing_input = format!("{encoded_header}.{encoded_claims}");

    let signature = provider.rsa_pkcs1v15_sha256_sign(private_key_pem, signing_input.as_bytes())?;

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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use reqsign_core::ErrorKind;
    use reqsign_crypto_rustcrypto::RustCryptoProvider;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Header<'a> {
        alg: &'a str,
        typ: &'a str,
    }

    #[derive(Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        scope: &'a str,
        aud: &'a str,
        exp: u64,
        iat: u64,
    }

    fn private_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut OsRng, 1024).expect("test RSA key generation must work")
    }

    fn decode_json(segment: &str) -> serde_json::Value {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(segment)
                .expect("JWS segment must decode"),
        )
        .expect("JWS segment must be JSON")
    }

    #[test]
    fn formats_three_unpadded_verifiable_segments_for_both_pem_formats() {
        let key = private_key();
        let provider = RustCryptoProvider::new();
        let header = Header {
            alg: "RS256",
            typ: "JWT",
        };
        let claims = Claims {
            iss: "signer@example.com",
            scope: "https://www.googleapis.com/auth/devstorage.read_write",
            aud: "https://oauth2.googleapis.com/token",
            exp: 1,
            iat: 0,
        };

        for pem in [
            key.to_pkcs8_pem(LineEnding::LF)
                .expect("test key must encode as PKCS#8"),
            key.to_pkcs1_pem(LineEnding::LF)
                .expect("test key must encode as PKCS#1"),
        ] {
            let jwt = encode_rs256(&provider, &header, &claims, pem.as_bytes())
                .expect("JWT encoding must succeed");
            let parts = jwt.split('.').collect::<Vec<_>>();
            assert_eq!(parts.len(), 3);
            assert!(parts.iter().all(|part| !part.contains('=')));
            assert_eq!(
                decode_json(parts[0]),
                serde_json::json!({"alg": "RS256", "typ": "JWT"})
            );
            assert_eq!(
                decode_json(parts[1]),
                serde_json::json!({
                    "iss": "signer@example.com",
                    "scope": "https://www.googleapis.com/auth/devstorage.read_write",
                    "aud": "https://oauth2.googleapis.com/token",
                    "exp": 1,
                    "iat": 0
                })
            );

            let signature = URL_SAFE_NO_PAD
                .decode(parts[2])
                .expect("signature must decode");
            let signature =
                Signature::try_from(signature.as_slice()).expect("signature must parse");
            let verifying_key = VerifyingKey::<Sha256>::new(key.to_public_key());
            verifying_key
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                .expect("signature must verify");
        }
    }

    #[test]
    fn malformed_private_key_is_credential_invalid() {
        let provider = RustCryptoProvider::new();
        let err = encode_rs256(
            &provider,
            &Header {
                alg: "RS256",
                typ: "JWT",
            },
            &Claims {
                iss: "signer@example.com",
                scope: "scope",
                aud: "audience",
                exp: 1,
                iat: 0,
            },
            b"not a private key",
        )
        .expect_err("malformed key must fail");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
    }
}
