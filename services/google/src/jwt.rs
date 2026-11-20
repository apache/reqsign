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
    use serde::Serialize;

    const RSA_PKCS8: &[u8] = include_bytes!("../tests/fixtures/rsa_pkcs8.pem");
    const RSA_PKCS1: &[u8] = include_bytes!("../tests/fixtures/rsa_pkcs1.pem");
    // Fixed RS256 vector for the fixture key. The signature was cross-checked
    // with an independent RSA implementation before being recorded here.
    const EXPECTED_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzaWduZXJAZXhhbXBsZS5jb20iLCJzY29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvZGV2c3RvcmFnZS5yZWFkX3dyaXRlIiwiYXVkIjoiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLCJleHAiOjEsImlhdCI6MH0.dbgmn-wCYhHG77IXPjkokZQ6c5zh9d5aZNm9x7VuBYKh3xHNyg33416VjStvOu9f5dFgJOar_V6PR_zkdP7uEUz9ZY_sd1G6Yz3bomInSYpHm05dHRr-b5Sa0MiqWusmfl-8LYJQe_hVi6PXPM0cMFUi1OyAQslUm74_HbJGnsTtrUb7hdsX6KBfDzaUB414sMjYoai8rsyqbqUrq1-7aDnmAVzPmMtBzANdncj3the_yD_-r1hPK5cbj0roz-DtrDHzrIacikeYnu26-RY2xLNB-qiwzlHbGuMAOTLfBsnu3t9-E-aFO9bf8pkKLWl38vsAhHqMxcYo6BxbQpkghg";

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

        for pem in [RSA_PKCS8, RSA_PKCS1] {
            let jwt =
                encode_rs256(&provider, &header, &claims, pem).expect("JWT encoding must succeed");
            assert_eq!(jwt, EXPECTED_JWT);
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
