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

use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use reqsign_aws_core::Credential;
use reqsign_aws_v4::RequestSigner;
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::{Context, ErrorKind, SignRequest};
use reqsign_crypto_boring::BoringCryptoProvider;
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use sha2::{Digest, Sha256};

const RSA_PKCS8: &[u8] = include_bytes!("fixtures/rsa_pkcs8.pem");
const RSA_PKCS1: &[u8] = include_bytes!("fixtures/rsa_pkcs1.pem");
const EC_PKCS8: &[u8] = include_bytes!("fixtures/ec_p256_pkcs8.pem");

fn boring() -> BoringCryptoProvider {
    BoringCryptoProvider::new()
}

fn rustcrypto() -> RustCryptoProvider {
    RustCryptoProvider::new()
}

fn install_boring() {
    let _ = BoringCryptoProvider::install_default();
}

#[test]
fn hashes_and_hmacs_match_rustcrypto() {
    let boring = boring();
    let rustcrypto = rustcrypto();

    for input in [&b""[..], b"abc", &[0u8; 65][..], &vec![b'x'; 100_000][..]] {
        assert_eq!(
            boring.sha1(input).expect("BoringSSL SHA-1 must succeed"),
            rustcrypto
                .sha1(input)
                .expect("RustCrypto SHA-1 must succeed")
        );
        assert_eq!(
            boring
                .sha256(input)
                .expect("BoringSSL SHA-256 must succeed"),
            rustcrypto
                .sha256(input)
                .expect("RustCrypto SHA-256 must succeed")
        );
    }

    for key in [
        &b""[..],
        &b"k"[..],
        &[0u8; 64][..],
        &[0u8; 65][..],
        &[0xaa; 131][..],
    ] {
        for input in [&b""[..], b"boundary message", &vec![b'x'; 100_000][..]] {
            assert_eq!(
                boring
                    .hmac_sha1(key, input)
                    .expect("BoringSSL HMAC-SHA1 must succeed"),
                rustcrypto
                    .hmac_sha1(key, input)
                    .expect("RustCrypto HMAC-SHA1 must succeed")
            );
            assert_eq!(
                boring
                    .hmac_sha256(key, input)
                    .expect("BoringSSL HMAC-SHA256 must succeed"),
                rustcrypto
                    .hmac_sha256(key, input)
                    .expect("RustCrypto HMAC-SHA256 must succeed")
            );
        }
    }
}

#[test]
fn rsa_signatures_match_rustcrypto_for_both_pem_formats() {
    let boring = boring();
    let rustcrypto = rustcrypto();

    for message in [&b""[..], b"message", &vec![b'x'; 100_000][..]] {
        for pem in [RSA_PKCS8, RSA_PKCS1] {
            assert_eq!(
                boring
                    .rsa_pkcs1v15_sha256_sign(pem, message)
                    .expect("BoringSSL RSA signing must succeed"),
                rustcrypto
                    .rsa_pkcs1v15_sha256_sign(pem, message)
                    .expect("RustCrypto RSA signing must succeed"),
                "RSA PKCS#1 v1.5 signatures must be byte-identical"
            );
        }
    }
}

#[test]
fn aes_gcm_output_matches_rustcrypto() {
    let boring = boring();
    let rustcrypto = rustcrypto();

    for key_len in [16, 32] {
        let key = vec![0x42; key_len];
        let nonce = [0x24; 12];
        for (aad, plaintext) in [
            (&b""[..], &b""[..]),
            (b"aad", b"message"),
            (b"", &[0u8; 128][..]),
            (b"header", &vec![b'p'; 10_000][..]),
        ] {
            assert_eq!(
                boring
                    .aes_gcm_encrypt(&key, &nonce, aad, plaintext)
                    .expect("BoringSSL AES-GCM must succeed"),
                rustcrypto
                    .aes_gcm_encrypt(&key, &nonce, aad, plaintext)
                    .expect("RustCrypto AES-GCM must succeed")
            );
        }
    }
}

#[test]
fn ecdsa_signature_verifies_across_backends() {
    let scalar = [7u8; 32];
    let signing_key = SigningKey::from_slice(&scalar).expect("test scalar must be valid");
    let verifying_key = VerifyingKey::from(&signing_key);

    for message in [&b""[..], b"message", &vec![b'x'; 100_000][..]] {
        let boring_signature = boring()
            .ecdsa_p256_sha256_sign(&scalar, message)
            .expect("BoringSSL ECDSA signing must succeed");
        let boring_signature =
            Signature::from_der(&boring_signature).expect("BoringSSL signature must be DER");
        verifying_key
            .verify(message, &boring_signature)
            .expect("BoringSSL signature must verify with p256");

        let rustcrypto_signature = rustcrypto()
            .ecdsa_p256_sha256_sign(&scalar, message)
            .expect("RustCrypto ECDSA signing must succeed");
        let rustcrypto_signature =
            Signature::from_der(&rustcrypto_signature).expect("RustCrypto signature must be DER");
        verifying_key
            .verify(message, &rustcrypto_signature)
            .expect("RustCrypto signature must verify with p256");
    }
}

#[test]
fn invalid_key_material_maps_to_credential_invalid() {
    let provider = boring();

    assert_eq!(
        provider
            .rsa_pkcs1v15_sha256_sign(b"not a private key", b"message")
            .expect_err("malformed key must fail")
            .kind(),
        ErrorKind::CredentialInvalid
    );
    assert_eq!(
        provider
            .rsa_pkcs1v15_sha256_sign(EC_PKCS8, b"message")
            .expect_err("non-RSA key must fail")
            .kind(),
        ErrorKind::CredentialInvalid
    );

    let order = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        .expect("P-256 order must decode");
    let mut order_bytes = [0u8; 32];
    order_bytes.copy_from_slice(&order);
    for scalar in [[0u8; 32], order_bytes, [0xffu8; 32]] {
        assert_eq!(
            provider
                .ecdsa_p256_sha256_sign(&scalar, b"message")
                .expect_err("invalid scalar must fail")
                .kind(),
            ErrorKind::CredentialInvalid
        );
    }

    for key in [&b""[..], &[0u8; 15][..], &[0u8; 31][..], &[0u8; 33][..]] {
        assert_eq!(
            provider
                .aes_gcm_encrypt(key, &[0u8; 12], b"", b"message")
                .expect_err("invalid AES key length must fail")
                .kind(),
            ErrorKind::CredentialInvalid
        );
    }
}

#[test]
fn fill_random_produces_distinct_nonzero_bytes() {
    let provider = boring();
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    provider
        .fill_random(&mut first)
        .expect("random must succeed");
    provider
        .fill_random(&mut second)
        .expect("random must succeed");
    assert_ne!(first, [0u8; 32]);
    assert_ne!(first, second);
    provider
        .fill_random(&mut [])
        .expect("filling an empty buffer must succeed");
}

#[tokio::test]
async fn aws_sigv4_end_to_end_matches_an_independent_hmac_implementation() {
    install_boring();

    let credential = Credential {
        access_key_id: "AKIDEXAMPLE".to_string(),
        secret_access_key: "test-secret-key".to_string(),
        session_token: None,
        expires_in: None,
    };
    let mut parts = http::Request::get("https://example.amazonaws.com/object")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    RequestSigner::new("s3", "test-region")
        .sign_request(&Context::new(), &mut parts, Some(&credential), None)
        .await
        .expect("AWS SigV4 signing must succeed");

    let date = parts.headers["x-amz-date"]
        .to_str()
        .expect("x-amz-date must be text");
    let canonical_request = format!(
        "GET\n/object\n\nhost:example.amazonaws.com\n\
         x-amz-content-sha256:UNSIGNED-PAYLOAD\n\
         x-amz-date:{date}\n\n\
         host;x-amz-content-sha256;x-amz-date\n\
         UNSIGNED-PAYLOAD"
    );
    let scope = format!("{}/{}/{}/aws4_request", &date[..8], "test-region", "s3");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let date_key = hmac_sha256(
        format!("AWS4{}", credential.secret_access_key).as_bytes(),
        &date.as_bytes()[..8],
    );
    let region_key = hmac_sha256(&date_key, b"test-region");
    let service_key = hmac_sha256(&region_key, b"s3");
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = parts.headers[http::header::AUTHORIZATION]
        .to_str()
        .expect("authorization must be text");
    assert!(
        authorization.ends_with(&format!("Signature={signature}")),
        "unexpected SigV4 authorization: {authorization}"
    );
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}
