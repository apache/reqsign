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
use reqsign_core::crypto::{CryptoProvider, get_default};
use reqsign_core::{ErrorKind, Result};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::Verifier as _;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const RSA_PKCS8: &[u8] = include_bytes!("fixtures/rsa_pkcs8.pem");
const RSA_PKCS1: &[u8] = include_bytes!("fixtures/rsa_pkcs1.pem");
const EC_PKCS8: &[u8] = include_bytes!("fixtures/ec_p256_pkcs8.pem");

fn provider() -> RustCryptoProvider {
    RustCryptoProvider::new()
}

fn install_provider() {
    let _ = RustCryptoProvider::install_default();
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[test]
fn installs_one_process_wide_provider() {
    install_provider();
    assert!(get_default().is_some());
    assert!(
        RustCryptoProvider::install_default().is_err(),
        "a second installation must be rejected"
    );
}

#[test]
fn hashes_delegate_to_the_expected_algorithms() {
    let provider = provider();
    let large_input = vec![b'a'; 1_000_000];

    for input in [&b""[..], b"abc", large_input.as_slice()] {
        let expected_sha1: [u8; 20] = Sha1::digest(input).into();
        assert_eq!(
            provider.sha1(input).expect("SHA-1 must succeed"),
            expected_sha1
        );

        let expected_sha256: [u8; 32] = Sha256::digest(input).into();
        assert_eq!(
            provider.sha256(input).expect("SHA-256 must succeed"),
            expected_sha256
        );
    }
}

#[test]
fn hmac_handles_block_boundaries_without_changing_key_or_input() {
    let provider = provider();
    let input = b"POST /object?uploadId=example HTTP/1.1";

    for key in [
        &b""[..],
        &b"k"[..],
        &[0u8; 64][..],
        &[0u8; 65][..],
        &[0xaa; 80][..],
        &[0xaa; 131][..],
    ] {
        assert_eq!(
            provider
                .hmac_sha1(key, input)
                .expect("HMAC-SHA1 must succeed"),
            reference_hmac_sha1(key, input)
        );
        assert_eq!(
            provider
                .hmac_sha256(key, input)
                .expect("HMAC-SHA256 must succeed"),
            reference_hmac_sha256(key, input)
        );
    }
}

fn reference_hmac_sha1(key: &[u8], input: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn reference_hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

#[test]
fn rsa_signs_both_pkcs8_and_pkcs1_pem() {
    let provider = provider();
    let public_key = RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(RSA_PKCS8).unwrap())
        .expect("test key must parse")
        .to_public_key();
    let verifying_key = RsaVerifyingKey::<RsaSha256>::new(public_key);

    let large_message = vec![b'x'; 100_000];
    for message in [&b""[..], b"message", large_message.as_slice()] {
        for pem in [RSA_PKCS8, RSA_PKCS1] {
            let signature = provider
                .rsa_pkcs1v15_sha256_sign(pem, message)
                .expect("RSA signing must succeed");
            assert_eq!(signature.len(), 256);
            let signature =
                RsaSignature::try_from(signature.as_slice()).expect("signature must parse");
            verifying_key
                .verify(message, &signature)
                .expect("signature must verify");
        }
    }
}

#[test]
fn rsa_rejects_malformed_and_non_rsa_keys() {
    let provider = provider();
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
}

#[test]
fn ecdsa_signature_verifies_with_p256() {
    let provider = provider();
    let scalar = [7u8; 32];
    let signing_key = SigningKey::from_slice(&scalar).expect("test scalar must be valid");
    let verifying_key = VerifyingKey::from(&signing_key);

    let large_message = vec![b'x'; 100_000];
    for message in [&b""[..], b"message", large_message.as_slice()] {
        let signature = provider
            .ecdsa_p256_sha256_sign(&scalar, message)
            .expect("ECDSA signing must succeed");
        let signature = Signature::from_der(&signature).expect("signature must be DER");
        verifying_key
            .verify(message, &signature)
            .expect("signature must verify");
    }
}

#[test]
fn ecdsa_rejects_invalid_scalars() {
    let provider = provider();
    let order = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        .expect("order must decode");
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
}

#[test]
fn aes_gcm_matches_nist_vectors() {
    let provider = provider();

    assert_eq!(
        hex(&provider
            .aes_gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", b"")
            .expect("AES-128-GCM must succeed")),
        "58e2fccefa7e3061367f1d57a4e7455a"
    );
    assert_eq!(
        hex(&provider
            .aes_gcm_encrypt(&[0u8; 16], &[0u8; 12], b"", &[0u8; 16])
            .expect("AES-128-GCM must succeed")),
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    );
    assert_eq!(
        hex(&provider
            .aes_gcm_encrypt(&[0u8; 32], &[0u8; 12], b"", b"")
            .expect("AES-256-GCM must succeed")),
        "530f8afbc74536b9a963b4f1c4cb738b"
    );

    let key = hex::decode("feffe9928665731c6d6a8f9467308308").expect("key must decode");
    let nonce: [u8; 12] = hex::decode("cafebabefacedbaddecaf888")
        .expect("nonce must decode")
        .try_into()
        .expect("nonce must be 12 bytes");
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    )
    .expect("plaintext must decode");
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("aad must decode");
    assert_eq!(
        hex(&provider
            .aes_gcm_encrypt(&key, &nonce, &aad, &plaintext)
            .expect("AES-128-GCM with AAD must succeed")),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"
    );
}

#[test]
fn aes_gcm_rejects_invalid_key_lengths() {
    let provider = provider();
    for key in [&b""[..], &[0u8; 15][..], &[0u8; 31][..], &[0u8; 33][..]] {
        assert_eq!(
            provider
                .aes_gcm_encrypt(key, &[0u8; 12], b"", b"message")
                .expect_err("invalid key length must fail")
                .kind(),
            ErrorKind::CredentialInvalid
        );
    }
}

#[test]
fn fill_random_produces_distinct_nonzero_bytes() {
    let provider = provider();
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

#[derive(Debug)]
struct MinimalProvider;

impl CryptoProvider for MinimalProvider {
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

#[test]
fn minimal_provider_reports_unsupported_operations_as_config_invalid() {
    let provider = MinimalProvider;
    assert_eq!(
        provider
            .rsa_pkcs1v15_sha256_sign(b"pem", b"message")
            .expect_err("RSA must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
    assert_eq!(
        provider
            .ecdsa_p256_sha256_sign(&[1; 32], b"message")
            .expect_err("ECDSA must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
    assert_eq!(
        provider
            .aes_gcm_encrypt(&[0; 16], &[0; 12], b"", b"message")
            .expect_err("AES-GCM must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
    assert_eq!(
        provider
            .fill_random(&mut [0; 8])
            .expect_err("random must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
}
