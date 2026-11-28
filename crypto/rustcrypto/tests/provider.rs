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
#[cfg(feature = "p256")]
use p256::ecdsa::signature::Verifier;
#[cfg(feature = "p256")]
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use reqsign_core::crypto::{CryptoProvider, get_default};
use reqsign_core::{ErrorKind, Result};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
#[cfg(feature = "rsa")]
use rsa::PrivateKey;
#[cfg(feature = "rsa")]
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
#[cfg(feature = "rsa")]
use rsa::pkcs8::DecodePrivateKey;
#[cfg(feature = "rsa")]
use rsa::sha2::Sha256 as RsaSha256;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[cfg(feature = "rsa")]
const RSA_PKCS8: &[u8] = include_bytes!("fixtures/rsa_pkcs8.pem");
#[cfg(feature = "rsa")]
const RSA_PKCS1: &[u8] = include_bytes!("fixtures/rsa_pkcs1.pem");
#[cfg(feature = "rsa")]
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
fn md5_matches_published_vectors() {
    let provider = provider();

    for (input, expected) in [
        (&b""[..], "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ] {
        assert_eq!(
            hex(&provider.md5(input).expect("MD5 must succeed")),
            expected
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
fn hmac_sha512_matches_published_vectors() {
    let provider = provider();
    let key_25: Vec<u8> = (1u8..=25).collect();
    let long_key = [0xaa; 131];
    let long_data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

    // The first case covers an empty key; the rest are RFC 4231 test cases.
    let cases: &[(&[u8], &[u8], &str)] = &[
        (
            &[],
            b"",
            "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
        ),
        (
            &[0x0b; 20],
            b"Hi There",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        ),
        (
            &key_25,
            &[0xcd; 50],
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        ),
        (
            &long_key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        ),
        (
            &long_key,
            long_data,
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        ),
    ];

    for (key, input, expected) in cases {
        assert_eq!(
            hex(&provider
                .hmac_sha512(key, input)
                .expect("HMAC-SHA512 must succeed")),
            *expected
        );
    }
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_signs_both_pkcs8_and_pkcs1_pem() {
    let provider = provider();
    let public_key = PrivateKey::from_pkcs8_pem(std::str::from_utf8(RSA_PKCS8).unwrap())
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
            rsa::signature::Verifier::verify(&verifying_key, message, &signature)
                .expect("signature must verify");
        }
    }
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_pss_signatures_with_fresh_salt_verify_for_both_pem_formats() {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let provider = provider();
    let public_key = PrivateKey::from_pkcs8_pem(std::str::from_utf8(RSA_PKCS8).unwrap())
        .expect("test key must parse")
        .to_public_key();
    let verifier = VerifyingKey::<RsaSha256>::new_with_salt_len(public_key, 32);
    let message = b"PS256 interoperability test";
    let sign = |pem| {
        provider
            .rsa_pss_sha256_sign(pem, message)
            .expect("RSA-PSS signing must succeed")
    };
    let signatures = [sign(RSA_PKCS8), sign(RSA_PKCS1)];
    assert_ne!(signatures[0], signatures[1]);
    for bytes in signatures {
        assert_eq!(bytes.len(), 256);
        let signature = Signature::try_from(bytes.as_slice()).expect("signature must parse");
        verifier
            .verify(message, &signature)
            .expect("PS256 signature must verify");
    }
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_signature_is_deterministic_for_both_pem_formats() {
    const EXPECTED: &str = "6be8116e69987bb4dd2048520ab3ac580e5f4f0c872d6f7b6223e24dc58d86037b524e8fadd8b608ef97f0f44ab6011c05275cefb2fb43deb0bb9569634aac7ff0ae3e019979a15c455a4c1bc6d0b722bb5d17bfb9e4d9886e32678afa048e3af03f5c37c33d9dfab9229edf5ae9140c2440ca18a92a8d47e3994e04e4171b375c556c3c14632642510c1b7f2e464b1bf765a1e795490391653d384f25ed7da415709197da7b81f3ba5d8c23b9594d7e420ee1142cefe70664bd63fa3c2f84ac97884d278a4c4ef5ee3e0427601a76fbe20880231a00771f997151ab77d2d8e3260e397ba4c1f08f697ae80cd8fab9ff4eeaa20d4424e4c9cc793a35041e526d";

    let provider = provider();
    for pem in [RSA_PKCS8, RSA_PKCS1] {
        let signature = provider
            .rsa_pkcs1v15_sha256_sign(pem, b"reqsign-rsa-0.10-vector")
            .expect("RSA signing must succeed");
        assert_eq!(hex(&signature), EXPECTED);
    }
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_rejects_malformed_and_non_rsa_keys() {
    let provider = provider();
    for key in [&b"not a private key"[..], EC_PKCS8] {
        assert_eq!(
            provider
                .rsa_pkcs1v15_sha256_sign(key, b"message")
                .expect_err("invalid key must fail RS256 signing")
                .kind(),
            ErrorKind::CredentialInvalid
        );
        assert_eq!(
            provider
                .rsa_pss_sha256_sign(key, b"message")
                .expect_err("invalid key must fail PS256 signing")
                .kind(),
            ErrorKind::CredentialInvalid
        );
    }
}

#[cfg(feature = "p256")]
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

#[cfg(feature = "p256")]
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

#[cfg(feature = "aes-gcm")]
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

#[cfg(feature = "aes-gcm")]
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

#[cfg(feature = "aes-gcm")]
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

#[cfg(not(feature = "rsa"))]
#[test]
fn rsa_reports_the_missing_feature() {
    let provider = provider();
    for result in [
        provider.rsa_pkcs1v15_sha256_sign(b"pem", b"message"),
        provider.rsa_pss_sha256_sign(b"pem", b"message"),
    ] {
        let err = result.expect_err("RSA must be unavailable without its feature");
        assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
        assert!(err.to_string().contains("`rsa`"), "{err}");
    }
}

#[cfg(not(feature = "p256"))]
#[test]
fn ecdsa_reports_the_missing_feature() {
    let err = provider()
        .ecdsa_p256_sha256_sign(&[1; 32], b"message")
        .expect_err("ECDSA P-256 must be unavailable without its feature");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(err.to_string().contains("`p256`"), "{err}");
}

#[cfg(not(feature = "aes-gcm"))]
#[test]
fn aes_gcm_reports_the_missing_feature() {
    let err = provider()
        .aes_gcm_encrypt(&[0; 16], &[0; 12], b"", b"message")
        .expect_err("AES-GCM must be unavailable without its feature");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(err.to_string().contains("`aes-gcm`"), "{err}");
}

#[cfg(not(feature = "aes-gcm"))]
#[test]
fn random_generation_reports_the_missing_aes_gcm_feature() {
    let mut dest = [0; 8];
    let err = provider()
        .fill_random(&mut dest)
        .expect_err("random generation must be unavailable without the aes-gcm feature");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(err.to_string().contains("`aes-gcm`"), "{err}");
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
            .md5(b"message")
            .expect_err("MD5 must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
    assert_eq!(
        provider
            .hmac_sha512(b"key", b"message")
            .expect_err("HMAC-SHA512 must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
    assert_eq!(
        provider
            .rsa_pkcs1v15_sha256_sign(b"pem", b"message")
            .expect_err("RSA must be unsupported")
            .kind(),
        ErrorKind::ConfigInvalid
    );
    let err = provider
        .rsa_pss_sha256_sign(b"pem", b"message")
        .expect_err("RSA-PSS must be unsupported");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(
        err.to_string().contains("does not support RSA-PSS"),
        "{err}"
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
