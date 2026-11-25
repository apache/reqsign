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

#![allow(dead_code)]

use std::sync::Mutex;

use reqsign_core::crypto::CryptoProvider;
use reqsign_core::{Error, ErrorKind, Result};

const SHA1_INPUT: &[u8] = b"marker sha1 input";
const SHA256_INPUT: &[u8] = b"marker sha256 input";
const MD5_INPUT: &[u8] = b"marker md5 input";
const HMAC_SHA1_KEY: &[u8] = b"marker hmac-sha1 key";
const HMAC_SHA1_INPUT: &[u8] = b"marker hmac-sha1 input";
const HMAC_SHA256_KEY: &[u8] = b"marker hmac-sha256 key";
const HMAC_SHA256_INPUT: &[u8] = b"marker hmac-sha256 input";
const HMAC_SHA512_KEY: &[u8] = b"marker hmac-sha512 key";
const HMAC_SHA512_INPUT: &[u8] = b"marker hmac-sha512 input";
const RSA_KEY: &[u8] = b"marker rsa key";
const RSA_MESSAGE: &[u8] = b"marker rsa message";
const ECDSA_KEY: [u8; 32] = [0x42; 32];
const ECDSA_MESSAGE: &[u8] = b"marker ecdsa message";
const AES_KEY: &[u8] = b"marker-aes-key16";
const AES_NONCE: &[u8; 12] = b"marker nonce";
const AES_AAD: &[u8] = b"marker aad";
const AES_PLAINTEXT: &[u8] = b"marker plaintext";
const RANDOM_LEN: usize = 13;

/// Every method declared by [`CryptoProvider`], in declaration order.
pub const ALL_CRYPTO_METHODS: &[&str] = &[
    "sha1",
    "sha256",
    "md5",
    "hmac_sha1",
    "hmac_sha256",
    "hmac_sha512",
    "rsa_pkcs1v15_sha256_sign",
    "ecdsa_p256_sha256_sign",
    "aes_gcm_encrypt",
    "fill_random",
];

/// Provider that overrides every [`CryptoProvider`] method and records calls.
///
/// Each method checks that its arguments arrived unchanged and returns a value
/// unique to that method, so a default implementation is distinguishable from a
/// forwarded call.
#[derive(Debug, Default)]
pub struct MarkerProvider {
    calls: Mutex<Vec<&'static str>>,
}

impl MarkerProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recorded_calls(&self) -> Vec<&'static str> {
        self.calls
            .lock()
            .expect("marker call log must not be poisoned")
            .clone()
    }

    fn record(&self, method: &'static str) {
        self.calls
            .lock()
            .expect("marker call log must not be poisoned")
            .push(method);
    }
}

impl CryptoProvider for MarkerProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        self.record("sha1");
        assert_eq!(input, SHA1_INPUT, "sha1 input must be forwarded");
        Ok([1; 20])
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        self.record("sha256");
        assert_eq!(input, SHA256_INPUT, "sha256 input must be forwarded");
        Ok([2; 32])
    }

    fn md5(&self, input: &[u8]) -> Result<[u8; 16]> {
        self.record("md5");
        assert_eq!(input, MD5_INPUT, "md5 input must be forwarded");
        Err(Error::config_invalid("marker provider rejected MD5"))
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        self.record("hmac_sha1");
        assert_eq!(key, HMAC_SHA1_KEY, "HMAC-SHA1 key must be forwarded");
        assert_eq!(input, HMAC_SHA1_INPUT, "HMAC-SHA1 input must be forwarded");
        Ok([4; 20])
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        self.record("hmac_sha256");
        assert_eq!(key, HMAC_SHA256_KEY, "HMAC-SHA256 key must be forwarded");
        assert_eq!(
            input, HMAC_SHA256_INPUT,
            "HMAC-SHA256 input must be forwarded"
        );
        Ok([5; 32])
    }

    fn hmac_sha512(&self, key: &[u8], input: &[u8]) -> Result<[u8; 64]> {
        self.record("hmac_sha512");
        assert_eq!(key, HMAC_SHA512_KEY, "HMAC-SHA512 key must be forwarded");
        assert_eq!(
            input, HMAC_SHA512_INPUT,
            "HMAC-SHA512 input must be forwarded"
        );
        Ok([6; 64])
    }

    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.record("rsa_pkcs1v15_sha256_sign");
        assert_eq!(private_key_pem, RSA_KEY, "RSA key must be forwarded");
        assert_eq!(message, RSA_MESSAGE, "RSA message must be forwarded");
        Ok(vec![7; 32])
    }

    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.record("ecdsa_p256_sha256_sign");
        assert_eq!(
            private_key_scalar, &ECDSA_KEY,
            "ECDSA scalar must be forwarded"
        );
        assert_eq!(message, ECDSA_MESSAGE, "ECDSA message must be forwarded");
        Ok(vec![8; 16])
    }

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.record("aes_gcm_encrypt");
        assert_eq!(key, AES_KEY, "AES key must be forwarded");
        assert_eq!(nonce, AES_NONCE, "AES nonce must be forwarded");
        assert_eq!(aad, AES_AAD, "AES AAD must be forwarded");
        assert_eq!(plaintext, AES_PLAINTEXT, "AES plaintext must be forwarded");
        Ok(vec![9; 20])
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
        self.record("fill_random");
        assert_eq!(
            dest.len(),
            RANDOM_LEN,
            "random destination length must match"
        );
        dest.fill(0xAB);
        Ok(())
    }
}

/// Call every [`CryptoProvider`] method and assert the exact marker results.
pub fn assert_all_forwarded<P: CryptoProvider + ?Sized>(provider: &P) {
    assert_eq!(
        provider.sha1(SHA1_INPUT).expect("sha1 must succeed"),
        [1; 20]
    );
    assert_eq!(
        provider.sha256(SHA256_INPUT).expect("sha256 must succeed"),
        [2; 32]
    );

    let err = provider
        .md5(MD5_INPUT)
        .expect_err("the marker provider must reject MD5");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(err.to_string(), "marker provider rejected MD5");

    assert_eq!(
        provider
            .hmac_sha1(HMAC_SHA1_KEY, HMAC_SHA1_INPUT)
            .expect("HMAC-SHA1 must succeed"),
        [4; 20]
    );
    assert_eq!(
        provider
            .hmac_sha256(HMAC_SHA256_KEY, HMAC_SHA256_INPUT)
            .expect("HMAC-SHA256 must succeed"),
        [5; 32]
    );
    assert_eq!(
        provider
            .hmac_sha512(HMAC_SHA512_KEY, HMAC_SHA512_INPUT)
            .expect("HMAC-SHA512 must succeed"),
        [6; 64]
    );
    assert_eq!(
        provider
            .rsa_pkcs1v15_sha256_sign(RSA_KEY, RSA_MESSAGE)
            .expect("RSA signing must succeed"),
        vec![7; 32]
    );
    assert_eq!(
        provider
            .ecdsa_p256_sha256_sign(&ECDSA_KEY, ECDSA_MESSAGE)
            .expect("ECDSA signing must succeed"),
        vec![8; 16]
    );
    assert_eq!(
        provider
            .aes_gcm_encrypt(AES_KEY, AES_NONCE, AES_AAD, AES_PLAINTEXT)
            .expect("AES-GCM must succeed"),
        vec![9; 20]
    );

    let mut random = [0u8; RANDOM_LEN];
    provider
        .fill_random(&mut random)
        .expect("random generation must succeed");
    assert_eq!(random, [0xAB; RANDOM_LEN]);
}
