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

use reqsign_core::crypto::CryptoProvider;
use reqsign_core::{Error, ErrorKind, Result};

const INPUT: &[u8] = b"marker input";
const KEY: &[u8] = b"marker key";
const ECDSA_SCALAR: [u8; 32] = [0x42; 32];
const AES_KEY: &[u8] = b"marker-aes-key16";
const AES_NONCE: &[u8; 12] = b"marker nonce";
const AES_AAD: &[u8] = b"marker aad";
const AES_PLAINTEXT: &[u8] = b"marker plaintext";
const RANDOM_LEN: usize = 13;
const MD5_ERROR: &str = "marker provider rejected MD5";

/// Provider that overrides every [`CryptoProvider`] method.
///
/// Each method rejects arguments that were not forwarded unchanged and returns
/// a value unique to that method, so a trait default is distinguishable from a
/// forwarded call.
#[derive(Debug)]
pub struct MarkerProvider;

impl CryptoProvider for MarkerProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        assert_eq!(input, INPUT, "sha1 input must be forwarded");
        Ok([1; 20])
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        assert_eq!(input, INPUT, "sha256 input must be forwarded");
        Ok([2; 32])
    }

    fn md5(&self, input: &[u8]) -> Result<[u8; 16]> {
        assert_eq!(input, INPUT, "md5 input must be forwarded");
        Err(Error::config_invalid(MD5_ERROR))
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        assert_eq!(key, KEY, "HMAC-SHA1 key must be forwarded");
        assert_eq!(input, INPUT, "HMAC-SHA1 input must be forwarded");
        Ok([4; 20])
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        assert_eq!(key, KEY, "HMAC-SHA256 key must be forwarded");
        assert_eq!(input, INPUT, "HMAC-SHA256 input must be forwarded");
        Ok([5; 32])
    }

    fn hmac_sha512(&self, key: &[u8], input: &[u8]) -> Result<[u8; 64]> {
        assert_eq!(key, KEY, "HMAC-SHA512 key must be forwarded");
        assert_eq!(input, INPUT, "HMAC-SHA512 input must be forwarded");
        Ok([6; 64])
    }

    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        assert_eq!(private_key_pem, KEY, "RSA key must be forwarded");
        assert_eq!(message, INPUT, "RSA message must be forwarded");
        Ok(vec![7; 32])
    }

    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        assert_eq!(
            private_key_scalar, &ECDSA_SCALAR,
            "ECDSA scalar must be forwarded"
        );
        assert_eq!(message, INPUT, "ECDSA message must be forwarded");
        Ok(vec![8; 16])
    }

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        assert_eq!(key, AES_KEY, "AES key must be forwarded");
        assert_eq!(nonce, AES_NONCE, "AES nonce must be forwarded");
        assert_eq!(aad, AES_AAD, "AES AAD must be forwarded");
        assert_eq!(plaintext, AES_PLAINTEXT, "AES plaintext must be forwarded");
        Ok(vec![9; 20])
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
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
    assert_eq!(provider.sha1(INPUT).expect("sha1 must succeed"), [1; 20]);
    assert_eq!(
        provider.sha256(INPUT).expect("sha256 must succeed"),
        [2; 32]
    );

    let err = provider
        .md5(INPUT)
        .expect_err("the marker provider must reject MD5");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(err.to_string(), MD5_ERROR);

    assert_eq!(
        provider
            .hmac_sha1(KEY, INPUT)
            .expect("HMAC-SHA1 must succeed"),
        [4; 20]
    );
    assert_eq!(
        provider
            .hmac_sha256(KEY, INPUT)
            .expect("HMAC-SHA256 must succeed"),
        [5; 32]
    );
    assert_eq!(
        provider
            .hmac_sha512(KEY, INPUT)
            .expect("HMAC-SHA512 must succeed"),
        [6; 64]
    );
    assert_eq!(
        provider
            .rsa_pkcs1v15_sha256_sign(KEY, INPUT)
            .expect("RSA signing must succeed"),
        vec![7; 32]
    );
    assert_eq!(
        provider
            .ecdsa_p256_sha256_sign(&ECDSA_SCALAR, INPUT)
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
