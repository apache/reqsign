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

use std::sync::{Arc, Mutex};

use reqsign_core::crypto::CryptoProvider;
use reqsign_core::{Context, Result};
use reqsign_crypto_rustcrypto::RustCryptoProvider;

pub fn test_context() -> Context {
    Context::new().with_crypto(RustCryptoProvider::new())
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct RsaCall {
    pub pem: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Delegates every operation to RustCrypto while recording RSA signing calls.
#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct RecordingProvider {
    rsa_calls: Arc<Mutex<Vec<RsaCall>>>,
}

#[allow(dead_code)]
impl RecordingProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rsa_calls(&self) -> Vec<RsaCall> {
        self.rsa_calls.lock().expect("lock poisoned").clone()
    }
}

impl CryptoProvider for RecordingProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        RustCryptoProvider::new().sha1(input)
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        RustCryptoProvider::new().sha256(input)
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        RustCryptoProvider::new().hmac_sha1(key, input)
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        RustCryptoProvider::new().hmac_sha256(key, input)
    }

    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let signature =
            RustCryptoProvider::new().rsa_pkcs1v15_sha256_sign(private_key_pem, message)?;
        self.rsa_calls.lock().expect("lock poisoned").push(RsaCall {
            pem: private_key_pem.to_vec(),
            message: message.to_vec(),
            signature: signature.clone(),
        });
        Ok(signature)
    }

    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        RustCryptoProvider::new().ecdsa_p256_sha256_sign(private_key_scalar, message)
    }

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        RustCryptoProvider::new().aes_gcm_encrypt(key, nonce, aad, plaintext)
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
        RustCryptoProvider::new().fill_random(dest)
    }
}
