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

//! Test-only cryptographic provider for `reqsign-core` unit tests.
//!
//! `reqsign-core` cannot use `reqsign-crypto-rustcrypto` in its own unit tests:
//! the dev-dependency would link a second, non-test instance of
//! `reqsign-core`, and installation would populate that instance's
//! `OnceLock` instead of the one used by the test. This local provider keeps
//! crypto dependencies dev-only and installs into the test instance.

use crate::crypto::CryptoProvider;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct TestCryptoProvider;

impl CryptoProvider for TestCryptoProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        use sha1::Digest;
        Ok(sha1::Sha1::digest(input).into())
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        use sha2::Digest;
        Ok(sha2::Sha256::digest(input).into())
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        use hmac::{Hmac, KeyInit, Mac};
        let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(key)
            .map_err(|e| Error::unexpected("failed to initialize HMAC-SHA1").with_source(e))?;
        hmac.update(input);
        Ok(hmac.finalize().into_bytes().into())
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        use hmac::{Hmac, KeyInit, Mac};
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key)
            .map_err(|e| Error::unexpected("failed to initialize HMAC-SHA256").with_source(e))?;
        hmac.update(input);
        Ok(hmac.finalize().into_bytes().into())
    }

    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::rand_core::OsRng;
        use rsa::sha2::Sha256;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};

        let pem = std::str::from_utf8(private_key_pem).map_err(|e| {
            Error::credential_invalid("RSA private key PEM is not valid UTF-8").with_source(e)
        })?;
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| {
                Error::credential_invalid("failed to parse RSA private key PEM").with_source(e)
            })?;
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut OsRng, message);
        Ok(signature.to_bytes().to_vec())
    }
}
