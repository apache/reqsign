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

//! Pure Rust [`CryptoProvider`] for reqsign based on the RustCrypto crates.
//!
//! The provider supports SHA-1, SHA-256, HMAC-SHA-1, HMAC-SHA-256 and
//! ECDSA P-256 on every target. RSA PKCS#1 v1.5, AES-GCM and secure random
//! generation are available on native targets. On `wasm32` those operations
//! inherit the trait's unsupported-operation error.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use reqsign_core::crypto::{self, CryptoProvider};
use reqsign_core::{Error, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// RustCrypto implementation of [`CryptoProvider`].
#[derive(Debug, Default)]
pub struct RustCryptoProvider;

impl RustCryptoProvider {
    /// Create a RustCrypto provider.
    pub fn new() -> Self {
        Self
    }

    /// Install this provider as the process-wide default.
    ///
    /// See [`reqsign_core::crypto::install_default`] for the installation
    /// contract.
    pub fn install_default() -> std::result::Result<(), Arc<dyn CryptoProvider>> {
        crypto::install_default(Self)
    }
}

// The ordinary RSA decoder requires each CRT prime to fit in half of the
// modulus width. Valid legacy and test keys can have unbalanced primes, as the
// RFC 9421 RSA test key does. Decode those components without the half-width
// assumption and validate them through the wide-prime constructor.
#[cfg(not(target_arch = "wasm32"))]
fn decode_unbalanced_pkcs1_key(
    pem: &str,
) -> std::result::Result<rsa::PrivateKey, rsa::pkcs1::Error> {
    use rsa::PrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1::RsaPrivateKeyOwned;

    let key = RsaPrivateKeyOwned::from_pkcs1_pem(pem)?;
    let bits = u32::try_from(key.modulus.as_bytes().len())
        .map_err(|_| rsa::pkcs1::Error::KeyMalformed)?
        * 8;
    let uint = |value: &rsa::pkcs1::der::asn1::Uint| {
        rsa::BoxedUint::from_be_slice(value.as_bytes(), bits)
            .map_err(|_| rsa::pkcs1::Error::KeyMalformed)
    };
    let primes = vec![uint(&key.prime1)?, uint(&key.prime2)?];

    PrivateKey::from_components_with_wide_primes(
        uint(&key.modulus)?,
        uint(&key.public_exponent)?,
        uint(&key.private_exponent)?,
        primes,
    )
    .map_err(|_| rsa::pkcs1::Error::KeyMalformed)
}

impl CryptoProvider for RustCryptoProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        Ok(Sha1::digest(input).into())
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        Ok(Sha256::digest(input).into())
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        let mut mac = Hmac::<Sha1>::new_from_slice(key)
            .map_err(|e| Error::unexpected("failed to initialize HMAC-SHA1").with_source(e))?;
        mac.update(input);
        Ok(mac.finalize().into_bytes().into())
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| Error::unexpected("failed to initialize HMAC-SHA256").with_source(e))?;
        mac.update(input);
        Ok(mac.finalize().into_bytes().into())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use rsa::PrivateKey;
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs1v15::SigningKey as RsaSigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::sha2::Sha256 as RsaSha256;
        use rsa::signature::{SignatureEncoding, Signer};

        let pem = std::str::from_utf8(private_key_pem).map_err(|e| {
            Error::credential_invalid("RSA private key PEM is not valid UTF-8").with_source(e)
        })?;
        let private_key = PrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| PrivateKey::from_pkcs1_pem(pem))
            .or_else(|_| decode_unbalanced_pkcs1_key(pem))
            .map_err(|e| {
                Error::credential_invalid("failed to parse RSA private key PEM").with_source(e)
            })?;

        let signing_key = RsaSigningKey::<RsaSha256>::new(private_key);
        let signature = signing_key.try_sign(message).map_err(|e| {
            Error::unexpected("RSA PKCS#1 v1.5 SHA-256 signing failed").with_source(e)
        })?;
        Ok(signature.to_bytes().to_vec())
    }

    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_slice(private_key_scalar).map_err(|e| {
            Error::credential_invalid("invalid ECDSA P-256 private key scalar").with_source(e)
        })?;
        let signature: DerSignature = signing_key.sign(message);
        Ok(signature.as_bytes().to_vec())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, Payload, array::Array};
        use aes_gcm::{Aes128Gcm, Aes256Gcm};

        let ciphertext = match key.len() {
            16 => Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::credential_invalid("invalid AES-128-GCM key").with_source(e))?
                .encrypt(
                    &Array(*nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| Error::unexpected("AES-GCM encryption failed").with_source(e))?,
            32 => Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::credential_invalid("invalid AES-256-GCM key").with_source(e))?
                .encrypt(
                    &Array(*nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| Error::unexpected("AES-GCM encryption failed").with_source(e))?,
            _ => {
                return Err(Error::credential_invalid(
                    "AES-GCM key must be 16 or 32 bytes",
                ));
            }
        };

        Ok(ciphertext)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest)
            .map_err(|e| Error::unexpected(format!("secure random generation failed: {e}")))
    }
}
