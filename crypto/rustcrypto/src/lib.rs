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
//! MD5, SHA-1, SHA-256, HMAC-SHA-1, HMAC-SHA-256, and HMAC-SHA-512 are always
//! available. The optional `rsa`, `p256`, and `aes-gcm` features, all enabled
//! by default, add RSA PKCS#1 v1.5 and RSA-PSS signing, ECDSA P-256 signing,
//! and AES-GCM encryption plus secure random generation. Disabled operations
//! return [`reqsign_core::ErrorKind::ConfigInvalid`] and name the missing feature. RSA, AES-GCM, and secure random generation are native-only;
//! on `wasm32` they return `ConfigInvalid` even when their feature is enabled.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
#[cfg(feature = "p256")]
use p256::ecdsa::signature::Signer;
#[cfg(feature = "p256")]
use p256::ecdsa::{DerSignature, SigningKey};
use reqsign_core::crypto::{self, CryptoProvider};
use reqsign_core::{Error, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

#[cfg(any(not(feature = "rsa"), not(feature = "p256"), not(feature = "aes-gcm")))]
fn missing_feature(operation: &str, feature: &str) -> Error {
    Error::config_invalid(format!(
        "{operation} requires the `{feature}` feature of reqsign-crypto-rustcrypto"
    ))
}

#[cfg(all(any(feature = "rsa", feature = "aes-gcm"), target_arch = "wasm32"))]
fn unsupported_on_wasm32(operation: &str) -> Error {
    Error::config_invalid(format!(
        "{operation} is not supported on wasm32-unknown-unknown by reqsign-crypto-rustcrypto"
    ))
}

#[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
fn rsa_private_key(private_key_pem: &[u8]) -> Result<rsa::PrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    let pem = std::str::from_utf8(private_key_pem).map_err(|e| {
        Error::credential_invalid("RSA private key PEM is not valid UTF-8").with_source(e)
    })?;
    rsa::PrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| rsa::PrivateKey::from_pkcs1_pem(pem))
        .map_err(|e| {
            Error::credential_invalid("failed to parse RSA private key PEM").with_source(e)
        })
}

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

impl CryptoProvider for RustCryptoProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        Ok(Sha1::digest(input).into())
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        Ok(Sha256::digest(input).into())
    }

    fn md5(&self, input: &[u8]) -> Result<[u8; 16]> {
        Ok(Md5::digest(input).into())
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

    fn hmac_sha512(&self, key: &[u8], input: &[u8]) -> Result<[u8; 64]> {
        let mut mac = Hmac::<Sha512>::new_from_slice(key)
            .map_err(|e| Error::unexpected("failed to initialize HMAC-SHA512").with_source(e))?;
        mac.update(input);
        Ok(mac.finalize().into_bytes().into())
    }

    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use rsa::pkcs1v15::SigningKey as RsaSigningKey;
        use rsa::sha2::Sha256 as RsaSha256;
        use rsa::signature::{SignatureEncoding, Signer};

        let private_key = rsa_private_key(private_key_pem)?;
        let signing_key = RsaSigningKey::<RsaSha256>::new(private_key);
        let signature = signing_key.try_sign(message).map_err(|e| {
            Error::unexpected("RSA PKCS#1 v1.5 SHA-256 signing failed").with_source(e)
        })?;
        Ok(signature.to_bytes().to_vec())
    }

    #[cfg(all(feature = "rsa", target_arch = "wasm32"))]
    fn rsa_pkcs1v15_sha256_sign(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported_on_wasm32("RSA PKCS#1 v1.5 SHA-256 signing"))
    }

    #[cfg(not(feature = "rsa"))]
    fn rsa_pkcs1v15_sha256_sign(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(missing_feature("RSA PKCS#1 v1.5 SHA-256 signing", "rsa"))
    }

    #[cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
    fn rsa_pss_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        use rsa::pss::SigningKey as PssSigningKey;
        use rsa::sha2::Sha256 as RsaSha256;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::traits::PublicKeyParts;

        let private_key = rsa_private_key(private_key_pem)?;
        if private_key.n().bit_width() < 2048 {
            return Err(Error::credential_invalid(
                "RSA-PSS requires an RSA key of at least 2048 bits",
            ));
        }
        let signing_key = PssSigningKey::<RsaSha256>::new_with_salt_len(private_key, 32);
        let signature = signing_key
            .try_sign(message)
            .map_err(|e| Error::unexpected("RSA-PSS SHA-256 signing failed").with_source(e))?;
        Ok(signature.to_bytes().to_vec())
    }

    #[cfg(all(feature = "rsa", target_arch = "wasm32"))]
    fn rsa_pss_sha256_sign(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported_on_wasm32("RSA-PSS SHA-256 signing"))
    }

    #[cfg(not(feature = "rsa"))]
    fn rsa_pss_sha256_sign(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(missing_feature("RSA-PSS SHA-256 signing", "rsa"))
    }

    #[cfg(feature = "p256")]
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

    #[cfg(not(feature = "p256"))]
    fn ecdsa_p256_sha256_sign(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>> {
        Err(missing_feature("ECDSA P-256 SHA-256 signing", "p256"))
    }

    #[cfg(all(feature = "aes-gcm", not(target_arch = "wasm32")))]
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

    #[cfg(all(feature = "aes-gcm", target_arch = "wasm32"))]
    fn aes_gcm_encrypt(&self, _: &[u8], _: &[u8; 12], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported_on_wasm32("AES-GCM encryption"))
    }

    #[cfg(not(feature = "aes-gcm"))]
    fn aes_gcm_encrypt(&self, _: &[u8], _: &[u8; 12], _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
        Err(missing_feature("AES-GCM encryption", "aes-gcm"))
    }

    #[cfg(all(feature = "aes-gcm", not(target_arch = "wasm32")))]
    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest)
            .map_err(|e| Error::unexpected(format!("secure random generation failed: {e}")))
    }

    #[cfg(all(feature = "aes-gcm", target_arch = "wasm32"))]
    fn fill_random(&self, _: &mut [u8]) -> Result<()> {
        Err(unsupported_on_wasm32("secure random generation"))
    }

    #[cfg(not(feature = "aes-gcm"))]
    fn fill_random(&self, _: &mut [u8]) -> Result<()> {
        Err(missing_feature("secure random generation", "aes-gcm"))
    }
}
