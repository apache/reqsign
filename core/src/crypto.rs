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

//! Process-wide cryptographic provider.
//!
//! Reqsign does not bundle a cryptographic implementation. Applications install
//! one [`CryptoProvider`] at startup with [`install_default`]. All hashing,
//! signing, encryption and random generation performed by reqsign goes through
//! the installed provider.
//!
//! A process can install at most one provider. Installation is not
//! idempotent: later attempts return the provider they tried to install and
//! leave the first provider in place.

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};

use crate::{Error, Result};

/// Cryptographic operations required by reqsign.
///
/// The first four methods are mandatory. A provider implements the remaining
/// methods when it supports the corresponding operation; the default
/// implementations return [`crate::ErrorKind::ConfigInvalid`] so that a minimal
/// provider can serve services that only need hashing and MACs.
///
/// Implementations must be safe to call concurrently and must not retain mutable
/// per-call state between invocations.
pub trait CryptoProvider: Debug + Send + Sync + 'static {
    /// Compute the SHA-1 digest of `input`.
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]>;

    /// Compute the SHA-256 digest of `input`.
    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]>;

    /// Compute HMAC-SHA-1 over `input` with `key`.
    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]>;

    /// Compute HMAC-SHA-256 over `input` with `key`.
    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]>;

    /// RSASSA-PKCS1-v1_5 with SHA-256 over `message`.
    ///
    /// `private_key_pem` is an unencrypted PKCS#8 (`PRIVATE KEY`) or PKCS#1
    /// (`RSA PRIVATE KEY`) PEM document. The returned bytes are the signature
    /// in big-endian, fixed-width form as required by RS256.
    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let _ = (private_key_pem, message);
        Err(Error::config_invalid(
            "configured CryptoProvider does not support RSA PKCS#1 v1.5 SHA-256 signing",
        ))
    }

    /// ECDSA over NIST P-256 with SHA-256 over `message`.
    ///
    /// `private_key_scalar` is the big-endian 32-byte private scalar in the
    /// range `1 <= d < n`. The returned bytes are an ASN.1 DER signature.
    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let _ = (private_key_scalar, message);
        Err(Error::config_invalid(
            "configured CryptoProvider does not support ECDSA P-256 SHA-256 signing",
        ))
    }

    /// AES-128-GCM (16-byte key) or AES-256-GCM (32-byte key) encryption.
    ///
    /// `nonce` is a 12-byte GCM nonce. `aad` is authenticated but not
    /// encrypted. The returned bytes are `ciphertext || 16-byte tag`.
    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let _ = (key, nonce, aad, plaintext);
        Err(Error::config_invalid(
            "configured CryptoProvider does not support AES-GCM encryption",
        ))
    }

    /// Fill `dest` with cryptographically secure random bytes.
    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
        let _ = dest;
        Err(Error::config_invalid(
            "configured CryptoProvider does not support random byte generation",
        ))
    }
}

static DEFAULT_PROVIDER: OnceLock<Arc<dyn CryptoProvider>> = OnceLock::new();

/// Install the process-wide [`CryptoProvider`].
///
/// Installation succeeds at most once per process. Concurrent calls are safe;
/// exactly one caller succeeds and every other caller receives an error holding
/// the provider it attempted to install. A failed installation does not replace
/// the provider that was installed first.
pub fn install_default(
    provider: impl CryptoProvider,
) -> std::result::Result<(), Arc<dyn CryptoProvider>> {
    let provider: Arc<dyn CryptoProvider> = Arc::new(provider);
    match DEFAULT_PROVIDER.set(provider) {
        Ok(()) => Ok(()),
        Err(provider) => Err(provider),
    }
}

/// Return the installed process-wide [`CryptoProvider`], if any.
///
/// This only reads the current state. Reading `None` before installation does
/// not prevent a later [`install_default`] call from succeeding.
pub fn get_default() -> Option<&'static Arc<dyn CryptoProvider>> {
    DEFAULT_PROVIDER.get()
}

pub(crate) fn require_default() -> Result<&'static Arc<dyn CryptoProvider>> {
    get_default().ok_or_else(|| {
        Error::config_invalid(
            "no CryptoProvider is installed; install one during application startup",
        )
    })
}
