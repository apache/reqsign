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

//! BoringSSL [`CryptoProvider`] for reqsign.
//!
//! The provider implements every operation with BoringSSL's safe, one-shot
//! APIs. Each call creates and drops its own BoringSSL context, so concurrent
//! calls do not share mutable state and the crate contains no `unsafe` code.
//!
//! This crate is excluded from the reqsign workspace: building it requires a
//! C/C++ toolchain and CMake, and the main workspace must stay pure Rust. The
//! `fips` feature forwards to `boring/fips`.

use std::sync::Arc;

use boring::aead::{AeadCtx, Algorithm};
use boring::bn::{BigNum, BigNumContext};
use boring::ec::{EcGroup, EcKey, EcPoint};
use boring::ecdsa::EcdsaSig;
use boring::hash::{MessageDigest, hash};
use boring::hmac::Hmac;
use boring::nid::Nid;
use boring::pkey::{Id, PKey, Private};
use boring::rsa::Padding;
use boring::sign::Signer;
use reqsign_core::crypto::{self, CryptoProvider};
use reqsign_core::{Error, Result};

/// BoringSSL implementation of [`CryptoProvider`].
#[derive(Debug, Default)]
pub struct BoringCryptoProvider;

impl BoringCryptoProvider {
    /// Create a BoringSSL provider.
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

fn unexpected(
    context: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::unexpected(context).with_source(source)
}

fn digest<const N: usize>(md: MessageDigest, input: &[u8]) -> Result<[u8; N]> {
    let bytes = hash(md, input).map_err(|e| unexpected("BoringSSL hashing failed", e))?;
    bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::unexpected("BoringSSL produced an unexpected digest length"))
}

fn hmac<const N: usize>(md: MessageDigest, key: &[u8], input: &[u8]) -> Result<[u8; N]> {
    let mut hmac =
        Hmac::init(key, &md).map_err(|e| unexpected("failed to initialize BoringSSL HMAC", e))?;
    hmac.update(input)
        .map_err(|e| unexpected("BoringSSL HMAC update failed", e))?;
    let bytes = hmac
        .finalize()
        .map_err(|e| unexpected("BoringSSL HMAC finalization failed", e))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::unexpected("BoringSSL produced an unexpected HMAC length"))
}

fn rsa_private_key(private_key_pem: &[u8]) -> Result<PKey<Private>> {
    let private_key = PKey::private_key_from_pem(private_key_pem).map_err(|e| {
        Error::credential_invalid("failed to parse RSA private key PEM").with_source(e)
    })?;
    if private_key.id() != Id::RSA {
        return Err(Error::credential_invalid(
            "private key PEM does not contain an RSA key",
        ));
    }
    Ok(private_key)
}

fn p256_private_key(private_key_scalar: &[u8; 32]) -> Result<EcKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| unexpected("failed to load the P-256 group", e))?;
    let mut context = BigNumContext::new()
        .map_err(|e| unexpected("failed to create a P-256 big number context", e))?;
    let mut order =
        BigNum::new().map_err(|e| unexpected("failed to allocate the P-256 group order", e))?;
    group
        .order(&mut order, &mut context)
        .map_err(|e| unexpected("failed to read the P-256 group order", e))?;
    let one = BigNum::from_u32(1)
        .map_err(|e| unexpected("failed to allocate a P-256 scalar bound", e))?;
    let scalar = BigNum::from_slice(private_key_scalar)
        .map_err(|e| unexpected("failed to parse the P-256 private scalar", e))?;

    if scalar < one || scalar >= order {
        return Err(Error::credential_invalid(
            "ECDSA P-256 private key scalar is outside the valid range",
        ));
    }

    let mut public_key = EcPoint::new(&group)
        .map_err(|e| unexpected("failed to allocate a P-256 public point", e))?;
    public_key
        .mul_generator(&group, &scalar, &mut context)
        .map_err(|e| unexpected("failed to derive the P-256 public point", e))?;
    EcKey::from_private_components(&group, &scalar, &public_key)
        .map_err(|e| unexpected("failed to build the P-256 private key", e))
}

impl CryptoProvider for BoringCryptoProvider {
    fn sha1(&self, input: &[u8]) -> Result<[u8; 20]> {
        digest(MessageDigest::sha1(), input)
    }

    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        digest(MessageDigest::sha256(), input)
    }

    fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> Result<[u8; 20]> {
        hmac(MessageDigest::sha1(), key, input)
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> Result<[u8; 32]> {
        hmac(MessageDigest::sha256(), key, input)
    }

    fn rsa_pkcs1v15_sha256_sign(&self, private_key_pem: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let private_key = rsa_private_key(private_key_pem)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
            .map_err(|e| unexpected("failed to initialize RSA signing", e))?;
        signer
            .set_rsa_padding(Padding::PKCS1)
            .map_err(|e| unexpected("failed to select RSA PKCS#1 v1.5 padding", e))?;
        signer
            .sign_oneshot_to_vec(message)
            .map_err(|e| unexpected("RSA PKCS#1 v1.5 SHA-256 signing failed", e))
    }

    fn ecdsa_p256_sha256_sign(
        &self,
        private_key_scalar: &[u8; 32],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let private_key = p256_private_key(private_key_scalar)?;
        let digest = digest::<32>(MessageDigest::sha256(), message)?;
        let signature = EcdsaSig::sign(&digest, &private_key)
            .map_err(|e| unexpected("ECDSA P-256 signing failed", e))?;
        signature
            .to_der()
            .map_err(|e| unexpected("failed to encode the ECDSA signature", e))
    }

    fn aes_gcm_encrypt(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let algorithm = match key.len() {
            16 => Algorithm::aes_128_gcm(),
            32 => Algorithm::aes_256_gcm(),
            _ => {
                return Err(Error::credential_invalid(
                    "AES-GCM key must be 16 or 32 bytes",
                ));
            }
        };
        let mut context = AeadCtx::new_default_tag(&algorithm, key)
            .map_err(|e| unexpected("failed to initialize AES-GCM", e))?;
        let mut ciphertext = plaintext.to_vec();
        let mut tag = [0u8; 16];
        let tag = context
            .seal_in_place_mut(nonce, &mut ciphertext, &mut tag, aad)
            .map_err(|e| unexpected("AES-GCM encryption failed", e))?;
        ciphertext.extend_from_slice(tag);
        Ok(ciphertext)
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<()> {
        boring::rand::rand_bytes(dest)
            .map_err(|e| unexpected("BoringSSL random generation failed", e))
    }
}
