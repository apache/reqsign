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

//! Credentials for RFC 9421 request signatures.
//!
//! A credential contains a key identifier and either an HMAC-SHA256 shared
//! key or an RSA private key used with RSASSA-PKCS1-v1_5 and SHA-256. Key
//! material is private and redacted from [`Debug`] output.

use std::fmt;

use reqsign_core::SigningCredential;
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash::hmac_sha256;
use reqsign_core::{Error, Result};

const REDACTED: &str = "REDACTED";

/// A signing credential for RFC 9421 request signatures.
///
/// Construct one with [`Credential::hmac_sha256`] or
/// [`Credential::rsa_v1_5_sha256`]. The private key material is never exposed
/// through [`Debug`] and is not included in errors.
#[derive(Clone)]
pub struct Credential {
    keyid: String,
    key: KeyMaterial,
}

#[derive(Clone)]
enum KeyMaterial {
    HmacSha256(Vec<u8>),
    RsaV1_5Sha256(Vec<u8>),
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("keyid", &self.keyid)
            .field("algorithm", &self.algorithm())
            .field("key", &REDACTED)
            .finish()
    }
}

impl Credential {
    /// Create an HMAC-SHA256 credential from a key identifier and nonempty raw
    /// key bytes.
    pub fn hmac_sha256(keyid: impl Into<String>, key: impl AsRef<[u8]>) -> Result<Self> {
        let keyid = keyid.into();
        validate_keyid(&keyid)?;

        let key = key.as_ref().to_vec();
        if key.is_empty() {
            return Err(Error::credential_invalid(
                "HMAC-SHA256 key must not be empty",
            ));
        }

        Ok(Self {
            keyid,
            key: KeyMaterial::HmacSha256(key),
        })
    }

    /// Create an RSASSA-PKCS1-v1_5 SHA-256 credential from a key identifier and
    /// an unencrypted PKCS#1 or PKCS#8 PEM private key.
    pub fn rsa_v1_5_sha256(keyid: impl Into<String>, pem: impl AsRef<[u8]>) -> Result<Self> {
        let keyid = keyid.into();
        validate_keyid(&keyid)?;

        let pem = pem.as_ref().to_vec();
        if pem.is_empty() {
            return Err(Error::credential_invalid(
                "RSA private key PEM must not be empty",
            ));
        }

        Ok(Self {
            keyid,
            key: KeyMaterial::RsaV1_5Sha256(pem),
        })
    }

    pub(crate) fn keyid(&self) -> &str {
        &self.keyid
    }

    pub(crate) fn algorithm(&self) -> &'static str {
        match self.key {
            KeyMaterial::HmacSha256(_) => "hmac-sha256",
            KeyMaterial::RsaV1_5Sha256(_) => "rsa-v1_5-sha256",
        }
    }

    pub(crate) fn sign(&self, provider: &dyn CryptoProvider, base: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            KeyMaterial::HmacSha256(key) => Ok(hmac_sha256(provider, key, base)?.to_vec()),
            KeyMaterial::RsaV1_5Sha256(pem) => provider.rsa_pkcs1v15_sha256_sign(pem, base),
        }
    }
}

impl SigningCredential for Credential {
    fn is_valid(&self) -> bool {
        !self.keyid.is_empty()
            && match &self.key {
                KeyMaterial::HmacSha256(key) => !key.is_empty(),
                KeyMaterial::RsaV1_5Sha256(pem) => !pem.is_empty(),
            }
    }
}

fn validate_keyid(keyid: &str) -> Result<()> {
    if keyid.is_empty() {
        return Err(Error::credential_invalid("keyid must not be empty"));
    }
    if !crate::structured_field::is_string(keyid) {
        return Err(Error::credential_invalid(
            "keyid is not representable as an RFC 8941 String",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_hmac_key_without_echoing_material() {
        let error = Credential::hmac_sha256("key-id", b"").unwrap_err();
        assert_eq!(error.kind(), reqsign_core::ErrorKind::CredentialInvalid);
        assert!(!format!("{error:?}").contains("key-id"));
    }

    #[test]
    fn rejects_empty_or_non_ascii_keyid() {
        assert!(Credential::hmac_sha256("", b"secret").is_err());
        assert!(Credential::hmac_sha256("ключ", b"secret").is_err());
    }

    #[test]
    fn debug_redacts_key_material() {
        let credential =
            Credential::hmac_sha256("test-key", b"key-prefix-key-material-suffix").unwrap();
        let debug = format!("{credential:?}");
        assert!(debug.contains("test-key"));
        assert!(debug.contains(REDACTED));
        assert!(!debug.contains("key-prefix"));
        assert!(!debug.contains("suffix"));

        let credential =
            Credential::rsa_v1_5_sha256("test-rsa", b"not-a-real-private-key\n").unwrap();
        let debug = format!("{credential:?}");
        assert!(debug.contains("test-rsa"));
        assert!(debug.contains(REDACTED));
        assert!(!debug.contains("not-a-real-private-key"));
    }
}
