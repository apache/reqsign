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

//! Hash related utils.
//!
//! SHA and HMAC use RustCrypto by default. With the `boring` feature they use
//! BoringSSL instead, through the [`boring`](https://docs.rs/boring) crate, for
//! applications that standardize their cryptography on BoringSSL.

use crate::Error;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;

/// Base64 encode
pub fn base64_encode(content: &[u8]) -> String {
    BASE64_STANDARD.encode(content)
}

/// Base64 decode
pub fn base64_decode(content: &str) -> crate::Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(content)
        .map_err(|e| Error::unexpected("base64 decode failed").with_source(e))
}

/// Hex encoded SHA1 hash.
///
/// Use this function instead of `hex::encode(sha1(content))` can reduce
/// extra copy.
pub fn hex_sha1(content: &[u8]) -> String {
    hex::encode(backend::sha1(content))
}

/// Hex encoded SHA256 hash.
///
/// Use this function instead of `hex::encode(sha256(content))` can reduce
/// extra copy.
pub fn hex_sha256(content: &[u8]) -> String {
    hex::encode(backend::sha256(content))
}

/// HMAC with SHA256 hash.
pub fn hmac_sha256(key: &[u8], content: &[u8]) -> Vec<u8> {
    backend::hmac_sha256(key, content).to_vec()
}

/// Base64 encoded HMAC with SHA256 hash.
pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    base64_encode(&backend::hmac_sha256(key, content))
}

/// Hex encoded HMAC with SHA1 hash.
///
/// Use this function instead of `hex::encode(hmac_sha1(key, content))` can
/// reduce extra copy.
pub fn hex_hmac_sha1(key: &[u8], content: &[u8]) -> String {
    hex::encode(backend::hmac_sha1(key, content))
}

/// Hex encoded HMAC with SHA256 hash.
///
/// Use this function instead of `hex::encode(hmac_sha256(key, content))` can
/// reduce extra copy.
pub fn hex_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    hex::encode(backend::hmac_sha256(key, content))
}

/// Base64 encoded HMAC with SHA1 hash.
pub fn base64_hmac_sha1(key: &[u8], content: &[u8]) -> String {
    base64_encode(&backend::hmac_sha1(key, content))
}

#[cfg(not(feature = "boring"))]
mod backend {
    use hmac::Hmac;
    use hmac::KeyInit;
    use hmac::Mac;
    use sha1::Sha1;
    use sha2::Digest;
    use sha2::Sha256;

    pub(super) fn sha1(content: &[u8]) -> [u8; 20] {
        Sha1::digest(content).into()
    }

    pub(super) fn sha256(content: &[u8]) -> [u8; 32] {
        Sha256::digest(content).into()
    }

    pub(super) fn hmac_sha1(key: &[u8], content: &[u8]) -> [u8; 20] {
        // SAFETY: HMAC's new_from_slice always returns Ok - it handles any key length
        let mut h = Hmac::<Sha1>::new_from_slice(key).unwrap();
        h.update(content);
        h.finalize().into_bytes().into()
    }

    pub(super) fn hmac_sha256(key: &[u8], content: &[u8]) -> [u8; 32] {
        // SAFETY: HMAC's new_from_slice always returns Ok - it handles any key length
        let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
        h.update(content);
        h.finalize().into_bytes().into()
    }
}

#[cfg(feature = "boring")]
mod backend {
    use boring::hash::MessageDigest;
    use boring::hash::hash;

    pub(super) fn sha1(content: &[u8]) -> [u8; 20] {
        let digest = hash(MessageDigest::sha1(), content).expect("SHA-1 does not fail");
        digest[..].try_into().expect("SHA-1 digest is 20 bytes")
    }

    pub(super) fn sha256(content: &[u8]) -> [u8; 32] {
        let digest = hash(MessageDigest::sha256(), content).expect("SHA-256 does not fail");
        digest[..].try_into().expect("SHA-256 digest is 32 bytes")
    }

    pub(super) fn hmac_sha1(key: &[u8], content: &[u8]) -> [u8; 20] {
        boring::hash::hmac_sha1(key, content).expect("HMAC-SHA1 does not fail")
    }

    pub(super) fn hmac_sha256(key: &[u8], content: &[u8]) -> [u8; 32] {
        boring::hash::hmac_sha256(key, content).expect("HMAC-SHA256 does not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_known_answers() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex_sha1(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn hmac_known_answers() {
        // RFC 4231 test case 1 and RFC 2202 test case 1.
        let key = [0x0b; 20];
        assert_eq!(
            hex_hmac_sha256(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            base64_hmac_sha256(&key, b"Hi There"),
            "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
        );
        assert_eq!(
            hex_hmac_sha1(&key, b"Hi There"),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            base64_hmac_sha1(&key, b"Hi There"),
            "thcxhlUFcmTii8C2+zeMjvFGvgA="
        );
    }

    #[test]
    fn hmac_key_longer_than_block_size() {
        // RFC 4231 test case 6: a 131-byte key is hashed before use.
        let key = [0xaa; 131];
        assert_eq!(
            hex_hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn aws_sigv4_signing_key_known_answer() {
        // Example from the AWS SigV4 documentation.
        let date = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let region = hmac_sha256(&date, b"us-east-1");
        let service = hmac_sha256(&region, b"iam");
        let signing_key = hmac_sha256(&service, b"aws4_request");
        assert_eq!(
            hex::encode(signing_key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
