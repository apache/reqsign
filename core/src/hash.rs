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
//! Encoding helpers are pure functions. Digest and MAC helpers use the
//! process-wide [`crate::crypto::CryptoProvider`] and return an error when no
//! provider is installed or the installed provider cannot serve the operation.

use crate::crypto;
use crate::{Error, Result};
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

/// SHA1 digest.
pub fn sha1(content: &[u8]) -> Result<[u8; 20]> {
    crypto::require_default()?.sha1(content)
}

/// SHA256 digest.
pub fn sha256(content: &[u8]) -> Result<[u8; 32]> {
    crypto::require_default()?.sha256(content)
}

/// HMAC with SHA1 hash.
pub fn hmac_sha1(key: &[u8], content: &[u8]) -> Result<[u8; 20]> {
    crypto::require_default()?.hmac_sha1(key, content)
}

/// HMAC with SHA256 hash.
pub fn hmac_sha256(key: &[u8], content: &[u8]) -> Result<[u8; 32]> {
    crypto::require_default()?.hmac_sha256(key, content)
}

/// Hex encoded SHA1 hash.
pub fn hex_sha1(content: &[u8]) -> Result<String> {
    Ok(hex::encode(sha1(content)?))
}

/// Hex encoded SHA256 hash.
pub fn hex_sha256(content: &[u8]) -> Result<String> {
    Ok(hex::encode(sha256(content)?))
}

/// Base64 encoded HMAC with SHA256 hash.
pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> Result<String> {
    Ok(base64_encode(&hmac_sha256(key, content)?))
}

/// Hex encoded HMAC with SHA1 hash.
pub fn hex_hmac_sha1(key: &[u8], content: &[u8]) -> Result<String> {
    Ok(hex::encode(hmac_sha1(key, content)?))
}

/// Hex encoded HMAC with SHA256 hash.
pub fn hex_hmac_sha256(key: &[u8], content: &[u8]) -> Result<String> {
    Ok(hex::encode(hmac_sha256(key, content)?))
}

/// Base64 encoded HMAC with SHA1 hash.
pub fn base64_hmac_sha1(key: &[u8], content: &[u8]) -> Result<String> {
    Ok(base64_encode(&hmac_sha1(key, content)?))
}
