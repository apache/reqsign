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

use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash;
use reqsign_core::hash::{
    base64_hmac_sha1, base64_hmac_sha256, hex_hmac_sha1, hex_hmac_sha256, hex_sha1, hex_sha256,
    hmac_sha1, hmac_sha256, sha1, sha256,
};
use reqsign_crypto_rustcrypto::RustCryptoProvider;

const INPUT: &[u8] = b"GET /bucket/object?partNumber=1&uploadId=example";
const KEY: &[u8] = b"reqsign-test-secret-key-material";

#[test]
fn hash_helpers_delegate_to_the_provider_with_expected_widths() {
    let provider = RustCryptoProvider::new();
    let expected_sha1 = provider.sha1(INPUT).expect("SHA-1 must succeed");
    let expected_sha256 = provider.sha256(INPUT).expect("SHA-256 must succeed");

    assert_eq!(
        sha1(&provider, INPUT).expect("SHA-1 must succeed"),
        expected_sha1
    );
    assert_eq!(
        sha256(&provider, INPUT).expect("SHA-256 must succeed"),
        expected_sha256
    );
    assert_eq!(expected_sha1.len(), 20);
    assert_eq!(expected_sha256.len(), 32);

    assert_eq!(
        hex_sha1(&provider, INPUT).expect("hex SHA-1 must succeed"),
        hex::encode(expected_sha1)
    );
    assert_eq!(
        hex_sha256(&provider, INPUT).expect("hex SHA-256 must succeed"),
        hex::encode(expected_sha256)
    );
}

#[test]
fn hmac_helpers_preserve_key_and_input_with_expected_widths() {
    let provider = RustCryptoProvider::new();
    let expected_sha1 = provider
        .hmac_sha1(KEY, INPUT)
        .expect("HMAC-SHA1 must succeed");
    let expected_sha256 = provider
        .hmac_sha256(KEY, INPUT)
        .expect("HMAC-SHA256 must succeed");

    assert_eq!(
        hmac_sha1(&provider, KEY, INPUT).expect("HMAC-SHA1 must succeed"),
        expected_sha1
    );
    assert_eq!(
        hmac_sha256(&provider, KEY, INPUT).expect("HMAC-SHA256 must succeed"),
        expected_sha256
    );
    assert_eq!(expected_sha1.len(), 20);
    assert_eq!(expected_sha256.len(), 32);

    assert_eq!(
        hex_hmac_sha1(&provider, KEY, INPUT).expect("hex HMAC-SHA1 must succeed"),
        hex::encode(expected_sha1)
    );
    assert_eq!(
        hex_hmac_sha256(&provider, KEY, INPUT).expect("hex HMAC-SHA256 must succeed"),
        hex::encode(expected_sha256)
    );
    assert_eq!(
        base64_hmac_sha1(&provider, KEY, INPUT).expect("base64 HMAC-SHA1 must succeed"),
        hash::base64_encode(&expected_sha1)
    );
    assert_eq!(
        base64_hmac_sha256(&provider, KEY, INPUT).expect("base64 HMAC-SHA256 must succeed"),
        hash::base64_encode(&expected_sha256)
    );
}

#[test]
fn base64_helpers_remain_pure_encoding_utilities() {
    let encoded = hash::base64_encode(b"\x00binary\xff");
    assert_eq!(
        hash::base64_decode(&encoded).expect("base64 decode must succeed"),
        b"\x00binary\xff"
    );
    assert_eq!(encoded, "AGJpbmFyef8=");
}
