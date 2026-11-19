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

use reqsign_core::hash;
use reqsign_core::hash::{
    base64_hmac_sha1, base64_hmac_sha256, hex_hmac_sha1, hex_hmac_sha256, hex_sha1, hex_sha256,
    hmac_sha1, hmac_sha256, sha1, sha256,
};
use reqsign_crypto_rustcrypto::RustCryptoProvider;

fn install_provider() {
    let _ = RustCryptoProvider::install_default();
}

#[test]
fn hashes_match_published_vectors_with_expected_widths() {
    install_provider();

    assert_eq!(
        hex::encode(sha1(b"abc").expect("SHA-1 must succeed")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex::encode(sha256(b"abc").expect("SHA-256 must succeed")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(sha1(b"abc").expect("SHA-1 must succeed").len(), 20);
    assert_eq!(sha256(b"abc").expect("SHA-256 must succeed").len(), 32);

    assert_eq!(
        hex_sha1(b"abc").expect("hex SHA-1 must succeed"),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex_sha256(b"abc").expect("hex SHA-256 must succeed"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hmac_matches_rfc_vectors_with_expected_widths() {
    install_provider();

    let key = [0x0b; 20];
    assert_eq!(
        hex::encode(hmac_sha1(&key, b"Hi There").expect("HMAC-SHA1 must succeed")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex::encode(hmac_sha256(&key, b"Hi There").expect("HMAC-SHA256 must succeed")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hmac_sha1(&key, b"Hi There")
            .expect("HMAC-SHA1 must succeed")
            .len(),
        20
    );
    assert_eq!(
        hmac_sha256(&key, b"Hi There")
            .expect("HMAC-SHA256 must succeed")
            .len(),
        32
    );

    assert_eq!(
        hex_hmac_sha1(&key, b"Hi There").expect("hex HMAC-SHA1 must succeed"),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex_hmac_sha256(&key, b"Hi There").expect("hex HMAC-SHA256 must succeed"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        base64_hmac_sha1(&key, b"Hi There").expect("base64 HMAC-SHA1 must succeed"),
        "thcxhlUFcmTii8C2+zeMjvFGvgA="
    );
    assert_eq!(
        base64_hmac_sha256(&key, b"Hi There").expect("base64 HMAC-SHA256 must succeed"),
        "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
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
