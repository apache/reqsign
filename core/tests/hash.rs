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

mod support;

use reqsign_core::hash::{
    base64_decode, base64_encode, base64_hmac_sha1, base64_hmac_sha256, hex_hmac_sha1,
    hex_hmac_sha256, hex_sha1, hex_sha256,
};
use support::TestProvider;

const INPUT: &[u8] = b"GET /bucket/object?partNumber=1&uploadId=example";
const KEY: &[u8] = b"reqsign-test-secret-key-material";

#[test]
fn encoded_hash_helpers_preserve_inputs_and_format_canned_bytes() {
    let provider = TestProvider::expecting("hash", KEY, INPUT);

    assert_eq!(
        hex_sha1(&provider, INPUT).expect("hex SHA-1 must succeed"),
        "0101010101010101010101010101010101010101"
    );
    assert_eq!(
        hex_sha256(&provider, INPUT).expect("hex SHA-256 must succeed"),
        "0202020202020202020202020202020202020202020202020202020202020202"
    );
    assert_eq!(
        hex_hmac_sha1(&provider, KEY, INPUT).expect("hex HMAC-SHA1 must succeed"),
        "0303030303030303030303030303030303030303"
    );
    assert_eq!(
        hex_hmac_sha256(&provider, KEY, INPUT).expect("hex HMAC-SHA256 must succeed"),
        "0404040404040404040404040404040404040404040404040404040404040404"
    );
    assert_eq!(
        base64_hmac_sha1(&provider, KEY, INPUT).expect("base64 HMAC-SHA1 must succeed"),
        "AwMDAwMDAwMDAwMDAwMDAwMDAwM="
    );
    assert_eq!(
        base64_hmac_sha256(&provider, KEY, INPUT).expect("base64 HMAC-SHA256 must succeed"),
        "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
    );
}

#[test]
fn base64_helpers_remain_pure_encoding_utilities() {
    let encoded = base64_encode(b"\x00binary\xff");
    assert_eq!(
        base64_decode(&encoded).expect("base64 decode must succeed"),
        b"\x00binary\xff"
    );
    assert_eq!(encoded, "AGJpbmFyef8=");
}
