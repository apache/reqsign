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

//! This test binary runs without a provider on purpose. Keep it as a separate
//! test target so another test cannot install a provider into the same process.

use reqsign_core::ErrorKind;
use reqsign_core::crypto::get_default;
use reqsign_core::hash;

#[test]
fn unset_provider_returns_config_invalid_without_panicking() {
    assert!(get_default().is_none());

    let err = hash::sha256(b"payload").expect_err("hashing without a provider must fail");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(!err.is_retryable());

    let err = hash::sha1(b"payload").expect_err("hashing without a provider must fail");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);

    let err = hash::hmac_sha256(b"key", b"payload").expect_err("HMAC without a provider must fail");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);

    let err =
        hash::base64_hmac_sha1(b"key", b"payload").expect_err("HMAC without a provider must fail");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
}

#[cfg(feature = "jwt")]
#[test]
fn jwt_signing_without_a_provider_returns_config_invalid() {
    #[derive(serde::Serialize)]
    struct Empty {}
    let err = reqsign_core::jwt::encode_rs256_pem(&Empty {}, &Empty {}, b"not used")
        .expect_err("JWT signing without a provider must fail");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
}
