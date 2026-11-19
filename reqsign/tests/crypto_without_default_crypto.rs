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

//! This binary is built with `--no-default-features --features default-context`.

#![cfg(all(feature = "default-context", not(feature = "default-crypto")))]

use reqsign::ErrorKind;
use reqsign::crypto::{CryptoProvider, install_default};

#[derive(Debug)]
struct TestProvider;

impl CryptoProvider for TestProvider {
    fn sha1(&self, _: &[u8]) -> reqsign::Result<[u8; 20]> {
        Ok([9; 20])
    }

    fn sha256(&self, _: &[u8]) -> reqsign::Result<[u8; 32]> {
        Ok([9; 32])
    }

    fn hmac_sha1(&self, _: &[u8], _: &[u8]) -> reqsign::Result<[u8; 20]> {
        Ok([9; 20])
    }

    fn hmac_sha256(&self, _: &[u8], _: &[u8]) -> reqsign::Result<[u8; 32]> {
        Ok([9; 32])
    }
}

#[test]
fn default_context_without_default_crypto_uses_explicit_or_global_only() {
    assert!(reqsign::crypto::get_default().is_none());
    let before_global = reqsign::default_context();
    let err = before_global
        .crypto_provider()
        .expect_err("default-context alone must not resolve a provider");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);

    install_default(TestProvider).expect("global installation must succeed");
    let after_global = reqsign::default_context();
    assert_eq!(
        reqsign::hash::sha256(
            after_global.crypto_provider().expect("global must resolve"),
            b"x"
        )
        .expect("global hashing must succeed"),
        [9; 32]
    );
}
