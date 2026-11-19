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

#[test]
fn default_context_without_default_crypto_has_no_fallback() {
    assert!(reqsign::crypto::get_default().is_none());
    let err = reqsign::default_context()
        .crypto_provider()
        .expect_err("default-context alone must not resolve a provider");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
}
