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

use reqsign_core::Context;
use reqsign_core::ErrorKind;
use reqsign_core::crypto::get_default;

#[test]
fn bare_context_without_a_provider_returns_config_invalid() {
    assert!(get_default().is_none());

    let err = Context::new()
        .crypto_provider()
        .expect_err("a bare context without a provider must fail");
    assert_eq!(err.kind(), ErrorKind::ConfigInvalid);
    assert!(!err.is_retryable());
}
