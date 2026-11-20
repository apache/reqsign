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

use reqsign_core::crypto::{get_default, install_default};
use support::ByteProvider;

#[test]
fn second_installation_returns_the_rejected_provider_without_replacing_first() {
    install_default(ByteProvider(1)).expect("first install must succeed");
    let installed = get_default().expect("provider must be installed");
    assert_eq!(
        installed
            .sha256(b"probe")
            .expect("installed provider hashing must succeed"),
        [1; 32],
        "the first provider must be installed"
    );

    let rejected = install_default(ByteProvider(2)).expect_err("second install must be rejected");

    assert_eq!(
        rejected
            .sha256(b"probe")
            .expect("rejected provider hashing must succeed"),
        [2; 32],
        "the error must return the provider that was not installed"
    );
    assert_eq!(
        get_default()
            .expect("provider must stay installed")
            .sha256(b"probe")
            .expect("installed provider hashing must succeed"),
        [1; 32],
        "the first provider must remain installed"
    );
}
