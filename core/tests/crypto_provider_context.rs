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
use reqsign_core::{Context, hash};
use support::ByteProvider;

#[test]
fn context_resolution_prefers_explicit_then_global() {
    let bare = Context::new();
    assert!(
        bare.crypto_provider().is_err(),
        "a bare context must fail before a global provider exists"
    );

    let explicit = Context::new().with_crypto(ByteProvider(2));
    assert_eq!(
        hash::sha256(
            explicit.crypto_provider().expect("explicit must resolve"),
            b"x"
        )
        .expect("explicit hashing must succeed"),
        [2; 32]
    );

    let unbound = Context::new();
    assert!(
        get_default().is_none(),
        "creating a context must not install"
    );
    install_default(ByteProvider(9)).expect("global installation must succeed");

    assert_eq!(
        hash::sha256(
            unbound.crypto_provider().expect("global must resolve"),
            b"x"
        )
        .expect("global hashing must succeed"),
        [9; 32],
        "an unbound context must observe the process-wide provider"
    );
    assert_eq!(
        hash::sha256(
            explicit.crypto_provider().expect("explicit must resolve"),
            b"x"
        )
        .expect("explicit hashing must succeed"),
        [2; 32],
        "an explicit binding must keep priority over the global provider"
    );

    let first = Context::new().with_crypto(ByteProvider(4));
    let second = Context::new().with_crypto(ByteProvider(5));
    assert_eq!(
        hash::sha256(
            first.crypto_provider().expect("first context must resolve"),
            b"x"
        )
        .expect("first context hashing must succeed"),
        [4; 32]
    );
    assert_eq!(
        hash::sha256(
            second
                .crypto_provider()
                .expect("second context must resolve"),
            b"x"
        )
        .expect("second context hashing must succeed"),
        [5; 32]
    );
}
