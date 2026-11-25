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

use std::sync::Arc;

use reqsign_core::Context;
use reqsign_core::crypto::CryptoProvider;
use support::crypto_arc::{MarkerProvider, assert_all_forwarded};

#[test]
fn arc_forwards_every_method_of_a_dyn_provider() {
    let provider: Arc<dyn CryptoProvider> = Arc::new(MarkerProvider);

    // `P = Arc<dyn CryptoProvider>` forces the calls through the blanket impl.
    // Calling methods on the Arc directly could autoderef to the inner dyn
    // provider and hide a missing forwarding method.
    assert_all_forwarded::<Arc<dyn CryptoProvider>>(&provider);
}

#[test]
fn context_with_crypto_accepts_an_arc_dyn_provider() {
    let provider: Arc<dyn CryptoProvider> = Arc::new(MarkerProvider);
    let context = Context::new().with_crypto(provider);
    let resolved = context
        .crypto_provider()
        .expect("the explicit Arc provider must resolve");

    assert_eq!(
        resolved
            .sha256(b"marker input")
            .expect("the Arc provider must forward sha256"),
        [2; 32]
    );
}
