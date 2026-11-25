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

//! This test binary installs the process-wide provider on purpose. Keep it
//! separate so the Arc forwarding tests cannot observe that global state.

mod support;

use std::sync::Arc;

use reqsign_core::crypto::{CryptoProvider, get_default, install_default};
use support::crypto_arc::MarkerProvider;

#[test]
fn install_default_accepts_an_arc_dyn_provider() {
    let provider: Arc<dyn CryptoProvider> = Arc::new(MarkerProvider);

    install_default(provider).expect("an Arc<dyn CryptoProvider> must install");
    let installed = get_default().expect("the provider must be installed");

    assert_eq!(
        installed
            .sha256(b"marker input")
            .expect("the installed Arc provider must forward sha256"),
        [2; 32]
    );
}
