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

//! The facade exposes a provider but must never install one implicitly.

#[cfg(feature = "default-context")]
#[test]
fn default_context_does_not_install_a_crypto_provider() {
    let _ = reqsign::default_context();
    assert!(
        reqsign::crypto::get_default().is_none(),
        "default_context must leave provider installation to the application"
    );
}
