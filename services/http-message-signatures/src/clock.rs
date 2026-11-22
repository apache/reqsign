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

//! The signer's clock source.
//!
//! On `wasm32-unknown-unknown`, Jiff is built with its `js` feature so time is
//! read from the JavaScript host. This requires a wasm-bindgen host such as a
//! browser or Node; a bare WASM runtime without a JavaScript clock is not a
//! supported host.

use reqsign_core::time::Timestamp;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn now() -> Timestamp {
    Timestamp::now()
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn now() -> Timestamp {
    let now = jiff::Timestamp::now();
    Timestamp::from_millisecond(now.as_millisecond())
        .expect("Jiff's current timestamp is within reqsign's timestamp range")
}
