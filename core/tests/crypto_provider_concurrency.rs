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

use std::sync::{Arc, Barrier};

use reqsign_core::crypto::{get_default, install_default};
use support::TestProvider;

#[test]
fn concurrent_installation_elects_exactly_one_provider() {
    const NAMES: [&str; 16] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    ];

    let barrier = Arc::new(Barrier::new(NAMES.len()));
    let handles = NAMES
        .into_iter()
        .map(|name| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                install_default(TestProvider::new(name))
            })
        })
        .collect::<Vec<_>>();

    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("install thread must not panic"))
        .collect::<Vec<_>>();

    let winners = results.iter().filter(|result| result.is_ok()).count();
    let installed = get_default().expect("one provider must be installed");

    assert_eq!(winners, 1, "exactly one concurrent install must succeed");
    for rejected in results.iter().filter_map(|result| result.as_ref().err()) {
        assert!(
            !Arc::ptr_eq(rejected, installed),
            "a rejected provider must not be the installed provider"
        );
    }
}
