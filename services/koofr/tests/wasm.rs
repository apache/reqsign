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

#![cfg(target_arch = "wasm32")]

use std::time::Duration;

use http::header::AUTHORIZATION;
use reqsign_core::{Context, Signer};
use reqsign_koofr::{RequestSigner, StaticCredentialProvider};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn signs_without_a_clock_and_ignores_expires_in() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("fabricated-koofr-token"),
        RequestSigner,
    );
    let mut parts = http::Request::get(
        "https://app.koofr.net/api/v2/mounts/primary/files/list?path=%2Fdata&limit=10",
    )
    .body(())
    .expect("request must build")
    .into_parts()
    .0;

    signer
        .sign(&mut parts, Some(Duration::MAX))
        .await
        .expect("Koofr signing must not read the clock or evaluate expires_in");

    let authorization = parts
        .headers
        .get(AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!("Token token=fabricated-koofr-token", authorization);
    assert!(authorization.is_sensitive());
}
