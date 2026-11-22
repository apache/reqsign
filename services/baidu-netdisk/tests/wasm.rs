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

use reqsign_baidu_netdisk::{RequestSigner, StaticCredentialProvider};
use reqsign_core::{Context, Signer};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn static_token_signs_without_a_clock() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("fabricated-token"),
        RequestSigner,
    );
    let mut parts = http::Request::get(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=list&dir=%2Fapps%2FMyApp",
    )
    .body(())
    .expect("request must build")
    .into_parts()
    .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must work");

    assert_eq!(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=list&dir=%2Fapps%2FMyApp&access_token=fabricated-token",
        parts.uri.to_string()
    );
}
