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

use http::Request;
use http::header::{AUTHORIZATION, DATE};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_upyun::{RequestSigner, StaticCredentialProvider};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn signs_the_published_upyun_vector_on_wasm() {
    let signing_time: Timestamp = "2016-11-09T14:26:58Z".parse().expect("timestamp parses");
    let signer = Signer::new(
        Context::new().with_crypto(RustCryptoProvider::new()),
        StaticCredentialProvider::new("operator123", "password123"),
        RequestSigner::new().with_time(signing_time),
    );
    let mut req = Request::put("https://v0.api.upyun.com/upyun-temp/demo.jpg")
        .header("content-md5", "7ac66c0f148de9519b8bd264312c4d64")
        .body(())
        .expect("request builds")
        .into_parts()
        .0;

    signer
        .sign(&mut req, None)
        .await
        .expect("signing must succeed");

    assert_eq!(req.headers[DATE], "Wed, 09 Nov 2016 14:26:58 GMT");
    assert_eq!(
        req.headers[AUTHORIZATION],
        "UPYUN operator123:YUaAZX+WNAcJdNGHS5SBlITME5A="
    );
}
