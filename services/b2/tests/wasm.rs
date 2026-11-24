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
use reqsign_b2::{Credential, RequestSigner, StaticCredentialProvider};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Signer};
use wasm_bindgen_test::*;

const TOKEN: &str = "fabricated-b2-wasm-authorization";
const API_URL: &str = "https://api001.backblazeb2.com";
const DOWNLOAD_URL: &str = "https://f001.backblazeb2.com";

fn credential() -> Credential {
    Credential::new(TOKEN, API_URL, DOWNLOAD_URL)
}

fn request() -> http::request::Parts {
    http::Request::get(format!(
        "{API_URL}/b2api/v4/b2_list_buckets?accountId=account"
    ))
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

#[wasm_bindgen_test]
async fn static_credential_without_expiry_signs_with_the_js_clock() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(credential()),
        RequestSigner,
    );
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("static B2 credential must sign");

    let authorization = parts
        .headers
        .get(AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(TOKEN, authorization);
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn expiring_credential_signs_with_the_js_clock() {
    let credential = credential().with_expires_at(Timestamp::now() + Duration::from_secs(3_600));
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(credential),
        RequestSigner,
    );
    let mut parts = request();

    signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect("expiring B2 credential must sign");

    assert_eq!(TOKEN, parts.headers[AUTHORIZATION]);
}
