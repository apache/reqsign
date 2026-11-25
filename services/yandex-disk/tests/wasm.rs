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

use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ErrorKind, ProvideCredentialChain, Signer};
use reqsign_yandex_disk::{Credential, RequestSigner, StaticCredentialProvider};
use wasm_bindgen_test::*;

const TOKEN: &str = "fake-wasm-yandex-disk-token-H6";

fn request() -> http::request::Parts {
    http::Request::get(
        "https://cloud-api.yandex.net/v1/disk/resources?path=disk%3A%2Ffolder%2Ffile",
    )
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

#[wasm_bindgen_test]
async fn static_token_signs_without_a_clock() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(TOKEN),
        RequestSigner,
    );
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must work");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(
        authorization.to_str().expect("Authorization must be text"),
        format!("OAuth {TOKEN}")
    );
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn expiring_token_signs_with_the_js_clock() {
    let credential = StaticCredentialProvider::new(TOKEN)
        .with_expires_at(Timestamp::now() + Duration::from_secs(3_600));
    let signer = Signer::new(Context::new(), credential, RequestSigner);
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("expiring token must sign");

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        format!("OAuth {TOKEN}")
    );
}

#[wasm_bindgen_test]
async fn deliberate_empty_chain_fails_without_mutating_the_request() {
    let signer = Signer::new(
        Context::new(),
        ProvideCredentialChain::<Credential>::new(),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("a deliberate empty chain must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
}
