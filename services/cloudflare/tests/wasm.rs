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

use reqsign_cloudflare::{DefaultCredentialProvider, RequestSigner, StaticCredentialProvider};
use reqsign_core::{Context, ErrorKind, Signer, StaticEnv};
use std::collections::HashMap;
use wasm_bindgen_test::*;

fn request() -> http::request::Parts {
    http::Request::get(
        "https://api.cloudflare.com/client/v4/accounts/fake-account/storage/kv/namespaces/fake-namespace/values/fake-key",
    )
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

#[wasm_bindgen_test]
async fn env_token_signs_without_a_clock() {
    let context = Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([(
            "CLOUDFLARE_API_TOKEN".to_string(),
            "fake-wasm-api-token".to_string(),
        )]),
    });
    let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must work");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer fake-wasm-api-token");
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn static_token_signs_without_a_clock() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("fake-wasm-static-token"),
        RequestSigner,
    );
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must work");

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-wasm-static-token"
    );
}

#[wasm_bindgen_test]
async fn missing_token_fails_without_a_clock() {
    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("no token must not sign");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
}
