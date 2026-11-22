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

use reqsign_core::{Context, Signer, StaticEnv};
use reqsign_github::{DefaultCredentialProvider, RequestSigner, StaticCredentialProvider};
use std::collections::HashMap;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn env_token_signs_without_a_clock() {
    let context = Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([("GH_TOKEN".to_string(), "wasm-github-token".to_string())]),
    });
    let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("GitHub signing must succeed");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer wasm-github-token");
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn static_token_signs_without_a_command_adapter() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("wasm-static-github-token"),
        RequestSigner,
    );
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("static GitHub signing must succeed");

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer wasm-static-github-token"
    );
}

#[wasm_bindgen_test]
async fn no_token_falls_back_to_anonymous_without_a_command_adapter() {
    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .header(
            http::header::AUTHORIZATION,
            "Bearer stale-wasm-github-token",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("anonymous GitHub signing must succeed");

    assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
}
