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
use reqsign_dropbox::{DefaultCredentialProvider, RequestSigner};
use std::collections::HashMap;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn public_default_signer_uses_the_wasm_clock() {
    let context = Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([(
            "DBXCLI_ACCESS_TOKEN".to_string(),
            "wasm-dropbox-token".to_string(),
        )]),
    });
    let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);
    let mut parts = http::Request::get("https://api.dropboxapi.com/2/users/get_current_account")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("Dropbox signing must succeed");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer wasm-dropbox-token");
    assert!(authorization.is_sensitive());
}
