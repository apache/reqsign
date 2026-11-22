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

use reqsign_core::{Context, ErrorKind, Signer, StaticEnv};
use reqsign_vercel::{
    ArtifactsDefaultCredentialProvider, ArtifactsRequestSigner, ArtifactsStaticCredentialProvider,
    BlobDefaultCredentialProvider, BlobRequestSigner, BlobStaticCredentialProvider,
};
use std::collections::HashMap;
use wasm_bindgen_test::*;

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn blob_request() -> http::request::Parts {
    http::Request::put("https://vercel.com/api/blob/reports/example.csv?addRandomSuffix=0")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn artifacts_request() -> http::request::Parts {
    http::Request::put("https://api.vercel.com/v8/artifacts/example-hash?teamId=team_example")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[wasm_bindgen_test]
async fn blob_environment_token_signs_without_a_clock() {
    let context = context(HashMap::from([(
        "BLOB_READ_WRITE_TOKEN".to_string(),
        "fake-wasm-blob-token".to_string(),
    )]));
    let signer = Signer::new(
        context,
        BlobDefaultCredentialProvider::new(),
        BlobRequestSigner,
    );
    let mut parts = blob_request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must work");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer fake-wasm-blob-token");
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn artifacts_environment_token_signs_without_a_clock() {
    let context = context(HashMap::from([(
        "TURBO_TOKEN".to_string(),
        "fake-wasm-artifacts-token".to_string(),
    )]));
    let signer = Signer::new(
        context,
        ArtifactsDefaultCredentialProvider::new(),
        ArtifactsRequestSigner,
    );
    let mut parts = artifacts_request();

    signer
        .sign(&mut parts, None)
        .await
        .expect("signing must work");

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-wasm-artifacts-token"
    );
}

#[wasm_bindgen_test]
async fn static_tokens_sign_without_a_clock() {
    let blob = Signer::new(
        Context::new(),
        BlobStaticCredentialProvider::new("fake-wasm-blob-static-token"),
        BlobRequestSigner,
    );
    let mut parts = blob_request();
    blob.sign(&mut parts, None)
        .await
        .expect("Blob signing must work");
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-wasm-blob-static-token"
    );

    let artifacts = Signer::new(
        Context::new(),
        ArtifactsStaticCredentialProvider::new("fake-wasm-artifacts-static-token"),
        ArtifactsRequestSigner,
    );
    let mut parts = artifacts_request();
    artifacts
        .sign(&mut parts, None)
        .await
        .expect("Artifacts signing must work");
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-wasm-artifacts-static-token"
    );
}

#[wasm_bindgen_test]
async fn missing_tokens_fail_without_a_clock() {
    let blob = Signer::new(
        Context::new(),
        BlobDefaultCredentialProvider::new(),
        BlobRequestSigner,
    );
    let original = blob_request();
    let mut parts = original.clone();
    let error = blob
        .sign(&mut parts, None)
        .await
        .expect_err("no Blob token must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let artifacts = Signer::new(
        Context::new(),
        ArtifactsDefaultCredentialProvider::new(),
        ArtifactsRequestSigner,
    );
    let original = artifacts_request();
    let mut parts = original.clone();
    let error = artifacts
        .sign(&mut parts, None)
        .await
        .expect_err("no Artifacts token must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
}
