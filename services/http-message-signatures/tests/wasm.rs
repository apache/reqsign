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

use reqsign_core::{Context, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use reqsign_http_message_signatures::{
    Component, Credential, RequestSigner, StaticCredentialProvider,
};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
async fn public_signer_signs_hmac_with_the_wasm_clock() {
    let credential = Credential::hmac_sha256("wasm-test-key", b"shared secret")
        .expect("credential must be valid");
    let request_signer = RequestSigner::new(
        "sig1",
        [Component::Method, Component::Authority, Component::Path],
    )
    .expect("policy must be valid");
    let signer = Signer::new(
        Context::new().with_crypto(RustCryptoProvider::new()),
        StaticCredentialProvider::new(credential),
        request_signer,
    );

    let mut parts = http::Request::builder()
        .method("POST")
        .uri("https://example.com/resource?b=2&a=1")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("HMAC signing must succeed");

    let signature_input = parts
        .headers
        .get("signature-input")
        .expect("Signature-Input must be present")
        .to_str()
        .expect("Signature-Input must be ASCII");
    assert!(signature_input.starts_with("sig1=(\"@method\" \"@authority\" \"@path\")"));
    assert!(signature_input.contains(";created="));
    assert!(signature_input.contains(";keyid=\"wasm-test-key\""));
    assert!(signature_input.contains(";alg=\"hmac-sha256\""));

    let signature = parts
        .headers
        .get("signature")
        .expect("Signature must be present")
        .to_str()
        .expect("Signature must be ASCII");
    assert!(signature.starts_with("sig1=:"));
}
