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

#![cfg(not(target_arch = "wasm32"))]

use std::time::Duration;

use reqsign_baidu_netdisk::{Credential, RequestSigner, StaticCredentialProvider};
use reqsign_core::{Context, ErrorKind, ProvideCredential, Result, Signer};

fn request(uri: &str) -> http::request::Parts {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .header(http::header::USER_AGENT, "caller-agent")
        .header("x-caller", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn signer(access_token: &str) -> Signer<Credential> {
    Signer::new(
        Context::new(),
        StaticCredentialProvider::new(access_token),
        RequestSigner,
    )
}

#[tokio::test]
async fn signer_appends_a_form_encoded_access_token() {
    let mut parts = request("https://pan.baidu.com/rest/2.0/xpan/file");
    let original_headers = parts.headers.clone();

    signer("fabricated token")
        .sign(&mut parts, None)
        .await
        .expect("signing must succeed");

    let query = parts.uri.query().expect("query must be present");
    assert_eq!("access_token=fabricated+token", query);
    assert_eq!(original_headers, parts.headers);
}

#[tokio::test]
async fn re_signing_replaces_authentication_and_preserves_wire_query() {
    let mut parts = request(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=meta&path=%2Fapps%2FMyApp%2Fa+b&empty=&dup=1&dup=2&access%5Ftoken=stale&access_token=older",
    );
    let original_headers = parts.headers.clone();
    let signer = signer("fresh-token");

    signer
        .sign(&mut parts, None)
        .await
        .expect("first signing must succeed");
    assert_eq!(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=meta&path=%2Fapps%2FMyApp%2Fa+b&empty=&dup=1&dup=2&access_token=fresh-token",
        parts.uri.to_string()
    );
    assert_eq!(original_headers, parts.headers);

    let signer = signer.with_credential_provider(StaticCredentialProvider::new("rotated-token"));
    signer
        .sign(&mut parts, None)
        .await
        .expect("second signing must succeed");
    assert_eq!(
        "https://pan.baidu.com/rest/2.0/xpan/file?method=meta&path=%2Fapps%2FMyApp%2Fa+b&empty=&dup=1&dup=2&access_token=rotated-token",
        parts.uri.to_string()
    );
    assert_eq!(original_headers, parts.headers);
}

#[derive(Debug)]
struct MissingProvider;

impl ProvideCredential for MissingProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(None)
    }
}

#[derive(Debug)]
struct EmptyProvider;

impl ProvideCredential for EmptyProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        Ok(Some(Credential::new("")))
    }
}

#[tokio::test]
async fn unavailable_or_empty_credentials_fail_without_mutating_the_request() {
    for signer in [
        Signer::new(Context::new(), MissingProvider, RequestSigner),
        Signer::new(Context::new(), EmptyProvider, RequestSigner),
    ] {
        let original = request("https://pan.baidu.com/rest/2.0/xpan/file?method=list");
        let mut parts = original.clone();

        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("invalid credential must fail");

        assert_eq!(ErrorKind::CredentialInvalid, error.kind());
        assert_eq!(original.uri, parts.uri);
        assert_eq!(original.headers, parts.headers);
    }
}

#[tokio::test]
async fn empty_static_token_is_rejected_before_it_enters_the_cache() {
    let original = request("https://pan.baidu.com/rest/2.0/xpan/file?method=list");
    let mut parts = original.clone();

    let error = signer("")
        .sign(&mut parts, None)
        .await
        .expect_err("empty static token must fail");

    assert_eq!(ErrorKind::ConfigInvalid, error.kind());
    assert_eq!(original.uri, parts.uri);
    assert_eq!(original.headers, parts.headers);
}

#[tokio::test]
async fn expires_in_is_rejected_without_mutating_the_request() {
    let original = request("https://pan.baidu.com/rest/2.0/xpan/file?method=list");
    let mut parts = original.clone();

    let error = signer("fabricated-token")
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("expires_in must be rejected");

    assert_eq!(ErrorKind::RequestInvalid, error.kind());
    assert_eq!(original.uri, parts.uri);
    assert_eq!(original.headers, parts.headers);
}

#[test]
fn debug_redacts_the_token_in_credentials_and_providers() {
    let credential_debug = format!("{:?}", Credential::new("baseline-token"));
    let provider_debug = format!("{:?}", StaticCredentialProvider::new("baseline-token"));

    for token in [
        "fabricated-secret-token-value",
        "密码密码密码",
        "fabricated-secret-gfs37fb5",
    ] {
        let credential = Credential::new(token);
        let provider = StaticCredentialProvider::new(token);

        assert_eq!(token, credential.access_token());
        assert_eq!(credential_debug, format!("{credential:?}"));
        assert_eq!(provider_debug, format!("{provider:?}"));
        assert!(!credential_debug.contains(token));
        assert!(!provider_debug.contains(token));
    }
}
