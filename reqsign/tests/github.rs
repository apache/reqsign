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

#![cfg(feature = "github")]

use reqsign::github::{
    AnonymousCredentialProvider, DefaultCredentialProvider, GhCliCredentialProvider,
    StaticCredentialProvider,
};
use reqsign::{Context, ErrorKind, Result, StaticEnv};
use std::collections::HashMap;

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn request() -> http::request::Parts {
    http::Request::get("https://api.github.com/repos/apache/reqsign")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[tokio::test]
async fn facade_default_signer_reads_gh_token() -> Result<()> {
    let signer = reqsign::github::default_signer(context(HashMap::from([(
        "GH_TOKEN".to_string(),
        "facade-env-token".to_string(),
    )])));
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer facade-env-token"
    );
    assert!(parts.headers[http::header::AUTHORIZATION].is_sensitive());
    Ok(())
}

#[tokio::test]
async fn facade_default_signer_uses_static_override_and_anonymous_fallback() -> Result<()> {
    let signer = reqsign::github::default_signer(context(HashMap::new()))
        .with_credential_provider(StaticCredentialProvider::new("facade-static-token"));
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer facade-static-token"
    );

    let signer = reqsign::github::default_signer(context(HashMap::new()));
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));

    let _ = AnonymousCredentialProvider::new();
    let _ = GhCliCredentialProvider::new();
    Ok(())
}

#[tokio::test]
async fn facade_no_anonymous_fails_without_mutating_the_request() -> Result<()> {
    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_gh_cli()
        .no_anonymous()
        .build();
    let signer =
        reqsign::github::default_signer(context(HashMap::new())).with_credential_provider(provider);
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("no_anonymous must remove the fallback");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}
