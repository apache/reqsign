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

#![cfg(feature = "cloudflare")]

use reqsign::cloudflare::{DefaultSigner, StaticCredentialProvider, default_signer};
use reqsign::{Context, ErrorKind, Result, StaticEnv};
use std::collections::HashMap;

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn request() -> http::request::Parts {
    http::Request::put(
        "https://api.cloudflare.com/client/v4/accounts/fake-account/storage/kv/namespaces/fake-namespace/values/fake-key",
    )
    .header(http::header::CONTENT_TYPE, "application/octet-stream")
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

#[tokio::test]
async fn facade_default_signer_reads_the_api_token() -> Result<()> {
    let signer: DefaultSigner = default_signer(context(HashMap::from([(
        "CLOUDFLARE_API_TOKEN".to_string(),
        "fake-facade-api-token".to_string(),
    )])));
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-facade-api-token"
    );
    assert!(parts.headers[http::header::AUTHORIZATION].is_sensitive());
    assert_eq!(
        parts.headers[http::header::CONTENT_TYPE],
        "application/octet-stream"
    );
    Ok(())
}

#[tokio::test]
async fn facade_static_override_replaces_ambient_discovery() -> Result<()> {
    let signer = default_signer(context(HashMap::from([(
        "CLOUDFLARE_API_TOKEN".to_string(),
        "fake-facade-api-token".to_string(),
    )])))
    .with_credential_provider(StaticCredentialProvider::new("fake-facade-static-token"));
    let mut parts = request();
    parts.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-facade-token"),
    );

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-facade-static-token"
    );
    Ok(())
}

#[tokio::test]
async fn facade_without_a_token_fails_without_mutating_the_request() -> Result<()> {
    let signer = default_signer(context(HashMap::new()));
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("a missing token must not sign");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}
