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

#![cfg(feature = "aws-bearer")]

use std::time::Duration;

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Request, Version, request::Parts};
use reqsign::aws::bearer::{
    Credential, EnvCredentialProvider, RequestSigner, StaticCredentialProvider, default_signer,
};
use reqsign::{Context, ErrorKind, ProvideCredential, Result, SignRequest, Signer, StaticEnv};

fn context(variables: &[(&str, &str)]) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: variables
            .iter()
            .map(|&(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    })
}

fn request() -> Parts {
    Request::post(
        "https://bedrock-runtime.us-west-2.amazonaws.com/model/a%2Fb/invoke?k=%2f&k=a+b&empty=",
    )
    .version(Version::HTTP_2)
    .header(AUTHORIZATION, "previous-authentication")
    .header(AUTHORIZATION, "duplicate-authentication")
    .header(CONTENT_TYPE, "application/json")
    .extension("caller extension")
    .body(())
    .unwrap()
    .into_parts()
    .0
}

fn assert_same_request(actual: &Parts, expected: &Parts) {
    assert_eq!(actual.method, expected.method);
    assert_eq!(actual.version, expected.version);
    assert_eq!(actual.uri.to_string(), expected.uri.to_string());
    assert_eq!(actual.headers, expected.headers);
    assert_eq!(
        actual.extensions.get::<&str>(),
        expected.extensions.get::<&str>()
    );
}

#[tokio::test]
async fn environment_token_is_selected_by_signing_name() -> Result<()> {
    let ctx = context(&[
        ("AWS_BEARER_TOKEN_BEDROCK", "fake-bedrock-token"),
        ("AWS_BEARER_TOKEN_EXAMPLE_API_SERVICE", "fake-other-token"),
    ]);

    for (signing_name, authorization) in [
        ("bedrock", "Bearer fake-bedrock-token"),
        ("Example-API Service", "Bearer fake-other-token"),
    ] {
        let signer = default_signer(ctx.clone(), signing_name)?;
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(parts.headers[AUTHORIZATION], authorization);
        assert!(parts.headers[AUTHORIZATION].is_sensitive());
    }
    Ok(())
}

#[test]
fn invalid_signing_names_are_rejected_at_construction() {
    for name in ["", " \t", "name=value", "name\0value"] {
        let error = default_signer(Context::new(), name).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
}

#[tokio::test]
async fn static_token_replaces_only_authorization_and_is_redacted() -> Result<()> {
    let provider = StaticCredentialProvider::new("ZX9.static-token+value/1~_==")?;
    let provider_debug = format!("{provider:?}");
    let signer = Signer::new(Context::new(), provider, RequestSigner);
    let credential = signer.credential_for(None).await?;

    let mut parts = request();
    signer.sign(&mut parts, None).await?;

    let mut expected = request();
    expected.headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer ZX9.static-token+value/1~_=="),
    );
    assert_same_request(&parts, &expected);
    assert!(parts.headers[AUTHORIZATION].is_sensitive());
    for debug in [
        provider_debug,
        format!("{credential:?}"),
        format!("{parts:?}"),
        format!("{signer:?}"),
    ] {
        assert!(!debug.contains("ZX9"));
        assert!(!debug.contains("_=="));
    }
    Ok(())
}

#[tokio::test]
async fn missing_and_empty_environment_tokens_do_not_fall_back() -> Result<()> {
    let unrelated_tokens = [
        ("AWS_BEARER_TOKEN_BEDROCK", "fake-bedrock-token"),
        ("AWS_BEARER_TOKEN", "fake-unscoped-token"),
        ("AWS_SESSION_TOKEN", "fake-session-token"),
    ];
    let mut with_empty = unrelated_tokens.to_vec();
    with_empty.push(("AWS_BEARER_TOKEN_EXAMPLE", ""));

    for variables in [&unrelated_tokens[..], &with_empty] {
        let ctx = context(variables);
        let provider = EnvCredentialProvider::new("example")?;
        assert!(provider.provide_credential(&ctx).await?.is_none());
        let signer = default_signer(ctx, "example")?;
        let original = request();
        let mut parts = original.clone();
        let error = signer.sign(&mut parts, None).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_same_request(&parts, &original);
    }
    Ok(())
}

#[tokio::test]
async fn malformed_tokens_are_rejected_without_leaking_the_input() -> Result<()> {
    const INVALID: &str = "fake-secret-token\r\nInjected: header";

    for token in [
        "",
        "=",
        "fake-secret-token=inside",
        "fake-secret-token with spaces",
        INVALID,
    ] {
        let error = StaticCredentialProvider::new(token).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert!(!format!("{error:?} {error}").contains("fake-secret-token"));
    }

    let signer = default_signer(context(&[("AWS_BEARER_TOKEN_BEDROCK", INVALID)]), "bedrock")?;
    let original = request();
    let mut parts = original.clone();
    let error = signer.sign(&mut parts, None).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!format!("{error:?} {error}").contains("fake-secret-token"));
    assert_same_request(&parts, &original);
    Ok(())
}

#[tokio::test]
async fn presigning_leaves_the_request_unchanged() -> Result<()> {
    let ctx = Context::new();
    let credential = Credential::new("fake-presign-token")?;
    let provider = StaticCredentialProvider::new("fake-presign-token")?;
    let signer = Signer::new(ctx.clone(), provider, RequestSigner);
    let original = request();
    let mut parts = original.clone();
    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(30)))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_same_request(&parts, &original);

    let error = RequestSigner
        .sign_request(&ctx, &mut parts, Some(&credential), Some(Duration::ZERO))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_same_request(&parts, &original);
    Ok(())
}

#[tokio::test]
async fn relative_uri_is_rejected_without_mutating_the_request() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("fake-relative-uri-token")?,
        RequestSigner,
    );
    let mut original = request();
    original.uri = "/model/example/invoke".parse().unwrap();
    let mut parts = original.clone();
    let error = signer.sign(&mut parts, None).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_same_request(&parts, &original);
    Ok(())
}
