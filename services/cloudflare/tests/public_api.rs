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

use reqsign_cloudflare::{
    Credential, DefaultCredentialProvider, EnvCredentialProvider, RequestSigner,
    StaticCredentialProvider,
};
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, ErrorKind, ProvideCredential, ProvideCredentialChain, Result, SignRequest, Signer,
    SigningCredential, StaticEnv,
};
use std::collections::HashMap;
use std::time::Duration;

const ENV_TOKEN: &str = "fake-env-api-token-A1";
const STATIC_TOKEN: &str = "fake-static-api-token-B2";
const ACCOUNT_ID: &str = "fake-account-0001";
const NAMESPACE_ID: &str = "fake-namespace-0002";
const DATABASE_ID: &str = "fake-database-0003";
const AUTHORIZATION: http::header::HeaderName = http::header::AUTHORIZATION;

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn env_context(api_token: &str) -> Context {
    context(HashMap::from([(
        "CLOUDFLARE_API_TOKEN".to_string(),
        api_token.to_string(),
    )]))
}

fn kv_request() -> http::request::Parts {
    http::Request::put(format!(
        "https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/storage/kv/namespaces/{NAMESPACE_ID}/values/owner%2Fnotes.txt?expiration_ttl=60"
    ))
    .header(
        http::header::CONTENT_TYPE,
        "multipart/form-data; boundary=----fake-boundary",
    )
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

fn d1_request() -> http::request::Parts {
    http::Request::post(format!(
        "https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/d1/database/{DATABASE_ID}/query"
    ))
    .header(http::header::CONTENT_TYPE, "application/json")
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

async fn sign_with_static(mut parts: http::request::Parts) -> Result<http::request::Parts> {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    signer.sign(&mut parts, None).await?;
    Ok(parts)
}

#[tokio::test]
async fn kv_and_d1_requests_are_signed_without_touching_the_wire_request() -> Result<()> {
    for original in [kv_request(), d1_request()] {
        let signed = sign_with_static(original.clone()).await?;

        let authorization = &signed.headers[AUTHORIZATION];
        assert_eq!(
            authorization.to_str().expect("header must be text"),
            format!("Bearer {STATIC_TOKEN}")
        );
        assert!(authorization.is_sensitive());
        assert_eq!(signed.uri, original.uri);
        assert_eq!(signed.method, original.method);
        assert_eq!(
            signed.headers[http::header::CONTENT_TYPE],
            original.headers[http::header::CONTENT_TYPE]
        );
        assert_eq!(signed.headers.len(), original.headers.len() + 1);
    }

    Ok(())
}

#[tokio::test]
async fn reused_request_has_its_stale_authorization_replaced() -> Result<()> {
    let mut original = d1_request();
    original.headers.insert(
        AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-fake-api-token-C3"),
    );

    let signed = sign_with_static(original).await?;

    assert_eq!(
        signed.headers[AUTHORIZATION],
        format!("Bearer {STATIC_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn environment_token_is_discovered_and_signs() -> Result<()> {
    let ctx = env_context(ENV_TOKEN);
    let provider = DefaultCredentialProvider::new();
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("env token must be discovered");
    assert_eq!(credential.api_token(), ENV_TOKEN);

    let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
    let mut parts = kv_request();
    signer.sign(&mut parts, None).await?;

    assert_eq!(parts.headers[AUTHORIZATION], format!("Bearer {ENV_TOKEN}"));

    Ok(())
}

#[tokio::test]
async fn empty_environment_value_is_absent_and_signing_fails_closed() -> Result<()> {
    let ctx = env_context("");
    assert!(
        DefaultCredentialProvider::new()
            .provide_credential(&ctx)
            .await?
            .is_none()
    );

    let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
    let original = kv_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an absent token must not sign");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn malformed_environment_value_fails_closed_without_echoing_it() -> Result<()> {
    let malformed = format!("{ENV_TOKEN}\nHeader-Injected: 1");
    let ctx = env_context(&malformed);

    let error = DefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect_err("a malformed token must be reported");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(error.to_string().contains("CLOUDFLARE_API_TOKEN"));
    assert!(!error.to_string().contains(ENV_TOKEN));
    assert!(!format!("{error:?}").contains(ENV_TOKEN));

    Ok(())
}

#[tokio::test]
async fn prepended_static_provider_takes_precedence_over_the_environment() -> Result<()> {
    let ctx = env_context(ENV_TOKEN);
    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(STATIC_TOKEN));

    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("prepended provider must win");
    assert_eq!(credential.api_token(), STATIC_TOKEN);

    Ok(())
}

#[tokio::test]
async fn invalid_prepended_provider_never_falls_through_to_the_environment() -> Result<()> {
    let ctx = env_context(ENV_TOKEN);
    let provider = DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(""));

    let error = provider
        .provide_credential(&ctx)
        .await
        .expect_err("an invalid explicit credential must not switch identity");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

    Ok(())
}

#[tokio::test]
async fn builder_slot_removal_and_readdition_control_the_environment() -> Result<()> {
    let ctx = env_context(ENV_TOKEN);

    let default_provider = DefaultCredentialProvider::builder().build();
    assert_eq!(
        default_provider
            .provide_credential(&ctx)
            .await?
            .expect("default slot must be enabled")
            .api_token(),
        ENV_TOKEN
    );

    let removed = DefaultCredentialProvider::builder().no_env().build();
    assert!(
        removed.provide_credential(&ctx).await?.is_none(),
        "no_env must remove the slot"
    );

    let readded = DefaultCredentialProvider::builder()
        .no_env()
        .env(EnvCredentialProvider::new())
        .build();
    assert_eq!(
        readded
            .provide_credential(&ctx)
            .await?
            .expect("a later positive slot call must re-enable the slot")
            .api_token(),
        ENV_TOKEN
    );

    Ok(())
}

#[tokio::test]
async fn caller_supplied_chain_keeps_the_chain_error_policy() -> Result<()> {
    let ctx = env_context(ENV_TOKEN);
    let chain = ProvideCredentialChain::new()
        .push(StaticCredentialProvider::new(""))
        .push(EnvCredentialProvider::new());

    let provider = DefaultCredentialProvider::with_chain(chain);
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("a caller-supplied chain continues past provider errors");

    assert_eq!(credential.api_token(), ENV_TOKEN);

    Ok(())
}

#[tokio::test]
async fn signer_override_replaces_ambient_discovery() -> Result<()> {
    let signer = Signer::new(
        env_context(ENV_TOKEN),
        DefaultCredentialProvider::new(),
        RequestSigner,
    )
    .with_credential_provider(StaticCredentialProvider::new(STATIC_TOKEN));

    let mut parts = d1_request();
    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {STATIC_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn missing_credential_fails_without_mutating_the_request() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let original = d1_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("no credential must not sign");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn expires_in_is_rejected_before_any_header_changes() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    let original = kv_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("Cloudflare has no query authentication");

    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn direct_signer_call_requires_a_credential() -> Result<()> {
    let credential = Credential::new(STATIC_TOKEN)?;
    let signer = RequestSigner;
    let mut parts = kv_request();

    signer
        .sign_request(&Context::new(), &mut parts, Some(&credential), None)
        .await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {STATIC_TOKEN}")
    );

    let mut missing = kv_request();
    let error = signer
        .sign_request(&Context::new(), &mut missing, None, None)
        .await
        .expect_err("direct callers must supply a credential");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!missing.headers.contains_key(AUTHORIZATION));

    Ok(())
}

#[test]
fn signing_deadline_is_constant_and_does_not_read_the_clock() {
    let credential = Credential::new(STATIC_TOKEN).expect("token must be valid");
    let signer = RequestSigner;

    assert_eq!(
        signer.required_valid_until(&credential, None),
        Timestamp::default()
    );
    assert_eq!(
        signer.required_valid_until(&credential, Some(Duration::from_secs(60))),
        Timestamp::default()
    );
    assert!(credential.is_valid_at(Timestamp::default()));
}

#[tokio::test]
async fn credential_rejects_values_that_cannot_become_a_header() {
    for invalid in [
        "",
        "fake token with space",
        "fake-token\r\nX-Injected: 1",
        "令牌",
    ] {
        let error = Credential::new(invalid).expect_err("invalid token must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        if !invalid.is_empty() {
            assert!(!error.to_string().contains(invalid));
        }
    }
}

#[test]
fn debug_output_redacts_token_material() {
    let credential = Credential::new(STATIC_TOKEN).expect("token must be valid");
    let static_provider = StaticCredentialProvider::new(STATIC_TOKEN);
    let default_provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(STATIC_TOKEN));

    for debug in [
        format!("{credential:?}"),
        format!("{static_provider:?}"),
        format!("{default_provider:?}"),
        format!("{default_provider:?} {static_provider:?} {credential:?}"),
    ] {
        assert!(!debug.contains(STATIC_TOKEN));
    }
}
