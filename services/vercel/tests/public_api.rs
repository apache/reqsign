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

use std::collections::HashMap;
use std::time::Duration;

use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, ErrorKind, ProvideCredential, ProvideCredentialChain, Result, SignRequest, Signer,
    StaticEnv,
};
use reqsign_vercel::{
    ArtifactsCredential, ArtifactsDefaultCredentialProvider, ArtifactsEnvCredentialProvider,
    ArtifactsRequestSigner, ArtifactsStaticCredentialProvider,
    ArtifactsVercelEnvCredentialProvider, BlobCredential, BlobDefaultCredentialProvider,
    BlobEnvCredentialProvider, BlobRequestSigner, BlobStaticCredentialProvider,
};

const BLOB_ENV_TOKEN: &str = "fake-blob-env-token-A1";
const BLOB_STATIC_TOKEN: &str = "fake-blob-static-token-B2";
const ARTIFACTS_TURBO_TOKEN: &str = "fake-artifacts-turbo-token-C3";
const ARTIFACTS_VERCEL_TOKEN: &str = "fake-artifacts-vercel-token-D4";
const ARTIFACTS_STATIC_TOKEN: &str = "fake-artifacts-static-token-E5";
const AUTHORIZATION: http::header::HeaderName = http::header::AUTHORIZATION;

fn context<K, V>(envs: impl IntoIterator<Item = (K, V)>) -> Context
where
    K: Into<String>,
    V: Into<String>,
{
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: envs
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect::<HashMap<_, _>>(),
    })
}

fn blob_request() -> http::request::Parts {
    http::Request::put("https://vercel.com/api/blob/reports/2026%20Q1.csv?addRandomSuffix=0")
        .header("x-api-version", "13")
        .header(http::header::CONTENT_TYPE, "text/csv")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn artifacts_request() -> http::request::Parts {
    http::Request::put("https://api.vercel.com/v8/artifacts/example-hash?teamId=team_example")
        .header("x-artifact-duration", "42")
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

#[tokio::test]
async fn blob_static_token_signs_without_touching_the_wire_request() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        BlobStaticCredentialProvider::new(BLOB_STATIC_TOKEN),
        BlobRequestSigner,
    );
    let original = blob_request();
    let mut signed = original.clone();

    signer.sign(&mut signed, None).await?;

    let authorization = &signed.headers[AUTHORIZATION];
    assert_eq!(authorization, &format!("Bearer {BLOB_STATIC_TOKEN}"));
    assert!(authorization.is_sensitive());
    assert_eq!(signed.uri, original.uri);
    assert_eq!(signed.method, original.method);
    assert_eq!(
        signed.headers["x-api-version"],
        original.headers["x-api-version"]
    );
    assert_eq!(
        signed.headers[http::header::CONTENT_TYPE],
        original.headers[http::header::CONTENT_TYPE]
    );
    assert_eq!(signed.headers.len(), original.headers.len() + 1);

    Ok(())
}

#[tokio::test]
async fn artifacts_static_token_signs_without_touching_scope_or_headers() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        ArtifactsStaticCredentialProvider::new(ARTIFACTS_STATIC_TOKEN),
        ArtifactsRequestSigner,
    );
    let original = artifacts_request();
    let mut signed = original.clone();

    signer.sign(&mut signed, None).await?;

    let authorization = &signed.headers[AUTHORIZATION];
    assert_eq!(authorization, &format!("Bearer {ARTIFACTS_STATIC_TOKEN}"));
    assert!(authorization.is_sensitive());
    assert_eq!(signed.uri, original.uri);
    assert_eq!(
        signed.uri.query(),
        Some("teamId=team_example"),
        "the caller owns the cache scope query"
    );
    assert_eq!(
        signed.headers["x-artifact-duration"],
        original.headers["x-artifact-duration"]
    );
    assert_eq!(signed.headers.len(), original.headers.len() + 1);

    Ok(())
}

#[tokio::test]
async fn reused_request_has_its_stale_authorization_replaced() -> Result<()> {
    let blob = Signer::new(
        Context::new(),
        BlobStaticCredentialProvider::new(BLOB_STATIC_TOKEN),
        BlobRequestSigner,
    );
    let mut parts = blob_request();
    parts.headers.insert(
        AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-fake-token"),
    );
    blob.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {BLOB_STATIC_TOKEN}")
    );

    let artifacts = Signer::new(
        Context::new(),
        ArtifactsStaticCredentialProvider::new(ARTIFACTS_STATIC_TOKEN),
        ArtifactsRequestSigner,
    );
    let mut parts = artifacts_request();
    parts.headers.insert(
        AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-fake-token"),
    );
    artifacts.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {ARTIFACTS_STATIC_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn blob_environment_token_is_discovered_and_signs() -> Result<()> {
    let ctx = context([("BLOB_READ_WRITE_TOKEN", BLOB_ENV_TOKEN)]);
    let credential = BlobDefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await?
        .expect("blob token must be discovered");
    assert_eq!(credential.token(), BLOB_ENV_TOKEN);

    let signer = Signer::new(ctx, BlobDefaultCredentialProvider::new(), BlobRequestSigner);
    let mut parts = blob_request();
    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {BLOB_ENV_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn artifacts_environment_token_precedence_is_documented() -> Result<()> {
    let both = context([
        ("TURBO_TOKEN", ARTIFACTS_TURBO_TOKEN),
        ("VERCEL_ARTIFACTS_TOKEN", ARTIFACTS_VERCEL_TOKEN),
    ]);
    let credential = ArtifactsDefaultCredentialProvider::new()
        .provide_credential(&both)
        .await?
        .expect("a token must be discovered");
    assert_eq!(credential.token(), ARTIFACTS_TURBO_TOKEN);

    let vercel_only = context([("VERCEL_ARTIFACTS_TOKEN", ARTIFACTS_VERCEL_TOKEN)]);
    let credential = ArtifactsDefaultCredentialProvider::new()
        .provide_credential(&vercel_only)
        .await?
        .expect("the Vercel build token must be discovered");
    assert_eq!(credential.token(), ARTIFACTS_VERCEL_TOKEN);

    let signer = Signer::new(
        vercel_only,
        ArtifactsDefaultCredentialProvider::new(),
        ArtifactsRequestSigner,
    );
    let mut parts = artifacts_request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {ARTIFACTS_VERCEL_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn each_service_discovers_only_its_own_environment_variables() -> Result<()> {
    let blob_only = context([("BLOB_READ_WRITE_TOKEN", BLOB_ENV_TOKEN)]);
    assert!(
        ArtifactsDefaultCredentialProvider::new()
            .provide_credential(&blob_only)
            .await?
            .is_none(),
        "an Artifacts signer must not authenticate with a Blob token"
    );

    let artifacts_only = context([
        ("TURBO_TOKEN", ARTIFACTS_TURBO_TOKEN),
        ("VERCEL_ARTIFACTS_TOKEN", ARTIFACTS_VERCEL_TOKEN),
    ]);
    assert!(
        BlobDefaultCredentialProvider::new()
            .provide_credential(&artifacts_only)
            .await?
            .is_none(),
        "a Blob signer must not authenticate with an Artifacts token"
    );

    assert!(
        BlobEnvCredentialProvider::new()
            .provide_credential(&artifacts_only)
            .await?
            .is_none()
    );
    assert!(
        ArtifactsEnvCredentialProvider::new()
            .provide_credential(&blob_only)
            .await?
            .is_none()
    );
    assert!(
        ArtifactsVercelEnvCredentialProvider::new()
            .provide_credential(&blob_only)
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn builder_slots_control_each_environment_source() -> Result<()> {
    let blob_ctx = context([("BLOB_READ_WRITE_TOKEN", BLOB_ENV_TOKEN)]);
    assert!(
        BlobDefaultCredentialProvider::builder()
            .no_env()
            .build()
            .provide_credential(&blob_ctx)
            .await?
            .is_none()
    );
    assert_eq!(
        BlobDefaultCredentialProvider::builder()
            .no_env()
            .env(BlobEnvCredentialProvider::new())
            .build()
            .provide_credential(&blob_ctx)
            .await?
            .expect("a later positive slot call must re-enable the slot")
            .token(),
        BLOB_ENV_TOKEN
    );

    let artifacts_ctx = context([
        ("TURBO_TOKEN", ARTIFACTS_TURBO_TOKEN),
        ("VERCEL_ARTIFACTS_TOKEN", ARTIFACTS_VERCEL_TOKEN),
    ]);
    assert_eq!(
        ArtifactsDefaultCredentialProvider::builder()
            .no_env()
            .build()
            .provide_credential(&artifacts_ctx)
            .await?
            .expect("the Vercel slot must remain available")
            .token(),
        ARTIFACTS_VERCEL_TOKEN
    );
    assert_eq!(
        ArtifactsDefaultCredentialProvider::builder()
            .no_vercel_env()
            .build()
            .provide_credential(&artifacts_ctx)
            .await?
            .expect("the Turborepo slot must remain available")
            .token(),
        ARTIFACTS_TURBO_TOKEN
    );
    assert!(
        ArtifactsDefaultCredentialProvider::builder()
            .no_env()
            .no_vercel_env()
            .build()
            .provide_credential(&artifacts_ctx)
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn malformed_environment_values_fail_closed_without_echoing_them() -> Result<()> {
    let malformed = format!("{BLOB_ENV_TOKEN}\nHeader-Injected: 1");
    let ctx = context([("BLOB_READ_WRITE_TOKEN", malformed.as_str())]);
    let error = BlobDefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect_err("a malformed Blob token must be reported");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(error.to_string().contains("BLOB_READ_WRITE_TOKEN"));
    assert!(!error.to_string().contains(BLOB_ENV_TOKEN));

    let malformed = format!("{ARTIFACTS_TURBO_TOKEN}\r\nHeader-Injected: 1");
    let ctx = context([("TURBO_TOKEN", malformed.as_str())]);
    let error = ArtifactsDefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect_err("a malformed Artifacts token must be reported");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(error.to_string().contains("TURBO_TOKEN"));
    assert!(!error.to_string().contains(ARTIFACTS_TURBO_TOKEN));

    Ok(())
}

#[tokio::test]
async fn invalid_static_providers_fail_without_falling_through() -> Result<()> {
    let ctx = context([("BLOB_READ_WRITE_TOKEN", BLOB_ENV_TOKEN)]);
    let provider =
        BlobDefaultCredentialProvider::new().push_front(BlobStaticCredentialProvider::new(""));
    let error = provider
        .provide_credential(&ctx)
        .await
        .expect_err("an invalid explicit Blob credential must not switch identity");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

    let ctx = context([("TURBO_TOKEN", ARTIFACTS_TURBO_TOKEN)]);
    let provider = ArtifactsDefaultCredentialProvider::new()
        .push_front(ArtifactsStaticCredentialProvider::new(""));
    let error = provider
        .provide_credential(&ctx)
        .await
        .expect_err("an invalid explicit Artifacts credential must not switch identity");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

    Ok(())
}

#[tokio::test]
async fn missing_credentials_fail_without_mutating_the_request() -> Result<()> {
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

    Ok(())
}

#[tokio::test]
async fn expires_in_is_rejected_before_any_header_changes() -> Result<()> {
    let blob = Signer::new(
        Context::new(),
        BlobStaticCredentialProvider::new(BLOB_STATIC_TOKEN),
        BlobRequestSigner,
    );
    let original = blob_request();
    let mut parts = original.clone();
    let error = blob
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("Vercel Blob has no query authentication");
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let artifacts = Signer::new(
        Context::new(),
        ArtifactsStaticCredentialProvider::new(ARTIFACTS_STATIC_TOKEN),
        ArtifactsRequestSigner,
    );
    let original = artifacts_request();
    let mut parts = original.clone();
    let error = artifacts
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("Vercel Artifacts has no query authentication");
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn direct_signer_calls_require_a_credential() -> Result<()> {
    let credential = BlobCredential::new(BLOB_STATIC_TOKEN)?;
    let signer = BlobRequestSigner;
    let mut parts = blob_request();
    signer
        .sign_request(&Context::new(), &mut parts, Some(&credential), None)
        .await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {BLOB_STATIC_TOKEN}")
    );

    let mut missing = blob_request();
    let error = signer
        .sign_request(&Context::new(), &mut missing, None, None)
        .await
        .expect_err("direct callers must supply a credential");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!missing.headers.contains_key(AUTHORIZATION));

    let credential = ArtifactsCredential::new(ARTIFACTS_STATIC_TOKEN)?;
    let signer = ArtifactsRequestSigner;
    let mut parts = artifacts_request();
    signer
        .sign_request(&Context::new(), &mut parts, Some(&credential), None)
        .await?;
    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("Bearer {ARTIFACTS_STATIC_TOKEN}")
    );

    let mut missing = artifacts_request();
    let error = signer
        .sign_request(&Context::new(), &mut missing, None, None)
        .await
        .expect_err("direct callers must supply a credential");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!missing.headers.contains_key(AUTHORIZATION));

    Ok(())
}

#[test]
fn signing_deadlines_are_constant_and_do_not_read_the_clock() {
    let blob = BlobCredential::new(BLOB_STATIC_TOKEN).expect("token must be valid");
    let artifacts = ArtifactsCredential::new(ARTIFACTS_STATIC_TOKEN).expect("token must be valid");

    assert_eq!(
        BlobRequestSigner.required_valid_until(&blob, None),
        Timestamp::default()
    );
    assert_eq!(
        BlobRequestSigner.required_valid_until(&blob, Some(Duration::from_secs(60))),
        Timestamp::default()
    );
    assert_eq!(
        ArtifactsRequestSigner.required_valid_until(&artifacts, None),
        Timestamp::default()
    );
    assert_eq!(
        ArtifactsRequestSigner.required_valid_until(&artifacts, Some(Duration::from_secs(60))),
        Timestamp::default()
    );
}

#[test]
fn credentials_reject_values_that_cannot_become_a_header() {
    for invalid in [
        "",
        "fake token with space",
        "fake-token\r\nX-Injected: 1",
        "令牌",
    ] {
        let error = BlobCredential::new(invalid).expect_err("invalid Blob token must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        if !invalid.is_empty() {
            assert!(!error.to_string().contains(invalid));
        }

        let error = ArtifactsCredential::new(invalid)
            .expect_err("invalid Artifacts token must be rejected");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        if !invalid.is_empty() {
            assert!(!error.to_string().contains(invalid));
        }
    }
}

#[test]
fn debug_output_redacts_token_material() {
    let secrets = [
        BLOB_ENV_TOKEN,
        BLOB_STATIC_TOKEN,
        ARTIFACTS_TURBO_TOKEN,
        ARTIFACTS_VERCEL_TOKEN,
        ARTIFACTS_STATIC_TOKEN,
    ];
    let debug = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        BlobCredential::new(BLOB_STATIC_TOKEN).expect("token must be valid"),
        BlobStaticCredentialProvider::new(BLOB_STATIC_TOKEN),
        BlobDefaultCredentialProvider::new()
            .push_front(BlobStaticCredentialProvider::new(BLOB_STATIC_TOKEN)),
        ArtifactsCredential::new(ARTIFACTS_STATIC_TOKEN).expect("token must be valid"),
        ArtifactsStaticCredentialProvider::new(ARTIFACTS_STATIC_TOKEN),
        ArtifactsDefaultCredentialProvider::new().push_front(
            ArtifactsStaticCredentialProvider::new(ARTIFACTS_STATIC_TOKEN)
        ),
        BlobDefaultCredentialProvider::new()
            .push_front(BlobStaticCredentialProvider::new(ARTIFACTS_VERCEL_TOKEN,)),
        ArtifactsDefaultCredentialProvider::new().push_front(
            ArtifactsStaticCredentialProvider::new(ARTIFACTS_TURBO_TOKEN)
        ),
    );

    for secret in secrets {
        assert!(!debug.contains(secret));
    }
}

#[tokio::test]
async fn caller_supplied_chain_keeps_the_chain_error_policy() -> Result<()> {
    let ctx = context([("BLOB_READ_WRITE_TOKEN", BLOB_ENV_TOKEN)]);
    let chain = ProvideCredentialChain::new()
        .push(BlobStaticCredentialProvider::new(""))
        .push(BlobEnvCredentialProvider::new());

    let provider = BlobDefaultCredentialProvider::with_chain(chain);
    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("a caller-supplied chain continues past provider errors");
    assert_eq!(credential.token(), BLOB_ENV_TOKEN);

    Ok(())
}
