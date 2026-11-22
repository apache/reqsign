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

#![cfg(feature = "vercel")]

use std::collections::HashMap;

use reqsign::vercel::{
    ArtifactsStaticCredentialProvider, BlobStaticCredentialProvider, DefaultArtifactsSigner,
    DefaultBlobSigner, default_artifacts_signer, default_blob_signer,
};
use reqsign::{Context, ErrorKind, Result, StaticEnv};

fn context(envs: impl IntoIterator<Item = (&'static str, &'static str)>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: envs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
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

#[tokio::test]
async fn facade_default_signers_use_each_documented_source() -> Result<()> {
    let blob: DefaultBlobSigner = default_blob_signer(context([(
        "BLOB_READ_WRITE_TOKEN",
        "fake-facade-blob-token",
    )]));
    let mut parts = blob_request();
    blob.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-facade-blob-token"
    );
    assert!(parts.headers[http::header::AUTHORIZATION].is_sensitive());

    let artifacts: DefaultArtifactsSigner =
        default_artifacts_signer(context([("TURBO_TOKEN", "fake-facade-artifacts-token")]));
    let mut parts = artifacts_request();
    artifacts.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-facade-artifacts-token"
    );
    assert_eq!(
        parts.uri.query(),
        Some("teamId=team_example"),
        "the caller owns the cache scope query"
    );

    Ok(())
}

#[tokio::test]
async fn facade_static_overrides_replace_ambient_discovery() -> Result<()> {
    let blob = default_blob_signer(context([(
        "BLOB_READ_WRITE_TOKEN",
        "fake-facade-blob-token",
    )]))
    .with_credential_provider(BlobStaticCredentialProvider::new(
        "fake-facade-blob-static-token",
    ));
    let mut parts = blob_request();
    parts.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-facade-token"),
    );
    blob.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-facade-blob-static-token"
    );

    let artifacts =
        default_artifacts_signer(context([("TURBO_TOKEN", "fake-facade-artifacts-token")]))
            .with_credential_provider(ArtifactsStaticCredentialProvider::new(
                "fake-facade-artifacts-static-token",
            ));
    let mut parts = artifacts_request();
    artifacts.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer fake-facade-artifacts-static-token"
    );

    Ok(())
}

#[tokio::test]
async fn facade_signers_do_not_cross_authenticate() -> Result<()> {
    let blob = default_blob_signer(context([("TURBO_TOKEN", "fake-facade-artifacts-token")]));
    let original = blob_request();
    let mut parts = original.clone();
    let error = blob
        .sign(&mut parts, None)
        .await
        .expect_err("a Blob signer must not use an Artifacts token");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let artifacts = default_artifacts_signer(context([(
        "BLOB_READ_WRITE_TOKEN",
        "fake-facade-blob-token",
    )]));
    let original = artifacts_request();
    let mut parts = original.clone();
    let error = artifacts
        .sign(&mut parts, None)
        .await
        .expect_err("an Artifacts signer must not use a Blob token");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn facade_without_a_token_fails_without_mutating_the_request() -> Result<()> {
    let blob = default_blob_signer(context(Vec::<(&str, &str)>::new()));
    let original = blob_request();
    let mut parts = original.clone();
    let error = blob
        .sign(&mut parts, None)
        .await
        .expect_err("a missing Blob token must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let artifacts = default_artifacts_signer(context(Vec::<(&str, &str)>::new()));
    let original = artifacts_request();
    let mut parts = original.clone();
    let error = artifacts
        .sign(&mut parts, None)
        .await
        .expect_err("a missing Artifacts token must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}
