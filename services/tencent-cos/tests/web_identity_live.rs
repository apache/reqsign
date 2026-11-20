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

//! Live coverage for `AssumeRoleWithWebIdentityCredentialProvider`.
//!
//! The test only runs when `REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY` is `on`.
//! CI sets that gate in `.github/workflows/tencent_cos_live.yml`, which runs
//! only from the main branch. The test exchanges a GitHub OIDC token for
//! temporary Tencent Cloud credentials through the real STS endpoint, then
//! reads a private COS object with the credentials returned by the provider.

mod common;

use std::env;
use std::time::Duration;

use http::StatusCode;
use log::info;
use reqsign_core::Result;
use reqsign_core::{OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqsign_tencent_cos::{AssumeRoleWithWebIdentityCredentialProvider, RequestSigner};

const SECURITY_TOKEN_HEADER: &str = "x-cos-security-token";

fn live_test_enabled() -> bool {
    env::var("REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY").unwrap_or_default() == "on"
}

#[tokio::test]
async fn test_web_identity_credential_reads_private_object() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = dotenvy::dotenv();

    if !live_test_enabled() {
        info!("REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY is not on, skipped");
        return Ok(());
    }

    let required = [
        "TENCENTCLOUD_REGION",
        "TENCENTCLOUD_ROLE_ARN",
        "TENCENTCLOUD_PROVIDER_ID",
        "TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE",
        "REQSIGN_TENCENT_COS_OBJECT_URL",
    ];
    let missing = required
        .iter()
        .filter(|name| env::var_os(name).is_none())
        .copied()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "REQSIGN_TENCENT_COS_TEST_WEB_IDENTITY is on, but these variables are not set: {}",
        missing.join(", ")
    );

    let token_file = env::var("TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE").unwrap_or_default();
    let token_size = std::fs::metadata(&token_file)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    assert!(
        token_size > 0,
        "TENCENTCLOUD_WEB_IDENTITY_TOKEN_FILE must reference the non-empty OIDC token file written by the live job"
    );

    let object_url = env::var("REQSIGN_TENCENT_COS_OBJECT_URL")
        .expect("REQSIGN_TENCENT_COS_OBJECT_URL must be set");
    assert!(
        object_url.starts_with("https://"),
        "REQSIGN_TENCENT_COS_OBJECT_URL must use https so the temporary credential and signed request are not sent in cleartext"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    // A public object would make the signed request succeed even if the
    // provider returned no usable credential, so refuse to run against one.
    let unsigned_response = client
        .get(&object_url)
        .send()
        .await
        .expect("failed to send unsigned request");
    assert!(
        !unsigned_response.status().is_success(),
        "the live test object must not be publicly readable, got {} without credentials",
        unsigned_response.status()
    );

    let ctx = crate::common::test_context()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv);
    let signer = Signer::new(
        ctx,
        AssumeRoleWithWebIdentityCredentialProvider::new(),
        RequestSigner::new(),
    );

    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(object_url.as_str())
        .body(Vec::new())?;
    let (mut parts, body) = req.into_parts();
    signer.sign(&mut parts, None).await?;
    assert!(
        parts.headers.contains_key(SECURITY_TOKEN_HEADER),
        "AssumeRoleWithWebIdentity must return a temporary credential with a security token"
    );

    let req = http::Request::from_parts(parts, body);
    let resp = client
        .execute(req.try_into().map_err(|e| {
            reqsign_core::Error::unexpected("failed to convert request")
                .with_source(anyhow::Error::new(e))
        })?)
        .await
        .map_err(|e| {
            reqsign_core::Error::unexpected("failed to execute request")
                .with_source(anyhow::Error::new(e))
        })?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        reqsign_core::Error::unexpected("failed to read response body")
            .with_source(anyhow::Error::new(e))
    })?;
    assert_eq!(
        StatusCode::OK,
        status,
        "credentials returned by AssumeRoleWithWebIdentity must be accepted for a read-only GET of the private object, got {status}: {body}"
    );

    Ok(())
}
