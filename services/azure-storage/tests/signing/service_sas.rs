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

use bytes::Bytes;
use http::StatusCode;
use http::header::CONTENT_DISPOSITION;
use reqsign_azure_storage::{RequestSigner, StaticCredentialProvider};
use reqsign_core::{Context, OsEnv, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use std::time::Duration;

/// The exact response override value used by OpenDAL's
/// `test_read_with_override_content_disposition`.
const CONTENT_DISPOSITION_VALUE: &str = "attachment; filename=foo.txt";
/// OpenDAL percent-encodes the override as a query value with its path encoder.
const CONTENT_DISPOSITION_QUERY: &str = "attachment%3B%20filename%3Dfoo.txt";
/// The live fixture blob written by `.github/azure-live-tests/with-probe.sh`.
const PROBE_BODY: &[u8] = b"reqsign-live-azure-ok\n";

fn is_test_enabled() -> bool {
    std::env::var("REQSIGN_AZURE_STORAGE_TEST").unwrap_or_default() == "on"
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn get_test_config() -> Option<(String, String, String)> {
    if !is_test_enabled() {
        return None;
    }

    let url = required_env("REQSIGN_AZURE_STORAGE_PROBE_URL");
    let account_name = required_env("REQSIGN_AZURE_STORAGE_ACCOUNT_NAME");
    let account_key = required_env("REQSIGN_AZURE_STORAGE_ACCOUNT_KEY");

    Some((url, account_name, account_key))
}

fn test_context() -> Context {
    crate::common::test_context()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::default())
        .with_env(OsEnv)
}

/// Presign and send one GET with the same Shared Key Service SAS configuration
/// and override encoding that OpenDAL uses.
async fn presigned_get(
    ctx: &Context,
    url: &str,
    account_name: &str,
    account_key: &str,
    encoded_content_disposition: Option<&str>,
) -> anyhow::Result<http::Response<Bytes>> {
    let mut url = url.to_string();
    if let Some(value) = encoded_content_disposition {
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str("rscd=");
        url.push_str(value);
    }

    let request = http::Request::get(&url)
        .body(Bytes::new())
        .map_err(|_| anyhow::anyhow!("failed to build the Azure Blob Service SAS probe"))?;
    let (mut parts, body) = request.into_parts();

    let signer = Signer::new(
        ctx.clone(),
        StaticCredentialProvider::new_shared_key(account_name, account_key),
        RequestSigner::new().with_service_sas_permissions("racwd"),
    );
    signer
        .sign(&mut parts, Some(Duration::from_secs(300)))
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to sign the Azure Blob Service SAS probe ({:?})",
                err.kind()
            )
        })?;

    ctx.http_send(http::Request::from_parts(parts, body))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Azure Blob Service SAS probe failed; signed request details are suppressed"
            )
        })
}

fn ensure_probe_body(response: &http::Response<Bytes>) -> anyhow::Result<()> {
    anyhow::ensure!(
        response.body().as_ref() == PROBE_BODY,
        "Azure Blob Service SAS probe returned unexpected bytes ({} bytes)",
        response.body().len()
    );
    Ok(())
}

#[tokio::test]
async fn test_service_sas_presign_read_without_override() -> anyhow::Result<()> {
    let Some((url, account_name, account_key)) = get_test_config() else {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return Ok(());
    };

    let response = presigned_get(&test_context(), &url, &account_name, &account_key, None).await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "Azure Blob Service SAS control GET returned HTTP {}",
        response.status()
    );
    ensure_probe_body(&response)
}

#[tokio::test]
async fn test_service_sas_presign_read_with_content_disposition_override() -> anyhow::Result<()> {
    let Some((url, account_name, account_key)) = get_test_config() else {
        eprintln!("Skipping test: REQSIGN_AZURE_STORAGE_TEST is not enabled");
        return Ok(());
    };

    let response = presigned_get(
        &test_context(),
        &url,
        &account_name,
        &account_key,
        Some(CONTENT_DISPOSITION_QUERY),
    )
    .await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "Azure Blob Service SAS override GET returned HTTP {}",
        response.status()
    );

    let disposition = response
        .headers()
        .get(CONTENT_DISPOSITION)
        .ok_or_else(|| anyhow::anyhow!("Azure Blob Service SAS override GET omitted the header"))?
        .to_str()
        .map_err(|_| {
            anyhow::anyhow!("Azure Blob Service SAS override header is not valid ASCII")
        })?;
    anyhow::ensure!(
        disposition == CONTENT_DISPOSITION_VALUE,
        "Azure Blob Service SAS override GET returned Content-Disposition {disposition:?}"
    );

    ensure_probe_body(&response)
}
