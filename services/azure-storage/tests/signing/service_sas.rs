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

use anyhow::Context as _;
use bytes::Bytes;
use http::header::{
    CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH, IF_NONE_MATCH, LAST_MODIFIED,
};
use http::{Method, Response, StatusCode, Uri};
use reqsign_azure_storage::{Credential, RequestSigner, StaticCredentialProvider};
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
const MARKER_API_VERSION: &str = "2022-11-02";
const MARKER_OWNER: &str = "x-ms-meta-reqsignprobe";

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

    send_presigned(ctx, http::Request::get(&url), account_name, account_key).await
}

async fn send_presigned(
    ctx: &Context,
    request: http::request::Builder,
    account_name: &str,
    account_key: &str,
) -> anyhow::Result<Response<Bytes>> {
    let signer = Signer::new(
        ctx.clone(),
        StaticCredentialProvider::new_shared_key(account_name, account_key),
        RequestSigner::new().with_service_sas_permissions("racwd"),
    );
    send_signed(ctx, &signer, request, Some(Duration::from_secs(300))).await
}

async fn send_signed(
    ctx: &Context,
    signer: &Signer<Credential>,
    request: http::request::Builder,
    lifetime: Option<Duration>,
) -> anyhow::Result<Response<Bytes>> {
    let request = request
        .body(Bytes::new())
        .map_err(|_| anyhow::anyhow!("failed to build the Azure signing probe"))?;
    let (mut parts, body) = request.into_parts();

    signer.sign(&mut parts, lifetime).await.map_err(|err| {
        anyhow::anyhow!("failed to sign the Azure signing probe ({:?})", err.kind())
    })?;

    ctx.http_send(http::Request::from_parts(parts, body))
        .await
        .map_err(|_| anyhow::anyhow!("failed to send the Azure signing probe"))
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

#[tokio::test]
#[ignore = "creates a marker in the live Azure signing fixture"]
async fn test_service_sas_presign_marker_head() -> anyhow::Result<()> {
    let (url, account_name, account_key) =
        get_test_config().context("REQSIGN_AZURE_STORAGE_TEST must be enabled")?;
    let probe: Uri = url.parse().context("invalid Azure signing probe URL")?;
    anyhow::ensure!(probe.query().is_none(), "expected an unsigned probe URL");
    let prefix = probe
        .path()
        .strip_suffix(".txt")
        .context("expected a signing probe from with-probe.sh")?;
    let owner = prefix.rsplit('/').next().unwrap_or_default().to_owned();
    let marker_path = format!("{prefix}/marker/");
    let mut uri_parts = probe.into_parts();
    uri_parts.path_and_query = Some(marker_path.parse()?);
    let uri = Uri::from_parts(uri_parts)?;

    let ctx = test_context();
    let signer = Signer::new(
        ctx.clone(),
        StaticCredentialProvider::new_shared_key(&account_name, &account_key),
        RequestSigner::new().with_service_sas_permissions("r"),
    );

    // Match the native OpenDAL marker fixture: an empty BlockBlob at the
    // literal slash-ending path under a unique prefix.
    let create = send_signed(
        &ctx,
        &signer,
        marker_request(Method::PUT, &uri)
            .header("x-ms-blob-type", "BlockBlob")
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, 0)
            .header(IF_NONE_MATCH, "*")
            .header(MARKER_OWNER, &owner),
        None,
    )
    .await
    .context("Azure marker PUT");
    if let Ok(response) = &create {
        if response.status() != StatusCode::CREATED {
            anyhow::bail!(
                "Azure marker PUT returned HTTP {}{}",
                response.status(),
                marker_put_diagnostic(&ctx, &signer, &uri, response).await
            );
        }
    }

    let result = async {
        let create = create?;
        eprintln!("Azure marker PUT returned HTTP 201");
        let reference = send_signed(&ctx, &signer, marker_request(Method::HEAD, &uri), None)
            .await
            .context("Shared Key marker HEAD")?;
        anyhow::ensure!(
            reference.status() == StatusCode::OK,
            "Shared Key marker HEAD returned HTTP {}",
            reference.status()
        );
        anyhow::ensure!(
            create.headers().get(ETAG).is_some()
                && reference.headers().get(ETAG) == create.headers().get(ETAG)
                && reference
                    .headers()
                    .get(CONTENT_LENGTH)
                    .is_some_and(|length| length == "0")
                && reference
                    .headers()
                    .get(MARKER_OWNER)
                    .is_some_and(|value| value == owner.as_str()),
            "Shared Key HEAD metadata must identify the created empty blob"
        );

        let presigned = send_signed(
            &ctx,
            &signer,
            http::Request::head(&uri),
            Some(Duration::from_secs(300)),
        )
        .await
        .context("Service SAS marker HEAD")?;
        anyhow::ensure!(
            presigned.status() == StatusCode::OK,
            "Service SAS marker HEAD returned HTTP {}",
            presigned.status()
        );
        for name in [ETAG, LAST_MODIFIED, CONTENT_LENGTH, CONTENT_TYPE] {
            anyhow::ensure!(
                reference
                    .headers()
                    .get(&name)
                    .is_some_and(|value| { presigned.headers().get(&name) == Some(value) }),
                "Service SAS marker HEAD did not match Shared Key {name}"
            );
        }
        anyhow::ensure!(
            presigned.body().is_empty(),
            "Azure marker HEAD returned a body"
        );
        eprintln!("Service SAS marker HEAD returned HTTP 200 with matching metadata");
        Ok::<_, anyhow::Error>(())
    }
    .await;

    // Check for the owned blob even when the PUT returned a transport error.
    let cleanup = cleanup_marker(&ctx, &signer, &uri, &owner).await;
    match (result, cleanup) {
        (Err(probe), Err(cleanup)) => {
            Err(probe.context(format!("marker cleanup failed ({cleanup:#})")))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn marker_request(method: Method, uri: &Uri) -> http::request::Builder {
    http::Request::builder()
        .method(method)
        .uri(uri)
        .header("x-ms-version", MARKER_API_VERSION)
}

async fn marker_put_diagnostic(
    ctx: &Context,
    signer: &Signer<Credential>,
    uri: &Uri,
    response: &Response<Bytes>,
) -> &'static str {
    if !response
        .headers()
        .get("x-ms-error-code")
        .is_some_and(|code| code == "InvalidUri")
    {
        return "";
    }

    let mut account = uri.clone().into_parts();
    account.path_and_query = Some(http::uri::PathAndQuery::from_static(
        "/?restype=account&comp=properties",
    ));
    if let Ok(account) = Uri::from_parts(account) {
        let info = send_signed(ctx, signer, marker_request(Method::HEAD, &account), None).await;
        if info.is_ok_and(|info| {
            info.status() == StatusCode::OK
                && info
                    .headers()
                    .get("x-ms-is-hns-enabled")
                    .is_some_and(|value| value == "true")
        }) {
            return " (InvalidUri: the exact marker requires a flat Blob Storage fixture)";
        }
    }
    " (InvalidUri for the literal slash-ending marker path)"
}

async fn cleanup_marker(
    ctx: &Context,
    signer: &Signer<Credential>,
    uri: &Uri,
    owner: &str,
) -> anyhow::Result<()> {
    let current = send_signed(ctx, signer, marker_request(Method::HEAD, uri), None)
        .await
        .context("marker cleanup HEAD")?;
    if current.status() == StatusCode::NOT_FOUND {
        eprintln!("Azure marker cleanup HEAD returned HTTP 404");
        return Ok(());
    }
    anyhow::ensure!(
        current.status() == StatusCode::OK,
        "marker cleanup HEAD returned HTTP {}",
        current.status()
    );
    anyhow::ensure!(
        current
            .headers()
            .get(MARKER_OWNER)
            .is_some_and(|value| value == owner),
        "marker cleanup requires matching ownership metadata"
    );
    let etag = current
        .headers()
        .get(ETAG)
        .context("marker cleanup HEAD omitted the ETag")?;
    let versioned: Option<Uri> = current
        .headers()
        .get("x-ms-version-id")
        .map(|version| {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("versionid", version.to_str()?)
                .finish();
            format!("{uri}?{query}")
                .parse()
                .context("invalid marker version URI")
        })
        .transpose()?;
    let response = send_signed(
        ctx,
        signer,
        marker_request(Method::DELETE, versioned.as_ref().unwrap_or(uri)).header(IF_MATCH, etag),
        None,
    )
    .await
    .context("marker cleanup DELETE")?;
    anyhow::ensure!(
        response.status() == StatusCode::ACCEPTED,
        "marker DELETE returned HTTP {}",
        response.status()
    );
    for target in [Some(uri), versioned.as_ref()].into_iter().flatten() {
        let proof = send_signed(ctx, signer, marker_request(Method::HEAD, target), None)
            .await
            .context("marker HEAD after DELETE")?;
        anyhow::ensure!(
            proof.status() == StatusCode::NOT_FOUND,
            "marker HEAD after DELETE returned HTTP {}",
            proof.status()
        );
    }
    eprintln!("Azure marker DELETE returned HTTP 202 and exact HEAD returned HTTP 404");
    Ok(())
}
