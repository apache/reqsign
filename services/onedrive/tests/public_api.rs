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

use bytes::Bytes;
use reqsign_core::ProvideCredentialChain;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ErrorKind, HttpSend, ProvideCredential, Result, SignRequest, Signer};
use reqsign_onedrive::{RefreshCredentialProvider, RequestSigner, StaticCredentialProvider};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const STATIC_TOKEN: &str = "static-Q8wv-graph-token";
const CLIENT_ID: &str = "client-id";
const CLIENT_SECRET: &str = "client-secret";
const REFRESH_TOKEN: &str = "refresh-token-T4mz";
const ROTATED_REFRESH_TOKEN: &str = "rotated-refresh-token-R7ck";
const ACCESS_TOKEN: &str = "graph-access-token-N2pd";

const COMMON_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

#[derive(Clone)]
struct CapturedRequest {
    method: http::Method,
    uri: String,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
struct MockHttpSend {
    requests: Arc<StdMutex<Vec<CapturedRequest>>>,
    responses: Arc<StdMutex<VecDeque<Result<http::Response<Bytes>>>>>,
    calls: Arc<AtomicUsize>,
}

impl std::fmt::Debug for MockHttpSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHttpSend")
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl MockHttpSend {
    fn new(responses: impl IntoIterator<Item = Result<http::Response<Bytes>>>) -> Self {
        Self {
            requests: Arc::new(StdMutex::new(Vec::new())),
            responses: Arc::new(StdMutex::new(responses.into_iter().collect())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request lock")
            .push(CapturedRequest {
                method: req.method().clone(),
                uri: req.uri().to_string(),
                headers: req.headers().clone(),
                body: req.body().to_vec(),
            });

        self.responses
            .lock()
            .expect("response lock")
            .pop_front()
            .expect("mock response must exist")
    }
}

fn token_response(
    access_token: &str,
    expires_in: Option<u64>,
    refresh_token: Option<&str>,
) -> http::Response<Bytes> {
    let mut fields = vec![
        format!("\"access_token\":\"{access_token}\""),
        "\"token_type\":\"Bearer\"".to_string(),
    ];
    if let Some(expires_in) = expires_in {
        fields.push(format!("\"expires_in\":{expires_in}"));
    }
    if let Some(refresh_token) = refresh_token {
        fields.push(format!("\"refresh_token\":\"{refresh_token}\""));
    }
    http::Response::builder()
        .status(http::StatusCode::OK)
        .body(Bytes::from(format!("{{{}}}", fields.join(","))))
        .expect("response must build")
}

fn request() -> http::request::Parts {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(
            "https://graph.microsoft.com/v1.0/me/drive/root:/documents/report.txt:?$select=id,name",
        )
        .header("x-original", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn context(http: MockHttpSend) -> Context {
    Context::new().with_http_send(http)
}

fn decoded_form(body: &[u8]) -> HashMap<String, String> {
    form_urlencoded::parse(body).into_owned().collect()
}

#[tokio::test]
async fn static_credential_signs_without_network_and_rejects_unusable_or_expired_tokens()
-> Result<()> {
    let http = MockHttpSend::new([]);
    let signer = Signer::new(
        context(http.clone()),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    let mut parts = request();
    let original = parts.clone();

    signer.sign(&mut parts, None).await?;

    assert_eq!(http.calls(), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(
        parts.headers.get("x-original"),
        original.headers.get("x-original")
    );
    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("authorization must be present");
    assert_eq!(
        authorization,
        &http::HeaderValue::from_static("Bearer static-Q8wv-graph-token")
    );
    assert!(authorization.is_sensitive());

    let expired = StaticCredentialProvider::new(STATIC_TOKEN)
        .with_expires_at(Timestamp::now() - Duration::from_secs(1));
    let signer = Signer::new(context(http.clone()), expired, RequestSigner);
    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("expired static token must fail");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(http.calls(), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let signer = Signer::new(
        context(http.clone()),
        StaticCredentialProvider::new("unusable access token"),
        RequestSigner,
    );
    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an unusable static token must fail");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(http.calls(), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn public_client_refresh_uses_the_common_endpoint_and_omits_client_secret() -> Result<()> {
    let http = MockHttpSend::new([Ok(token_response(
        ACCESS_TOKEN,
        Some(3600),
        Some(ROTATED_REFRESH_TOKEN),
    ))]);
    let signer = Signer::new(
        context(http.clone()),
        RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?,
        RequestSigner,
    );

    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        let authorization = &parts.headers[http::header::AUTHORIZATION];
        assert_eq!(authorization, "Bearer graph-access-token-N2pd");
        assert!(authorization.is_sensitive());
    }

    assert_eq!(
        http.calls(),
        1,
        "the access-token cache must reuse the result"
    );
    let requests = http.requests();
    let refresh = &requests[0];
    assert_eq!(refresh.method, http::Method::POST);
    assert_eq!(refresh.uri, COMMON_TOKEN_ENDPOINT);
    assert_eq!(
        refresh.headers.get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static(
            "application/x-www-form-urlencoded"
        ))
    );
    assert!(
        !refresh.headers.contains_key(http::header::AUTHORIZATION),
        "a public client must not authenticate with the token endpoint"
    );
    assert_eq!(
        std::str::from_utf8(&refresh.body).expect("form body must be UTF-8"),
        "grant_type=refresh_token&refresh_token=refresh-token-T4mz&client_id=client-id",
        "the public-client exchange sends exactly the RFC 6749 refresh fields it owns"
    );

    Ok(())
}

#[tokio::test]
async fn confidential_client_refresh_sends_the_client_secret() -> Result<()> {
    let http = MockHttpSend::new([Ok(token_response(ACCESS_TOKEN, Some(3600), None))]);
    let provider = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
        .client_secret(CLIENT_SECRET)
        .build()?;
    let signer = Signer::new(context(http.clone()), provider, RequestSigner);

    let mut parts = request();
    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer graph-access-token-N2pd"
    );
    let requests = http.requests();
    assert_eq!(
        std::str::from_utf8(&requests[0].body).expect("form body must be UTF-8"),
        "grant_type=refresh_token&refresh_token=refresh-token-T4mz&client_id=client-id&client_secret=client-secret"
    );

    Ok(())
}

#[tokio::test]
async fn rotated_refresh_token_is_reused_after_a_new_signer_cache() -> Result<()> {
    let http = MockHttpSend::new([
        Ok(token_response(
            ACCESS_TOKEN,
            Some(3600),
            Some(ROTATED_REFRESH_TOKEN),
        )),
        Ok(token_response("second-access-token", Some(3600), None)),
    ]);
    let provider = RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?;
    let signer = Signer::new(context(http.clone()), provider.clone(), RequestSigner);

    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer graph-access-token-N2pd"
        );
    }
    assert_eq!(http.calls(), 1, "sequential calls must reuse the cache");

    // A separately constructed signer has its own access-token cache but shares
    // the provider's rotated refresh-token state.
    let second = Signer::new(context(http.clone()), provider, RequestSigner);
    let mut parts = request();
    second.sign(&mut parts, None).await?;

    assert_eq!(http.calls(), 2);
    assert_eq!(
        decoded_form(&http.requests()[1].body)["refresh_token"],
        ROTATED_REFRESH_TOKEN
    );
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer second-access-token"
    );

    Ok(())
}

#[tokio::test]
async fn missing_expiration_is_rejected_after_committing_the_rotated_refresh_token() -> Result<()> {
    for expires_in in [None, Some(0)] {
        let http = MockHttpSend::new([
            Ok(token_response(
                "unusable-access-token",
                expires_in,
                Some(ROTATED_REFRESH_TOKEN),
            )),
            Ok(token_response("fresh-access-token", Some(3600), None)),
        ]);
        let signer = Signer::new(
            context(http.clone()),
            RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?,
            RequestSigner,
        );
        let mut parts = request();
        let original = parts.clone();

        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("a Microsoft Graph token without a usable expiration must be rejected");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.calls(), 1);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);

        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(http.calls(), 2);
        assert_eq!(
            decoded_form(&http.requests()[1].body)["refresh_token"],
            ROTATED_REFRESH_TOKEN,
            "the rejected exchange must still commit its rotated refresh token"
        );
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer fresh-access-token"
        );
    }

    Ok(())
}

#[tokio::test]
async fn tenant_scope_and_national_cloud_endpoint_are_applied() -> Result<()> {
    let http = MockHttpSend::new([
        Ok(token_response(ACCESS_TOKEN, Some(3600), None)),
        Ok(token_response(ACCESS_TOKEN, Some(3600), None)),
        Ok(token_response(ACCESS_TOKEN, Some(3600), None)),
    ]);

    let provider = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
        .tenant("contoso.onmicrosoft.com")
        .scope("offline_access Files.ReadWrite")
        .build()?;
    let mut parts = request();
    Signer::new(context(http.clone()), provider, RequestSigner)
        .sign(&mut parts, None)
        .await?;

    let tenant_request = &http.requests()[0];
    assert_eq!(
        tenant_request.uri,
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
    );
    assert_eq!(
        decoded_form(&tenant_request.body)["scope"],
        "offline_access Files.ReadWrite"
    );

    let provider = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
        .token_endpoint("https://login.microsoftonline.us/common/oauth2/v2.0/token")
        .build()?;
    let mut parts = request();
    Signer::new(context(http.clone()), provider, RequestSigner)
        .sign(&mut parts, None)
        .await?;
    assert_eq!(
        http.requests()[1].uri,
        "https://login.microsoftonline.us/common/oauth2/v2.0/token"
    );

    // Calling tenant and token_endpoint is last-wins rather than conflicting.
    let provider = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
        .tenant("organizations")
        .token_endpoint("https://login.microsoftonline.us/organizations/oauth2/v2.0/token")
        .build()?;
    let mut parts = request();
    Signer::new(context(http.clone()), provider, RequestSigner)
        .sign(&mut parts, None)
        .await?;
    assert_eq!(
        http.requests()[2].uri,
        "https://login.microsoftonline.us/organizations/oauth2/v2.0/token"
    );

    for invalid_tenant in [
        "",
        "common/../admin",
        "common?x=1",
        ".contoso.com",
        "-contoso-",
    ] {
        let error = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
            .tenant(invalid_tenant)
            .build()
            .expect_err("only a documented tenant segment may be used");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }

    let error = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
        .token_endpoint("http://login.microsoftonline.com/common/oauth2/v2.0/token")
        .build()
        .expect_err("the token endpoint must be HTTPS");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

    Ok(())
}

#[tokio::test]
async fn header_only_signing_rejects_expires_in_and_missing_credentials() -> Result<()> {
    let http = MockHttpSend::new([]);
    let ctx = context(http.clone());
    let signer = Signer::new(
        ctx.clone(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );

    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("OneDrive signing does not produce query authentication");
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let mut parts = request();
    let original = parts.clone();
    let error = RequestSigner
        .sign_request(&ctx, &mut parts, None, None)
        .await
        .expect_err("direct signing without a credential must fail");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    assert_eq!(http.calls(), 0);

    Ok(())
}

#[tokio::test]
async fn refresh_failures_are_redacted_and_not_retried() -> Result<()> {
    const SENTINEL: &str = "ONEDRIVE_RESPONSE_SENTINEL";
    let body = format!(
        r#"{{"error":"invalid_grant","error_description":"{SENTINEL}","access_token":"{SENTINEL}"}}"#
    );
    let http = MockHttpSend::new([Ok(http::Response::builder()
        .status(http::StatusCode::BAD_REQUEST)
        .body(Bytes::from(body))
        .expect("response must build"))]);
    let signer = Signer::new(
        context(http.clone()),
        RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?,
        RequestSigner,
    );
    let mut parts = request();
    let original = parts.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("rejected refresh must fail");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!error.to_string().contains(SENTINEL));
    assert!(!format!("{error:?}").contains(SENTINEL));
    assert_eq!(http.calls(), 1, "one failed exchange must not be retried");
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn debug_output_redacts_tokens_and_secrets() -> Result<()> {
    let provider = RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN)
        .client_secret(CLIENT_SECRET)
        .build()?;
    let builder_debug = format!(
        "{:?}",
        RefreshCredentialProvider::builder(CLIENT_ID, REFRESH_TOKEN).client_secret(CLIENT_SECRET)
    );
    for debug in [format!("{provider:?}"), builder_debug] {
        assert!(!debug.contains(REFRESH_TOKEN));
        assert!(!debug.contains(CLIENT_SECRET));
    }

    let credential = StaticCredentialProvider::new(STATIC_TOKEN)
        .provide_credential(&Context::new())
        .await?
        .expect("static provider yields a credential");
    let debug = format!("{credential:?}");
    assert!(!debug.contains(STATIC_TOKEN));
    assert!(debug.contains("access_token"));

    Ok(())
}

#[tokio::test]
async fn short_lived_token_is_accepted_for_the_current_operation() -> Result<()> {
    let http = MockHttpSend::new([Ok(token_response(ACCESS_TOKEN, Some(30), None))]);
    let signer = Signer::new(
        context(http),
        RefreshCredentialProvider::new(CLIENT_ID, REFRESH_TOKEN)?,
        RequestSigner,
    );
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer graph-access-token-N2pd"
    );
    Ok(())
}

#[tokio::test]
async fn deliberate_empty_chain_fails_without_mutating_the_request() -> Result<()> {
    let http = MockHttpSend::new([]);
    let signer = Signer::new(
        context(http.clone()),
        ProvideCredentialChain::<reqsign_onedrive::Credential>::new(),
        RequestSigner,
    );
    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("a deliberate empty chain must not sign");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(http.calls(), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn caller_supplied_chain_keeps_its_error_policy() -> Result<()> {
    let http = MockHttpSend::new([]);
    let chain = ProvideCredentialChain::new()
        .push(StaticCredentialProvider::new("unusable access token"))
        .push(StaticCredentialProvider::new(STATIC_TOKEN));
    let signer = Signer::new(context(http.clone()), chain, RequestSigner);

    let mut parts = request();
    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        format!("Bearer {STATIC_TOKEN}")
    );
    assert_eq!(http.calls(), 0);

    Ok(())
}
