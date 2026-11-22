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
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, ErrorKind, HttpSend, ProvideCredential, ProvideCredentialChain, Result,
    SignRequest, Signer, StaticEnv,
};
use reqsign_dropbox::{
    DefaultCredentialProvider, RefreshCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const ENV_TOKEN: &str = "env-token-A0";
const STATIC_TOKEN: &str = "static-token-A0";
const CLIENT_ID: &str = "client-id";
const CLIENT_SECRET: &str = "client-secret";
const REFRESH_TOKEN: &str = "refresh-token-R0";

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
        "\"token_type\":\"bearer\"".to_string(),
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
        .uri("https://api.dropboxapi.com/2/users/get_current_account?x=%2F")
        .header("x-original", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn context_with_env(envs: HashMap<String, String>, http: MockHttpSend) -> Context {
    Context::new().with_http_send(http).with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn decoded_form(body: &[u8]) -> HashMap<String, String> {
    form_urlencoded::parse(body).into_owned().collect()
}

#[tokio::test]
async fn default_env_discovery_signs_without_network_and_preserves_the_request() -> Result<()> {
    let http = MockHttpSend::new([]);
    let context = context_with_env(
        HashMap::from([("DBXCLI_ACCESS_TOKEN".to_string(), ENV_TOKEN.to_string())]),
        http.clone(),
    );
    let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);
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
        &http::HeaderValue::from_static("Bearer env-token-A0")
    );
    assert!(authorization.is_sensitive());

    Ok(())
}

#[tokio::test]
async fn default_provider_chain_and_push_front_keep_explicit_sources() -> Result<()> {
    let http = MockHttpSend::new([]);
    let context = context_with_env(
        HashMap::from([("DBXCLI_ACCESS_TOKEN".to_string(), ENV_TOKEN.to_string())]),
        http.clone(),
    );

    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new("front-token"));
    let signer = Signer::new(context.clone(), provider, RequestSigner);
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer front-token"
    );

    let chain = ProvideCredentialChain::new().push(StaticCredentialProvider::new("chain-token"));
    let provider = DefaultCredentialProvider::with_chain(chain);
    let signer = Signer::new(context, provider, RequestSigner);
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer chain-token"
    );
    assert_eq!(http.calls(), 0);

    Ok(())
}

#[tokio::test]
async fn no_env_removes_the_default_source_instead_of_falling_back() -> Result<()> {
    let http = MockHttpSend::new([]);
    let context = context_with_env(
        HashMap::from([("DBXCLI_ACCESS_TOKEN".to_string(), ENV_TOKEN.to_string())]),
        http.clone(),
    );
    let provider = DefaultCredentialProvider::builder().no_env().build();
    assert!(provider.provide_credential(&context).await?.is_none());

    let signer = Signer::new(context, provider, RequestSigner);
    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("removed env source must not be re-enabled");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(http.calls(), 0);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn static_provider_signs_without_network_and_rejects_expired_tokens() -> Result<()> {
    let http = MockHttpSend::new([]);
    let context = context_with_env(HashMap::new(), http.clone());

    let signer = Signer::new(
        context.clone(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(http.calls(), 0);
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer static-token-A0"
    );

    let expired = StaticCredentialProvider::with_expires_at(
        STATIC_TOKEN,
        Timestamp::now() - Duration::from_secs(1),
    );
    let signer = Signer::new(context, expired, RequestSigner);
    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("expired static token must fail");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn refresh_provider_uses_the_dropbox_form_endpoint_and_caches_the_access_token() -> Result<()>
{
    let http = MockHttpSend::new([Ok(token_response(
        "access-token-A1",
        Some(3600),
        Some("refresh-token-R1"),
    ))]);
    let context = context_with_env(HashMap::new(), http.clone());
    let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?;

    let signer = Signer::new(context, provider, RequestSigner);
    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        let authorization = &parts.headers[http::header::AUTHORIZATION];
        assert_eq!(authorization, "Bearer access-token-A1");
        assert!(authorization.is_sensitive());
    }

    assert_eq!(
        http.calls(),
        1,
        "the access-token cache must reuse the result"
    );
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    let refresh = &requests[0];
    assert_eq!(refresh.method, http::Method::POST);
    assert_eq!(refresh.uri, "https://api.dropboxapi.com/oauth2/token");
    assert_eq!(
        refresh.headers.get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static(
            "application/x-www-form-urlencoded"
        ))
    );
    assert!(!refresh.headers.contains_key(http::header::AUTHORIZATION));
    assert_eq!(
        decoded_form(&refresh.body),
        HashMap::from([
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), REFRESH_TOKEN.to_string()),
            ("client_id".to_string(), CLIENT_ID.to_string()),
            ("client_secret".to_string(), CLIENT_SECRET.to_string()),
        ])
    );

    Ok(())
}

#[tokio::test]
async fn fresh_short_lived_token_is_accepted_for_the_current_operation() -> Result<()> {
    let http = MockHttpSend::new([Ok(token_response("access-token-A1", Some(30), None))]);
    let context = context_with_env(HashMap::new(), http);
    let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?;
    let signer = Signer::new(context, provider, RequestSigner);
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer access-token-A1"
    );
    Ok(())
}

#[tokio::test]
async fn sequential_signing_reuses_cache_and_rotates_for_a_new_signer_cache() -> Result<()> {
    let http = MockHttpSend::new([
        Ok(token_response(
            "cached-access-token",
            Some(3600),
            Some("rotated-refresh-token"),
        )),
        Ok(token_response(
            "second-access-token",
            Some(3600),
            Some("second-refresh-token"),
        )),
    ]);
    let context = context_with_env(HashMap::new(), http.clone());
    let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?;

    let signer = Signer::new(context.clone(), provider.clone(), RequestSigner);
    for _ in 0..2 {
        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer cached-access-token"
        );
    }
    assert_eq!(http.calls(), 1, "sequential calls must reuse the cache");

    // A separately constructed signer has its own access-token cache but shares
    // the provider's rotated refresh-token state.
    let second = Signer::new(context, provider, RequestSigner);
    let mut parts = request();
    second.sign(&mut parts, None).await?;
    assert_eq!(http.calls(), 2);
    assert_eq!(
        decoded_form(&http.requests()[1].body)["refresh_token"],
        "rotated-refresh-token"
    );
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer second-access-token"
    );

    Ok(())
}

#[tokio::test]
async fn missing_or_zero_expiration_is_rejected_after_rotating_the_refresh_token() -> Result<()> {
    for expires_in in [None, Some(0)] {
        let http = MockHttpSend::new([
            Ok(token_response(
                "unusable-access-token",
                expires_in,
                Some("rotated-refresh-token"),
            )),
            Ok(token_response(
                "fresh-access-token",
                Some(3600),
                Some("second-refresh-token"),
            )),
        ]);
        let context = context_with_env(HashMap::new(), http.clone());
        let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?;
        let signer = Signer::new(context, provider, RequestSigner);
        let mut parts = request();
        let original = parts.clone();

        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("expiration required by Dropbox must be enforced");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(http.calls(), 1);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);

        let mut parts = request();
        signer.sign(&mut parts, None).await?;
        assert_eq!(http.calls(), 2);
        assert_eq!(
            decoded_form(&http.requests()[1].body)["refresh_token"],
            "rotated-refresh-token",
            "the rejected exchange must still commit its replacement token"
        );
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer fresh-access-token"
        );
    }

    Ok(())
}

#[tokio::test]
async fn presigning_and_missing_credentials_are_rejected_without_mutation() -> Result<()> {
    let http = MockHttpSend::new([]);
    let context = context_with_env(HashMap::new(), http);
    let signer = Signer::new(
        context.clone(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );

    let mut parts = request();
    let original = parts.clone();
    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("Dropbox has no query authentication");
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let mut parts = request();
    let original = parts.clone();
    let error = RequestSigner
        .sign_request(&context, &mut parts, None, None)
        .await
        .expect_err("direct signing without a credential must fail");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn response_failures_are_redacted_through_the_public_signer() -> Result<()> {
    const SENTINEL: &str = "DROPBOX_RESPONSE_SENTINEL";
    let body = format!(
        r#"{{"error":"invalid_grant","error_description":"{SENTINEL}","access_token":"{SENTINEL}"}}"#
    );
    let http = MockHttpSend::new([Ok(http::Response::builder()
        .status(http::StatusCode::BAD_REQUEST)
        .body(Bytes::from(body))
        .expect("response must build"))]);
    let context = context_with_env(HashMap::new(), http);
    let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?;
    let signer = Signer::new(context, provider, RequestSigner);
    let mut parts = request();
    let original = parts.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("rejected refresh must fail");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert!(!error.to_string().contains(SENTINEL));
    assert!(!format!("{error:?}").contains(SENTINEL));
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn credential_debug_output_redacts_the_access_token() -> Result<()> {
    let provider = StaticCredentialProvider::new(STATIC_TOKEN);
    assert!(!format!("{provider:?}").contains(STATIC_TOKEN));
    let credential = provider.provide_credential(&Context::new()).await?.unwrap();
    let debug = format!("{credential:?}");

    assert!(!debug.contains(STATIC_TOKEN));
    assert!(debug.contains("access_token"));

    Ok(())
}

#[tokio::test]
async fn refresh_endpoint_can_be_replaced_explicitly() -> Result<()> {
    let http = MockHttpSend::new([Ok(token_response("access-token-A1", Some(3600), None))]);
    let context = context_with_env(HashMap::new(), http.clone());
    let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?
        .with_token_endpoint("https://trusted.example/oauth2/token?tenant=common")?;
    let signer = Signer::new(context, provider, RequestSigner);

    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    assert_eq!(
        http.requests()[0].uri,
        "https://trusted.example/oauth2/token?tenant=common"
    );

    Ok(())
}

#[tokio::test]
async fn refresh_errors_are_not_retried_implicitly() -> Result<()> {
    let http = MockHttpSend::new([
        Err(Error::unexpected("transient").set_retryable(true)),
        Ok(token_response("access-token-A1", Some(3600), None)),
    ]);
    let context = context_with_env(HashMap::new(), http.clone());
    let provider = RefreshCredentialProvider::new(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN)?;
    let signer = Signer::new(context, provider, RequestSigner);
    let mut parts = request();

    signer
        .sign(&mut parts, None)
        .await
        .expect_err("one failed exchange must not be retried");
    assert_eq!(http.calls(), 1);

    Ok(())
}
