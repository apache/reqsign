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
use http::Method;
use http::StatusCode;
use http::header;
use reqsign_core::{
    Context, Error, ErrorKind, FileRead, HttpSend, ProvideCredential, Result, Signer, StaticEnv,
};
use reqsign_seafile::{
    AccountTokenCredentialProvider, ConfigFileCredentialProvider, DefaultCredentialProvider,
    RequestSigner, StaticCredentialProvider,
};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

const TOKEN: &str = "0123456789abcdef0123456789abcdef01234567";

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: Method,
    uri: http::Uri,
    headers: http::HeaderMap,
    body: Bytes,
}

#[derive(Clone, Default)]
struct MockHttpSend {
    requests: Arc<StdMutex<Vec<RecordedRequest>>>,
    responses: Arc<StdMutex<VecDeque<http::Response<Bytes>>>>,
}

impl std::fmt::Debug for MockHttpSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHttpSend")
            .field(
                "requests",
                &self.requests.lock().expect("request lock").len(),
            )
            .finish_non_exhaustive()
    }
}

impl MockHttpSend {
    fn push_response(&self, response: http::Response<Bytes>) {
        self.responses
            .lock()
            .expect("response lock")
            .push_back(response);
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, req: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        let (parts, body) = req.into_parts();
        self.requests
            .lock()
            .expect("request lock")
            .push(RecordedRequest {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                body,
            });

        self.responses
            .lock()
            .expect("response lock")
            .pop_front()
            .ok_or_else(|| Error::unexpected("mock HTTP response queue is empty"))
    }
}

#[derive(Clone, Default, Debug)]
struct MockFileRead {
    files: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    reads: Arc<AtomicUsize>,
}

impl MockFileRead {
    fn with_file(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            files: Arc::new(StdMutex::new(HashMap::from([(
                path.into(),
                content.into(),
            )]))),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl FileRead for MockFileRead {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.files
            .lock()
            .expect("file lock")
            .get(path)
            .cloned()
            .ok_or_else(|| Error::unexpected("mock file does not exist"))
    }
}

fn context(home: &str, http: MockHttpSend, files: MockFileRead) -> Context {
    Context::new()
        .with_http_send(http)
        .with_file_read(files)
        .with_env(StaticEnv {
            home_dir: Some(PathBuf::from(home)),
            envs: HashMap::new(),
        })
}

fn json_response(status: StatusCode, body: impl Into<Bytes>) -> http::Response<Bytes> {
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .expect("response must build")
}

fn request_at(uri: &str) -> http::request::Parts {
    http::Request::get(uri)
        .header(header::AUTHORIZATION, "Bearer stale")
        .header("x-caller", "value")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn request() -> http::request::Parts {
    request_at("https://files.example.com/company/seafile/api2/repos/?x=%2F")
}

#[tokio::test]
async fn account_exchange_preserves_base_path_and_signs_with_token() -> Result<()> {
    let http = MockHttpSend::default();
    http.push_response(json_response(
        StatusCode::OK,
        format!(r#"{{"token":"{TOKEN}"}}"#),
    ));

    let signer = Signer::new(
        Context::new().with_http_send(http.clone()),
        AccountTokenCredentialProvider::new(
            "https://files.example.com/company/seafile/",
            "user+tag@example.com",
            "password&with=chars",
        ),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

    let authorization = parts
        .headers
        .get(header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(
        authorization.to_str().expect("Authorization must be text"),
        format!("Token {TOKEN}")
    );
    assert!(authorization.is_sensitive());
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.headers["x-caller"], "value");

    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request.uri.to_string(),
        "https://files.example.com/company/seafile/api2/auth-token/"
    );
    assert_eq!(
        request.headers[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );

    let fields: HashMap<String, String> =
        form_urlencoded::parse(&request.body).into_owned().collect();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields["username"], "user+tag@example.com");
    assert_eq!(fields["password"], "password&with=chars");

    Ok(())
}

#[tokio::test]
async fn signer_caches_the_account_exchange() -> Result<()> {
    let http = MockHttpSend::default();
    http.push_response(json_response(
        StatusCode::OK,
        format!(r#"{{"token":"{TOKEN}"}}"#),
    ));

    let signer = Signer::new(
        Context::new().with_http_send(http.clone()),
        AccountTokenCredentialProvider::new(
            "https://files.example.com",
            "user@example.com",
            "password",
        ),
        RequestSigner,
    );

    let mut first = request();
    let mut second = request();
    signer.sign(&mut first, None).await?;
    signer.sign(&mut second, None).await?;

    assert_eq!(
        first.headers[header::AUTHORIZATION],
        format!("Token {TOKEN}")
    );
    assert_eq!(
        second.headers[header::AUTHORIZATION],
        format!("Token {TOKEN}")
    );
    assert_eq!(http.requests().len(), 1);

    Ok(())
}

#[tokio::test]
async fn account_exchange_failure_does_not_echo_credentials_or_response_body() {
    let http = MockHttpSend::default();
    http.push_response(json_response(
        StatusCode::UNAUTHORIZED,
        r#"{"message":"response-body-secret"}"#,
    ));

    let signer = Signer::new(
        Context::new().with_http_send(http),
        AccountTokenCredentialProvider::new(
            "https://files.example.com",
            "user@example.com",
            "password-secret",
        ),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("authentication failure must not sign");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    let debug = format!("{error:?}");
    assert!(debug.contains("status 401"));
    assert!(!debug.contains("password-secret"));
    assert!(!debug.contains("response-body-secret"));
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
}

#[tokio::test]
async fn account_exchange_rejects_invalid_servers_before_io() {
    for server in [
        "files.example.com",
        "ftp://files.example.com",
        "https://files.example.com?query=1",
        "https://user:pass@files.example.com",
    ] {
        let http = MockHttpSend::default();
        let provider = AccountTokenCredentialProvider::new(server, "user", "password");
        let error = provider
            .provide_credential(&Context::new().with_http_send(http.clone()))
            .await
            .expect_err("invalid server must fail");

        assert_eq!(
            error.kind(),
            ErrorKind::ConfigInvalid,
            "unexpected error for {server}: {error:?}"
        );
        assert!(http.requests().is_empty(), "I/O ran for {server}");
    }
}

#[tokio::test]
async fn default_provider_reads_the_seaf_cli_account_token() -> Result<()> {
    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\nserver = https://files.example.com\nuser = user@example.com\ntoken = cli-token\n",
    );
    let http = MockHttpSend::default();
    let signer = Signer::new(
        context("/home/seafile", http.clone(), files),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(parts.headers[header::AUTHORIZATION], "Token cli-token");
    assert!(http.requests().is_empty());

    Ok(())
}

#[tokio::test]
async fn missing_config_file_and_removed_slot_yield_no_credential() -> Result<()> {
    let ctx = context(
        "/home/seafile",
        MockHttpSend::default(),
        MockFileRead::default(),
    );
    let provider = DefaultCredentialProvider::new();
    assert!(
        provider.provide_credential(&ctx).await?.is_none(),
        "missing config file must not produce a credential"
    );

    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\ntoken = cli-token\n",
    );
    let ctx = context("/home/seafile", MockHttpSend::default(), files);
    let provider = DefaultCredentialProvider::builder()
        .no_config_file()
        .build();
    assert!(
        provider.provide_credential(&ctx).await?.is_none(),
        "no_config_file must remove the default source"
    );

    Ok(())
}

#[tokio::test]
async fn self_hosted_http_subpath_configuration_is_supported() -> Result<()> {
    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\nserver = http://127.0.0.1:8080/seafile\ntoken = self-hosted-token\n",
    );
    let signer = Signer::new(
        context("/home/seafile", MockHttpSend::default(), files),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = request_at("http://127.0.0.1:8080/seafile/api2/repos/");

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[header::AUTHORIZATION],
        "Token self-hosted-token"
    );

    Ok(())
}

#[tokio::test]
async fn malformed_config_file_is_a_configuration_error() {
    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\ntoken = config-secret\nthis line is not valid ini",
    );
    let context = context("/home/seafile", MockHttpSend::default(), files);
    let error = DefaultCredentialProvider::new()
        .provide_credential(&context)
        .await
        .expect_err("malformed config must fail");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(!format!("{error:?}").contains("config-secret"));
}

#[tokio::test]
async fn static_token_override_replaces_the_default_source() -> Result<()> {
    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\ntoken = cli-token\n",
    );
    let signer = Signer::new(
        context("/home/seafile", MockHttpSend::default(), files),
        DefaultCredentialProvider::new()
            .push_front(StaticCredentialProvider::new("explicit-token")),
        RequestSigner,
    );
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(parts.headers[header::AUTHORIZATION], "Token explicit-token");

    Ok(())
}

#[tokio::test]
async fn static_provider_rejects_unusable_tokens() {
    for token in ["", "token with space", "token-\u{00e9}"] {
        let error = StaticCredentialProvider::new(token)
            .provide_credential(&Context::new())
            .await
            .expect_err("unusable static token must fail");

        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
}

#[tokio::test]
async fn config_file_provider_honors_an_explicit_path() -> Result<()> {
    let files = MockFileRead::with_file(
        "/custom/seafile.conf",
        "[account]\nserver = https://files.example.com\ntoken = custom-token\n",
    );
    let context = context("/home/seafile", MockHttpSend::default(), files);
    let provider = ConfigFileCredentialProvider::new().with_path("/custom/seafile.conf");

    let credential = provider
        .provide_credential(&context)
        .await?
        .expect("explicit config path must load the token");

    assert_eq!(credential.token(), "custom-token");

    Ok(())
}

fn assert_request_unchanged(original: &http::request::Parts, parts: &http::request::Parts) {
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.version, original.version);
    assert_eq!(parts.headers, original.headers);
}

#[tokio::test]
async fn config_scope_is_checked_each_time_even_with_a_cached_credential() -> Result<()> {
    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\nserver = https://Files.Example.com:443/seafile/\ntoken = scoped-token\n",
    );
    let reads = files.clone();
    let signer = Signer::new(
        context("/home/seafile", MockHttpSend::default(), files),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );

    let mut allowed = request_at("https://files.example.com/seafile/api2/repos/");
    signer.sign(&mut allowed, None).await?;
    assert_eq!(allowed.headers[header::AUTHORIZATION], "Token scoped-token");

    for uri in [
        "http://files.example.com/seafile/api2/repos/",
        "https://other.example.com/seafile/api2/repos/",
        "https://files.example.com:8443/seafile/api2/repos/",
        "https://files.example.com/seafile-other/api2/repos/",
        "https://files.example.com/other/api2/repos/",
        "https://files.example.com/api2/repos/",
    ] {
        let original = request_at(uri);
        let mut parts = original.clone();
        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("out-of-scope request must not be signed");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_request_unchanged(&original, &parts);
        let debug = format!("{error:?}");
        assert!(!debug.contains("scoped-token"));
        assert!(!debug.contains("other.example.com"));
    }

    assert_eq!(reads.reads(), 1, "the cached credential must be reused");

    Ok(())
}

#[tokio::test]
async fn config_file_requires_a_usable_server_and_can_match_the_selected_account() -> Result<()> {
    for content in [
        "[account]\ntoken = token-without-server\n",
        "[account]\nserver = ftp://files.example.com\ntoken = token-with-invalid-server\n",
    ] {
        let files = MockFileRead::with_file("/home/seafile/.seafile.conf", content);
        let context = context("/home/seafile", MockHttpSend::default(), files);
        let error = ConfigFileCredentialProvider::new()
            .provide_credential(&context)
            .await
            .expect_err("an incomplete or invalid deployment must fail");

        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(!format!("{error:?}").contains("token-with"));
    }

    let files = MockFileRead::with_file(
        "/home/seafile/.seafile.conf",
        "[account]\nserver = https://files.example.com/seafile\nuser = user@example.com\ntoken = selected-account-token\n",
    );
    let ctx = context("/home/seafile", MockHttpSend::default(), files);
    let provider = ConfigFileCredentialProvider::new().with_account_user("user@example.com");
    assert!(!format!("{provider:?}").contains("user@example.com"));

    let credential = provider
        .provide_credential(&ctx)
        .await?
        .expect("the selected account must load");

    assert_eq!(credential.token(), "selected-account-token");

    for content in [
        "[account]\nserver = https://files.example.com/seafile\nuser = other@example.com\ntoken = selected-account-token\n",
        "[account]\nserver = https://files.example.com/seafile\ntoken = selected-account-token\n",
    ] {
        let files = MockFileRead::with_file("/home/seafile/.seafile.conf", content);
        let ctx = context("/home/seafile", MockHttpSend::default(), files);
        let error = ConfigFileCredentialProvider::new()
            .with_account_user("user@example.com")
            .provide_credential(&ctx)
            .await
            .expect_err("a different or missing account must fail");

        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(!format!("{error:?}").contains("user@example.com"));
        assert!(!format!("{error:?}").contains("selected-account-token"));
    }

    Ok(())
}

#[tokio::test]
async fn account_exchange_scope_is_checked_each_time_even_with_a_cached_credential() -> Result<()> {
    let http = MockHttpSend::default();
    http.push_response(json_response(
        StatusCode::OK,
        format!(r#"{{"token":"{TOKEN}"}}"#),
    ));
    let signer = Signer::new(
        Context::new().with_http_send(http.clone()),
        AccountTokenCredentialProvider::new(
            "https://files.example.com/seafile",
            "user@example.com",
            "password",
        ),
        RequestSigner,
    );

    let mut allowed = request_at("https://files.example.com/seafile/api2/repos/");
    signer.sign(&mut allowed, None).await?;
    assert_eq!(
        allowed.headers[header::AUTHORIZATION],
        format!("Token {TOKEN}")
    );

    for uri in [
        "https://files.example.com/other/api2/repos/",
        "https://other.example.com/seafile/api2/repos/",
    ] {
        let original = request_at(uri);
        let mut parts = original.clone();
        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("out-of-scope request must not be signed");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_request_unchanged(&original, &parts);
    }

    assert_eq!(http.requests().len(), 1, "the exchange must be cached");

    Ok(())
}

#[tokio::test]
async fn invalid_success_response_is_content_free_on_the_public_error_path() {
    const MARKER: &str = "synthetic-response-marker";
    let http = MockHttpSend::default();
    http.push_response(json_response(StatusCode::OK, format!(r#""{MARKER}""#)));
    let signer = Signer::new(
        Context::new().with_http_send(http),
        AccountTokenCredentialProvider::new(
            "https://files.example.com",
            "user@example.com",
            "password",
        ),
        RequestSigner,
    );
    let original = request_at("https://files.example.com/api2/repos/");
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("malformed success response must fail");

    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(!error.to_string().contains(MARKER));
    assert!(!format!("{error:?}").contains(MARKER));
    assert!(std::error::Error::source(&error).is_none());
    let mut source = std::error::Error::source(&error);
    while let Some(inner) = source {
        assert!(!format!("{inner}").contains(MARKER));
        assert!(!format!("{inner:?}").contains(MARKER));
        source = inner.source();
    }
    assert_request_unchanged(&original, &parts);
}
