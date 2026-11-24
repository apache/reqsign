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

use reqsign_core::time::Timestamp;
use reqsign_core::{
    CommandExecute, CommandOutput, Context, Error, ErrorKind, ProvideCredential,
    ProvideCredentialChain, Result, SignRequest, Signer, StaticEnv,
};
use reqsign_github::{
    AnonymousCredentialProvider, Credential, DefaultCredentialProvider, EnvCredentialProvider,
    GhCliCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const ENV_TOKEN: &str = "env-token-A1";
const STATIC_TOKEN: &str = "static-token-B2";
const CLI_TOKEN: &str = "cli-token-C3";
const GITHUB_HOST: &str = "github.com";
const AUTHORIZATION: http::header::HeaderName = http::header::AUTHORIZATION;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedCommand {
    program: String,
    args: Vec<String>,
}

#[derive(Clone)]
enum MockCommandResult {
    Output(CommandOutput),
    AdapterError(String),
    AdapterIoError(std::io::ErrorKind),
}

#[derive(Clone)]
struct MockCommandExecute {
    calls: Arc<StdMutex<Vec<RecordedCommand>>>,
    results: Arc<StdMutex<VecDeque<MockCommandResult>>>,
}

impl std::fmt::Debug for MockCommandExecute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockCommandExecute")
            .field("calls", &self.calls.lock().expect("call lock").len())
            .finish_non_exhaustive()
    }
}

impl MockCommandExecute {
    fn sequence(results: impl IntoIterator<Item = MockCommandResult>) -> Self {
        Self {
            calls: Arc::new(StdMutex::new(Vec::new())),
            results: Arc::new(StdMutex::new(results.into_iter().collect())),
        }
    }

    fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self::sequence([MockCommandResult::Output(CommandOutput {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        })])
    }

    fn failure(status: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self::sequence([MockCommandResult::Output(CommandOutput {
            status,
            stdout: Vec::new(),
            stderr: stderr.into(),
        })])
    }

    fn adapter_error(message: impl Into<String>) -> Self {
        Self::sequence([MockCommandResult::AdapterError(message.into())])
    }

    fn calls(&self) -> Vec<RecordedCommand> {
        self.calls.lock().expect("call lock").clone()
    }
}

impl CommandExecute for MockCommandExecute {
    async fn command_execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput> {
        self.calls.lock().expect("call lock").push(RecordedCommand {
            program: program.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        });

        match self
            .results
            .lock()
            .expect("result lock")
            .pop_front()
            .expect("mock result must exist")
        {
            MockCommandResult::Output(output) => Ok(output),
            MockCommandResult::AdapterError(message) => Err(Error::unexpected(message)),
            MockCommandResult::AdapterIoError(kind) => {
                Err(Error::unexpected("fabricated command execution failure")
                    .with_source(std::io::Error::new(kind, "SENTINEL_IO_SOURCE")))
            }
        }
    }
}

fn missing_executable_result() -> MockCommandResult {
    MockCommandResult::AdapterIoError(std::io::ErrorKind::NotFound)
}

fn user_result(user: &str) -> MockCommandResult {
    MockCommandResult::Output(CommandOutput {
        status: 0,
        stdout: format!("{user}\n").into_bytes(),
        stderr: Vec::new(),
    })
}

fn token_result(token: &str) -> MockCommandResult {
    MockCommandResult::Output(CommandOutput {
        status: 0,
        stdout: format!("{token}\n").into_bytes(),
        stderr: Vec::new(),
    })
}

fn failure_result(status: i32, stderr: impl Into<Vec<u8>>) -> MockCommandResult {
    MockCommandResult::Output(CommandOutput {
        status,
        stdout: Vec::new(),
        stderr: stderr.into(),
    })
}

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn context_with_command(envs: HashMap<String, String>, command: MockCommandExecute) -> Context {
    context(envs).with_command_execute(command)
}

fn request() -> http::request::Parts {
    http::Request::builder()
        .method(http::Method::GET)
        .uri("https://api.github.com/repos/apache/reqsign/contents/README.md?ref=main&x=%2F")
        .header(http::header::USER_AGENT, "opendal-test")
        .header("x-github-api-version", "2022-11-28")
        .header(http::header::ACCEPT, "application/vnd.github.raw+json")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn stale_request() -> http::request::Parts {
    let mut parts = request();
    parts.headers.insert(
        AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-token-D4"),
    );
    parts
}

async fn sign_parts(
    provider: impl ProvideCredential<Credential = Credential>,
    ctx: Context,
    mut parts: http::request::Parts,
) -> Result<http::request::Parts> {
    let signer = Signer::new(ctx, provider, RequestSigner);
    signer.sign(&mut parts, None).await?;
    Ok(parts)
}

#[tokio::test]
async fn token_signing_replaces_stale_authorization_and_preserves_request() -> Result<()> {
    let original = stale_request();
    let parts = sign_parts(
        StaticCredentialProvider::new(STATIC_TOKEN),
        Context::new(),
        original.clone(),
    )
    .await?;

    let authorization = parts
        .headers
        .get(AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(
        authorization.to_str().expect("Authorization must be text"),
        format!("Bearer {STATIC_TOKEN}")
    );
    assert!(authorization.is_sensitive());
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.headers[http::header::USER_AGENT], "opendal-test");
    assert_eq!(parts.headers["x-github-api-version"], "2022-11-28");
    assert_eq!(
        parts.headers[http::header::ACCEPT],
        "application/vnd.github.raw+json"
    );
    Ok(())
}

#[tokio::test]
async fn anonymous_signing_removes_stale_authorization_and_preserves_other_headers() -> Result<()> {
    let original = stale_request();
    let parts = sign_parts(
        AnonymousCredentialProvider::new(),
        Context::new(),
        original.clone(),
    )
    .await?;

    assert!(!parts.headers.contains_key(AUTHORIZATION));
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.headers[http::header::USER_AGENT], "opendal-test");
    assert_eq!(parts.headers["x-github-api-version"], "2022-11-28");
    assert_eq!(
        parts.headers[http::header::ACCEPT],
        "application/vnd.github.raw+json"
    );

    let unsigned = request();
    let parts = sign_parts(
        AnonymousCredentialProvider::new(),
        Context::new(),
        unsigned.clone(),
    )
    .await?;
    assert!(!parts.headers.contains_key(AUTHORIZATION));
    assert_eq!(parts.headers, unsigned.headers);
    Ok(())
}

#[tokio::test]
async fn expires_in_is_rejected_without_mutating_the_request() -> Result<()> {
    let original = stale_request();
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("GitHub has no query authentication");

    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn missing_credential_is_rejected_without_mutating_the_request() -> Result<()> {
    let original = stale_request();
    let mut parts = original.clone();

    let error = RequestSigner
        .sign_request(&Context::new(), &mut parts, None, None)
        .await
        .expect_err("a credential is required");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[test]
fn request_signer_does_not_read_the_wall_clock() {
    let credential = Credential::anonymous();
    assert_eq!(
        RequestSigner.required_valid_until(&credential, None),
        Timestamp::default()
    );
}

#[tokio::test]
async fn env_prefers_gh_token_then_github_token() -> Result<()> {
    let cases: Vec<(HashMap<String, String>, Option<&str>)> = vec![
        (
            HashMap::from([
                ("GH_TOKEN".to_string(), ENV_TOKEN.to_string()),
                ("GITHUB_TOKEN".to_string(), "github-token".to_string()),
            ]),
            Some(ENV_TOKEN),
        ),
        (
            HashMap::from([("GITHUB_TOKEN".to_string(), "github-token".to_string())]),
            Some("github-token"),
        ),
        (
            HashMap::from([
                ("GH_TOKEN".to_string(), String::new()),
                ("GITHUB_TOKEN".to_string(), "github-token".to_string()),
            ]),
            Some("github-token"),
        ),
        (
            HashMap::from([
                ("GH_TOKEN".to_string(), ENV_TOKEN.to_string()),
                ("GH_HOST".to_string(), "ghe.example.com".to_string()),
            ]),
            Some(ENV_TOKEN),
        ),
        (
            HashMap::from([(
                "GH_ENTERPRISE_TOKEN".to_string(),
                "enterprise-token".to_string(),
            )]),
            None,
        ),
    ];

    for (envs, expected) in cases {
        let parts = sign_parts(DefaultCredentialProvider::new(), context(envs), request()).await?;
        match expected {
            Some(expected) => assert_eq!(
                parts.headers[AUTHORIZATION].to_str().expect("header text"),
                format!("Bearer {expected}")
            ),
            None => assert!(!parts.headers.contains_key(AUTHORIZATION)),
        }
    }
    Ok(())
}

#[tokio::test]
async fn gh_cli_discovery_is_host_scoped_and_env_independent() -> Result<()> {
    let command = MockCommandExecute::sequence([user_result("cli-user"), token_result(CLI_TOKEN)]);
    let ctx = context_with_command(
        HashMap::from([("GH_TOKEN".to_string(), ENV_TOKEN.to_string())]),
        command.clone(),
    );
    let provider = DefaultCredentialProvider::builder().no_env().build();

    let parts = sign_parts(provider, ctx, request()).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {CLI_TOKEN}")
    );
    assert_eq!(
        command.calls(),
        vec![
            RecordedCommand {
                program: "gh".to_string(),
                args: ["config", "get", "user", "--host", GITHUB_HOST]
                    .map(str::to_string)
                    .to_vec(),
            },
            RecordedCommand {
                program: "gh".to_string(),
                args: [
                    "auth",
                    "token",
                    "--hostname",
                    GITHUB_HOST,
                    "--user",
                    "cli-user",
                    "--no-refresh",
                ]
                .map(str::to_string)
                .to_vec(),
            },
        ]
    );
    Ok(())
}

#[tokio::test]
async fn gh_cli_missing_account_or_token_falls_back_to_anonymous() -> Result<()> {
    // A bare context has no command executor, so CLI discovery does not
    // participate at all.
    let parts = sign_parts(
        DefaultCredentialProvider::new(),
        context(HashMap::new()),
        request(),
    )
    .await?;
    assert!(!parts.headers.contains_key(AUTHORIZATION));

    let cases = vec![
        // An adapter that reports no typed I/O cause cannot run commands in
        // this context, such as the no-op adapter installed by
        // `Context::new()`. The slot stays absent.
        MockCommandExecute::adapter_error("SENTINEL_CONFIG_ADAPTER"),
        // `gh` is not installed: the typed spawn error is NotFound.
        MockCommandExecute::sequence([missing_executable_result()]),
        // Older GitHub CLI versions print nothing for a host without an
        // account; newer versions report the missing key explicitly.
        MockCommandExecute::success(Vec::new()),
        MockCommandExecute::failure(1, b"could not find key \"user\"\n".to_vec()),
        MockCommandExecute::sequence([
            user_result("cli-user"),
            failure_result(
                1,
                b"no oauth token found for github.com account cli-user".to_vec(),
            ),
        ]),
    ];

    for command in cases {
        let ctx = context_with_command(HashMap::new(), command);
        let parts = sign_parts(DefaultCredentialProvider::new(), ctx, request()).await?;
        assert!(!parts.headers.contains_key(AUTHORIZATION));
    }
    Ok(())
}

#[tokio::test]
async fn gh_cli_config_lookup_failure_is_reported_without_leaking() {
    let cases = [
        // Only NotFound means the executable is missing. A permission failure
        // must not fall back to anonymous access.
        (
            MockCommandExecute::sequence([MockCommandResult::AdapterIoError(
                std::io::ErrorKind::PermissionDenied,
            )]),
            ErrorKind::Unexpected,
        ),
        // Any other non-zero status means the CLI configuration could not be
        // read.
        (
            MockCommandExecute::failure(
                1,
                b"failed to read config SENTINEL_CONFIG_STDERR".to_vec(),
            ),
            ErrorKind::ConfigInvalid,
        ),
    ];

    for (command, expected_kind) in cases {
        let ctx = context_with_command(HashMap::new(), command);
        let error = GhCliCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect_err("a config lookup failure must not become anonymous access");

        assert_eq!(error.kind(), expected_kind);
        let debug = format!("{error:?}");
        assert!(!debug.contains("SENTINEL_CONFIG_STDERR"));
        assert!(!debug.contains("SENTINEL_IO_SOURCE"));
    }
}

#[tokio::test]
async fn gh_cli_malformed_active_user_is_reported_without_leaking() {
    let cases = [
        b"--help\n".to_vec(),
        b"bad user\n".to_vec(),
        b"first\nsecond\n".to_vec(),
        b"nonutf8\xff".to_vec(),
        b" \n".to_vec(),
    ];

    for stdout in cases {
        let command = MockCommandExecute::sequence([MockCommandResult::Output(CommandOutput {
            status: 0,
            stdout: stdout.clone(),
            stderr: Vec::new(),
        })]);
        let ctx = context_with_command(HashMap::new(), command);
        let error = GhCliCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect_err("malformed account output must fail");

        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        let debug = format!("{error:?}");
        assert!(!debug.contains("first"));
        assert!(!debug.contains("second"));
        assert!(!debug.contains("bad user"));
        assert!(!debug.contains("nonutf8"));
    }
}

#[tokio::test]
async fn default_provider_rejects_config_lookup_failure_without_mutating_the_request() -> Result<()>
{
    let cases = [
        MockCommandExecute::sequence([MockCommandResult::AdapterIoError(
            std::io::ErrorKind::PermissionDenied,
        )]),
        MockCommandExecute::failure(1, b"failed to read config SENTINEL_CONFIG_STDERR".to_vec()),
        MockCommandExecute::sequence([user_result("--help")]),
        MockCommandExecute::sequence([user_result("bad user")]),
    ];

    for command in cases {
        let ctx = context_with_command(HashMap::new(), command);
        let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
        let original = stale_request();
        let mut parts = original.clone();

        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("a config lookup failure must not become anonymous access");

        assert!(!error.to_string().contains("SENTINEL_CONFIG"));
        assert!(!format!("{error:?}").contains("SENTINEL_CONFIG"));
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(parts.headers[AUTHORIZATION], "Bearer stale-token-D4");
    }
    Ok(())
}

#[tokio::test]
async fn gh_cli_token_lookup_adapter_error_is_reported_without_leaking() {
    let cases = [
        (
            MockCommandExecute::sequence([
                user_result("cli-user"),
                MockCommandResult::AdapterError("SENTINEL_TOKEN_ADAPTER".to_string()),
            ]),
            2,
        ),
        (
            MockCommandExecute::sequence([
                user_result("cli-user"),
                failure_result(1, b"unknown flag: --no-refresh".to_vec()),
                MockCommandResult::AdapterError("SENTINEL_RETRY_ADAPTER".to_string()),
            ]),
            3,
        ),
    ];

    for (command, expected_calls) in cases {
        let ctx = context_with_command(HashMap::new(), command.clone());
        let error = GhCliCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect_err("a token lookup adapter error must not become anonymous access");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        let debug = format!("{error:?}");
        assert!(!debug.contains("SENTINEL_TOKEN_ADAPTER"));
        assert!(!debug.contains("SENTINEL_RETRY_ADAPTER"));
        assert_eq!(command.calls().len(), expected_calls);
    }
}

#[tokio::test]
async fn gh_cli_other_token_failure_is_reported_without_leaking() {
    let command = MockCommandExecute::sequence([
        user_result("cli-user"),
        failure_result(1, b"the token is expired SENTINEL_STDERR".to_vec()),
    ]);
    let ctx = context_with_command(HashMap::new(), command);

    let error = GhCliCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect_err("a failed stored-token read must not become anonymous access");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    let debug = format!("{error:?}");
    assert!(!debug.contains("SENTINEL_STDERR"));
    assert!(!debug.contains("expired SENTINEL"));
}

#[tokio::test]
async fn default_provider_rejects_failed_stored_token_read() -> Result<()> {
    let command = MockCommandExecute::sequence([
        user_result("cli-user"),
        failure_result(1, b"the token is expired SENTINEL_STDERR".to_vec()),
    ]);
    let ctx = context_with_command(HashMap::new(), command);
    let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
    let original = stale_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("a failed stored-token read must not become anonymous access");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn default_provider_rejects_incomplete_stored_token_lookup() -> Result<()> {
    let cases = [
        (
            MockCommandExecute::sequence([
                user_result("cli-user"),
                MockCommandResult::AdapterError("SENTINEL_TOKEN_ADAPTER".to_string()),
            ]),
            ErrorKind::CredentialInvalid,
        ),
        (
            MockCommandExecute::sequence([
                user_result("cli-user"),
                MockCommandResult::Output(CommandOutput {
                    status: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }),
            ]),
            ErrorKind::ConfigInvalid,
        ),
        (
            MockCommandExecute::sequence([
                user_result("cli-user"),
                MockCommandResult::Output(CommandOutput {
                    status: 0,
                    stdout: b" \n\t".to_vec(),
                    stderr: Vec::new(),
                }),
            ]),
            ErrorKind::ConfigInvalid,
        ),
    ];

    for (command, expected_kind) in cases {
        let ctx = context_with_command(HashMap::new(), command);
        let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
        let original = stale_request();
        let mut parts = original.clone();

        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("an incomplete stored-token lookup must not become anonymous access");

        assert_eq!(error.kind(), expected_kind);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
    }
    Ok(())
}

#[tokio::test]
async fn gh_cli_retries_without_no_refresh_only_when_the_flag_is_unknown() -> Result<()> {
    let command = MockCommandExecute::sequence([
        user_result("cli-user"),
        failure_result(1, b"unknown flag: --no-refresh".to_vec()),
        token_result(CLI_TOKEN),
    ]);
    let ctx = context_with_command(HashMap::new(), command.clone());

    let parts = sign_parts(DefaultCredentialProvider::new(), ctx, request()).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {CLI_TOKEN}")
    );
    let calls = command.calls();
    assert_eq!(calls.len(), 3);
    assert!(calls[1].args.contains(&"--no-refresh".to_string()));
    assert!(!calls[2].args.contains(&"--no-refresh".to_string()));
    assert_eq!(
        calls[2].args,
        [
            "auth",
            "token",
            "--hostname",
            GITHUB_HOST,
            "--user",
            "cli-user",
        ]
        .map(str::to_string)
        .to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn gh_cli_rejects_unsupported_user_flag_without_retry() {
    let command = MockCommandExecute::sequence([
        user_result("cli-user"),
        failure_result(1, b"unknown flag: --user SENTINEL_STDERR".to_vec()),
    ]);
    let ctx = context_with_command(HashMap::new(), command.clone());

    let error = GhCliCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect_err("an unsupported --user flag must not be retried unsafely");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    let debug = format!("{error:?}");
    assert!(debug.contains("2.40.0"));
    assert!(!debug.contains("SENTINEL_STDERR"));
    assert_eq!(command.calls().len(), 2);
}

#[tokio::test]
async fn gh_cli_malformed_successful_output_is_reported_without_leaking_it() {
    let cases = [
        Vec::new(),
        b" \n\t".to_vec(),
        b"\r\n".to_vec(),
        b"first\nsecond".to_vec(),
        b"token with spaces".to_vec(),
        b"nonutf8\xff".to_vec(),
        "🚀🚀🚀🚀".as_bytes().to_vec(),
    ];

    for stdout in cases {
        let command = MockCommandExecute::sequence([
            user_result("cli-user"),
            MockCommandResult::Output(CommandOutput {
                status: 0,
                stdout,
                stderr: Vec::new(),
            }),
        ]);
        let ctx = context_with_command(HashMap::new(), command);
        let error = GhCliCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .expect_err("malformed output must fail");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

        let debug = format!("{error:?}");
        assert!(!debug.contains("first"));
        assert!(!debug.contains("second"));
        assert!(!debug.contains("token with spaces"));
        assert!(!debug.contains("nonutf8"));
        assert!(!debug.contains("🚀"));
    }
}

#[tokio::test]
async fn default_provider_rejects_malformed_cli_output_instead_of_anonymous() -> Result<()> {
    let command = MockCommandExecute::sequence([
        user_result("cli-user"),
        MockCommandResult::Output(CommandOutput {
            status: 0,
            stdout: b"first\nsecond".to_vec(),
            stderr: Vec::new(),
        }),
    ]);
    let ctx = context_with_command(HashMap::new(), command);
    let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
    let original = stale_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("malformed CLI output must not become anonymous access");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn prepended_invalid_static_credential_does_not_fall_back() -> Result<()> {
    for token in ["", "🚀🚀🚀🚀"] {
        let ctx = context(HashMap::from([(
            "GH_TOKEN".to_string(),
            ENV_TOKEN.to_string(),
        )]));
        let provider =
            DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(token));
        let signer = Signer::new(ctx, provider, RequestSigner);
        let original = stale_request();
        let mut parts = original.clone();

        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("an invalid prepended credential must not fall back");

        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
    }
    Ok(())
}

#[tokio::test]
async fn malformed_env_token_is_not_silently_replaced() -> Result<()> {
    let ctx = context(HashMap::from([
        ("GH_TOKEN".to_string(), "🚀🚀🚀🚀".to_string()),
        ("GITHUB_TOKEN".to_string(), "good-token".to_string()),
    ]));
    let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
    let original = stale_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("GH_TOKEN takes precedence and is malformed");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn default_chain_falls_back_to_anonymous_and_no_anonymous_removes_it() -> Result<()> {
    let parts = sign_parts(DefaultCredentialProvider::new(), Context::new(), request()).await?;
    assert!(!parts.headers.contains_key(AUTHORIZATION));

    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_gh_cli()
        .no_anonymous()
        .build();
    let signer = Signer::new(Context::new(), provider, RequestSigner);
    let original = stale_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an empty chain must not produce a credential");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn removed_slots_are_not_reenabled_during_build() -> Result<()> {
    let envs = HashMap::from([("GH_TOKEN".to_string(), ENV_TOKEN.to_string())]);

    let command = MockCommandExecute::sequence([user_result("cli-user"), token_result(CLI_TOKEN)]);
    let provider = DefaultCredentialProvider::builder().no_env().build();
    let parts = sign_parts(
        provider,
        context_with_command(envs.clone(), command),
        request(),
    )
    .await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {CLI_TOKEN}")
    );

    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_gh_cli()
        .build();
    let parts = sign_parts(provider, context(envs.clone()), request()).await?;
    assert!(!parts.headers.contains_key(AUTHORIZATION));

    let provider = DefaultCredentialProvider::builder().no_anonymous().build();
    let parts = sign_parts(provider, context(envs.clone()), request()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {ENV_TOKEN}")
    );

    let provider = DefaultCredentialProvider::builder()
        .env(EnvCredentialProvider::new())
        .gh_cli(GhCliCredentialProvider::new())
        .anonymous(AnonymousCredentialProvider::new())
        .build();
    let parts = sign_parts(provider, context(envs), request()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {ENV_TOKEN}")
    );
    Ok(())
}

#[tokio::test]
async fn push_front_and_with_chain_override_default_sources() -> Result<()> {
    let ctx = context(HashMap::from([(
        "GH_TOKEN".to_string(),
        ENV_TOKEN.to_string(),
    )]));

    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new("front-token"));
    let parts = sign_parts(provider, ctx.clone(), request()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        "Bearer front-token"
    );

    let chain = ProvideCredentialChain::new().push(StaticCredentialProvider::new("chain-token"));
    let provider = DefaultCredentialProvider::with_chain(chain);
    let parts = sign_parts(provider, ctx, request()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        "Bearer chain-token"
    );
    Ok(())
}

#[derive(Debug)]
struct FailingProvider {
    calls: Arc<AtomicUsize>,
}

impl ProvideCredential for FailingProvider {
    type Credential = Credential;

    async fn provide_credential(&self, _ctx: &Context) -> Result<Option<Self::Credential>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(Error::config_invalid("injected provider failure"))
    }
}

#[tokio::test]
async fn with_chain_keeps_the_caller_chain_error_contract() -> Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let chain = ProvideCredentialChain::new()
        .push(FailingProvider {
            calls: calls.clone(),
        })
        .push(AnonymousCredentialProvider::new());
    let provider = DefaultCredentialProvider::with_chain(chain);

    let parts = sign_parts(provider, Context::new(), request()).await?;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!parts.headers.contains_key(AUTHORIZATION));
    Ok(())
}

#[tokio::test]
async fn credential_validation_rejects_non_ascii_and_debug_is_safe() -> Result<()> {
    let credential = Credential::new(STATIC_TOKEN)?;
    assert_eq!(credential.token(), Some(STATIC_TOKEN));
    assert!(!credential.is_anonymous());
    assert!(!format!("{credential:?}").contains(STATIC_TOKEN));

    let anonymous = Credential::anonymous();
    assert!(anonymous.is_anonymous());
    assert_eq!(anonymous.token(), None);
    assert_eq!(anonymous.bearer_header_value()?, None);

    let error = Credential::new("").expect_err("empty token must fail");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

    for token in ["🚀🚀🚀🚀", "token\u{7f}", "token with spaces"] {
        let error = Credential::new(token).expect_err("invalid token must fail");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(!format!("{error:?}").contains(token));
    }

    let provider = StaticCredentialProvider::new(STATIC_TOKEN);
    assert!(!format!("{provider:?}").contains(STATIC_TOKEN));

    let provider = StaticCredentialProvider::new("🚀🚀🚀🚀");
    assert!(!format!("{provider:?}").contains("🚀"));
    let error = provider
        .provide_credential(&Context::new())
        .await
        .expect_err("invalid static token must fail");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(!format!("{error:?}").contains("🚀"));
    Ok(())
}
