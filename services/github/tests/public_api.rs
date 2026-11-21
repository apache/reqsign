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

use reqsign_core::{
    CommandExecute, CommandOutput, Context, Error, ErrorKind, ProvideCredential,
    ProvideCredentialChain, Result, SignRequest, Signer, StaticEnv,
};
use reqsign_github::{
    AnonymousCredentialProvider, Credential, DefaultCredentialProvider, EnvCredentialProvider,
    GhCliCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use std::collections::{HashMap, VecDeque};
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
    fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self::with_result(MockCommandResult::Output(CommandOutput {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }))
    }

    fn failure(status: i32, stdout: impl Into<Vec<u8>>, stderr: impl Into<Vec<u8>>) -> Self {
        Self::with_result(MockCommandResult::Output(CommandOutput {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }))
    }

    fn adapter_error(message: impl Into<String>) -> Self {
        Self::with_result(MockCommandResult::AdapterError(message.into()))
    }

    fn with_result(result: MockCommandResult) -> Self {
        Self {
            calls: Arc::new(StdMutex::new(Vec::new())),
            results: Arc::new(StdMutex::new(VecDeque::from([result]))),
        }
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
        }
    }
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

async fn sign_with(
    provider: impl ProvideCredential<Credential = Credential>,
    ctx: Context,
) -> Result<http::request::Parts> {
    let signer = Signer::new(ctx, provider, RequestSigner);
    let mut parts = request();
    signer.sign(&mut parts, None).await?;
    Ok(parts)
}

#[tokio::test]
async fn static_token_signs_bearer_and_preserves_the_request() -> Result<()> {
    let original = request();
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

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
async fn anonymous_signing_leaves_the_request_unchanged() -> Result<()> {
    let original = request();
    let signer = Signer::new(
        Context::new(),
        AnonymousCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

    assert!(!parts.headers.contains_key(AUTHORIZATION));
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn expires_in_is_rejected_without_mutating_the_request() -> Result<()> {
    let original = request();
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
    let original = request();
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
        let parts = sign_with(DefaultCredentialProvider::new(), context(envs)).await?;
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
async fn gh_cli_discovery_is_host_scoped_and_read_only() -> Result<()> {
    let command = MockCommandExecute::success(format!("{CLI_TOKEN}\n").into_bytes());
    let ctx = context_with_command(HashMap::new(), command.clone());

    let parts = sign_with(DefaultCredentialProvider::new(), ctx).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {CLI_TOKEN}")
    );
    let calls = command.calls();
    assert_eq!(
        calls,
        vec![RecordedCommand {
            program: "gh".to_string(),
            args: ["auth", "token", "--hostname", GITHUB_HOST, "--no-refresh"]
                .map(str::to_string)
                .to_vec(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn gh_cli_unavailable_or_failed_falls_back_to_anonymous() -> Result<()> {
    for command in [
        MockCommandExecute::success(Vec::new()),
        MockCommandExecute::success(b" \n".to_vec()),
        MockCommandExecute::failure(1, Vec::new(), b"SENTINEL_STDERR".to_vec()),
        MockCommandExecute::adapter_error("SENTINEL_ADAPTER"),
    ] {
        let ctx = context_with_command(HashMap::new(), command);
        let parts = sign_with(DefaultCredentialProvider::new(), ctx).await?;
        assert!(!parts.headers.contains_key(AUTHORIZATION));
    }
    Ok(())
}

#[tokio::test]
async fn gh_cli_malformed_output_is_reported_without_leaking_it() {
    let cases = [
        b"first\nsecond".to_vec(),
        b"token with spaces".to_vec(),
        b"nonutf8\xff".to_vec(),
    ];

    for stdout in cases {
        let ctx = context_with_command(HashMap::new(), MockCommandExecute::success(stdout));
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
    }
}

#[tokio::test]
async fn default_chain_falls_back_to_anonymous_and_no_anonymous_removes_it() -> Result<()> {
    let parts = sign_with(DefaultCredentialProvider::new(), Context::new()).await?;
    assert!(!parts.headers.contains_key(AUTHORIZATION));

    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_gh_cli()
        .no_anonymous()
        .build();
    let signer = Signer::new(Context::new(), provider, RequestSigner);
    let original = request();
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
    let ctx = context_with_command(
        HashMap::from([("GH_TOKEN".to_string(), ENV_TOKEN.to_string())]),
        MockCommandExecute::success(format!("{CLI_TOKEN}\n").into_bytes()),
    );

    let provider = DefaultCredentialProvider::builder().no_env().build();
    let parts = sign_with(provider, ctx.clone()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {CLI_TOKEN}")
    );

    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_gh_cli()
        .build();
    let parts = sign_with(provider, ctx.clone()).await?;
    assert!(!parts.headers.contains_key(AUTHORIZATION));

    let provider = DefaultCredentialProvider::builder().no_anonymous().build();
    let parts = sign_with(provider, ctx.clone()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        format!("Bearer {ENV_TOKEN}")
    );

    let provider = DefaultCredentialProvider::builder()
        .env(EnvCredentialProvider::new())
        .gh_cli(GhCliCredentialProvider::new())
        .anonymous(AnonymousCredentialProvider::new())
        .build();
    let parts = sign_with(provider, ctx).await?;
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
    let parts = sign_with(provider, ctx.clone()).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        "Bearer front-token"
    );

    let chain = ProvideCredentialChain::new().push(StaticCredentialProvider::new("chain-token"));
    let provider = DefaultCredentialProvider::with_chain(chain);
    let parts = sign_with(provider, ctx).await?;
    assert_eq!(
        parts.headers[AUTHORIZATION].to_str().expect("header text"),
        "Bearer chain-token"
    );
    Ok(())
}

#[tokio::test]
async fn malformed_env_token_is_not_silently_replaced() -> Result<()> {
    let ctx = context(HashMap::from([
        ("GH_TOKEN".to_string(), "bad token".to_string()),
        ("GITHUB_TOKEN".to_string(), "good-token".to_string()),
    ]));
    let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
    let original = request();
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
async fn debug_and_signing_errors_do_not_leak_tokens() -> Result<()> {
    let credential = Credential::new(STATIC_TOKEN)?;
    assert_eq!(credential.token(), Some(STATIC_TOKEN));
    assert!(!credential.is_anonymous());
    assert!(!format!("{credential:?}").contains(STATIC_TOKEN));

    let anonymous = Credential::anonymous();
    assert!(anonymous.is_anonymous());
    assert_eq!(anonymous.token(), None);
    assert_eq!(anonymous.bearer_header_value()?, None);

    let provider = StaticCredentialProvider::new(STATIC_TOKEN);
    assert!(!format!("{provider:?}").contains(STATIC_TOKEN));

    let credential = Credential::new("bad token with spaces")?;
    let original = request();
    let mut parts = original.clone();
    let error = RequestSigner
        .sign_request(&Context::new(), &mut parts, Some(&credential), None)
        .await
        .expect_err("invalid header characters must fail");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(!format!("{error:?}").contains("bad token with spaces"));
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let error = Credential::new("").expect_err("empty token must fail");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    Ok(())
}
