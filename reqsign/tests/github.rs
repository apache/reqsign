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

#![cfg(feature = "github")]

use reqsign::github::{
    AnonymousCredentialProvider, DefaultCredentialProvider, GhCliCredentialProvider,
    StaticCredentialProvider,
};
use reqsign::{CommandExecute, CommandOutput, Context, Error, ErrorKind, Result, StaticEnv};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Clone)]
enum MockCommandResult {
    Output(CommandOutput),
    AdapterError(String),
    RawNotFoundSource,
    CommandUnavailable(String),
}

#[derive(Clone)]
struct MockCommandExecute {
    results: Arc<StdMutex<VecDeque<MockCommandResult>>>,
}

impl std::fmt::Debug for MockCommandExecute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockCommandExecute").finish_non_exhaustive()
    }
}

impl MockCommandExecute {
    fn sequence(results: impl IntoIterator<Item = MockCommandResult>) -> Self {
        Self {
            results: Arc::new(StdMutex::new(results.into_iter().collect())),
        }
    }
}

impl CommandExecute for MockCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        match self
            .results
            .lock()
            .expect("result lock")
            .pop_front()
            .expect("mock result must exist")
        {
            MockCommandResult::Output(output) => Ok(output),
            MockCommandResult::AdapterError(message) => Err(Error::unexpected(message)),
            MockCommandResult::RawNotFoundSource => Err(Error::unexpected(
                "fabricated command execution failure",
            )
            .with_source(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "SENTINEL_FACADE_IO_SOURCE",
            ))),
            MockCommandResult::CommandUnavailable(message) => {
                Err(Error::command_unavailable(message))
            }
        }
    }
}

fn context(envs: HashMap<String, String>) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs,
    })
}

fn request() -> http::request::Parts {
    http::Request::get("https://api.github.com/repos/apache/reqsign")
        .header(http::header::USER_AGENT, "opendal-test")
        .body(())
        .expect("request must build")
        .into_parts()
        .0
}

fn stale_request() -> http::request::Parts {
    let mut parts = request();
    parts.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer stale-facade-token"),
    );
    parts
}

#[tokio::test]
async fn facade_default_signer_reads_gh_token() -> Result<()> {
    let signer = reqsign::github::default_signer(context(HashMap::from([(
        "GH_TOKEN".to_string(),
        "facade-env-token".to_string(),
    )])));
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer facade-env-token"
    );
    assert!(parts.headers[http::header::AUTHORIZATION].is_sensitive());
    Ok(())
}

#[tokio::test]
async fn facade_static_override_replaces_stale_authorization() -> Result<()> {
    let signer = reqsign::github::default_signer(context(HashMap::new()))
        .with_credential_provider(StaticCredentialProvider::new("facade-static-token"));
    let mut parts = stale_request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer facade-static-token"
    );
    assert_eq!(parts.headers[http::header::USER_AGENT], "opendal-test");
    Ok(())
}

#[tokio::test]
async fn facade_anonymous_signing_removes_stale_authorization() -> Result<()> {
    let original = stale_request();
    let signer = reqsign::github::default_signer(context(HashMap::new()));
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

    assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers[http::header::USER_AGENT], "opendal-test");

    let _ = AnonymousCredentialProvider::new();
    let _ = GhCliCredentialProvider::new();
    Ok(())
}

#[tokio::test]
async fn facade_default_signer_rejects_malformed_cli_output() -> Result<()> {
    let command = MockCommandExecute::sequence([
        MockCommandResult::Output(CommandOutput {
            status: 0,
            stdout: b"facade-cli-user\n".to_vec(),
            stderr: Vec::new(),
        }),
        MockCommandResult::Output(CommandOutput {
            status: 0,
            stdout: b"first\nsecond".to_vec(),
            stderr: Vec::new(),
        }),
    ]);
    let signer =
        reqsign::github::default_signer(context(HashMap::new()).with_command_execute(command));
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
async fn facade_invalid_static_override_does_not_fall_back() -> Result<()> {
    let signer = reqsign::github::default_signer(context(HashMap::from([(
        "GH_TOKEN".to_string(),
        "facade-env-token".to_string(),
    )])))
    .with_credential_provider(StaticCredentialProvider::new(""));
    let original = stale_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an invalid explicit credential must not fall back");

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

#[tokio::test]
async fn facade_no_anonymous_fails_without_mutating_the_request() -> Result<()> {
    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_gh_cli()
        .no_anonymous()
        .build();
    let signer =
        reqsign::github::default_signer(context(HashMap::new())).with_credential_provider(provider);
    let original = stale_request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("no_anonymous must remove the fallback");

    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    Ok(())
}

fn output(
    status: i32,
    stdout: impl Into<Vec<u8>>,
    stderr: impl Into<Vec<u8>>,
) -> MockCommandResult {
    MockCommandResult::Output(CommandOutput {
        status,
        stdout: stdout.into(),
        stderr: stderr.into(),
    })
}

fn cli_user() -> MockCommandResult {
    output(0, b"cli-user\n", Vec::new())
}

fn cli_token() -> MockCommandResult {
    output(0, b"cli-token\n", Vec::new())
}

#[tokio::test]
async fn facade_command_unavailable_falls_back_to_anonymous() -> Result<()> {
    let command = MockCommandExecute::sequence([MockCommandResult::CommandUnavailable(
        "fabricated unavailable command executor".to_string(),
    )]);
    let signer =
        reqsign::github::default_signer(context(HashMap::new()).with_command_execute(command));
    let original = stale_request();
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

    assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
    assert_eq!(parts.uri, original.uri);
    Ok(())
}

#[tokio::test]
async fn facade_unknown_adapter_failures_do_not_fall_back_or_cache_anonymous() -> Result<()> {
    let failures = [
        // An arbitrary adapter failure is not an absent account.
        MockCommandResult::AdapterError("SENTINEL_FACADE_ADAPTER".to_string()),
        // A raw or nested `NotFound` source from a custom adapter is
        // ambiguous, not the typed command-unavailable marker.
        MockCommandResult::RawNotFoundSource,
    ];

    for failure in failures {
        let command = MockCommandExecute::sequence([failure, cli_user(), cli_token()]);
        let signer =
            reqsign::github::default_signer(context(HashMap::new()).with_command_execute(command));
        let original = stale_request();

        let mut parts = original.clone();
        let error = signer
            .sign(&mut parts, None)
            .await
            .expect_err("an unmarked adapter failure must not become anonymous access");
        assert_eq!(error.kind(), ErrorKind::Unexpected);
        assert!(!error.to_string().contains("SENTINEL"));
        assert!(!format!("{error:?}").contains("SENTINEL"));
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer stale-facade-token"
        );

        // The failed sign must not install or cache an anonymous credential:
        // a retry consults the provider again and uses the stored token.
        let mut retry = original.clone();
        signer.sign(&mut retry, None).await?;
        assert_eq!(
            retry.headers[http::header::AUTHORIZATION],
            "Bearer cli-token"
        );
        assert_eq!(retry.uri, original.uri);
    }
    Ok(())
}

#[tokio::test]
async fn facade_token_stage_unavailable_fails_and_retries_without_anonymous() -> Result<()> {
    let command = MockCommandExecute::sequence([
        cli_user(),
        MockCommandResult::CommandUnavailable("fabricated token-stage unavailable".to_string()),
        cli_user(),
        cli_token(),
    ]);
    let signer =
        reqsign::github::default_signer(context(HashMap::new()).with_command_execute(command));
    let original = stale_request();

    let mut parts = original.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("a token-stage unavailable command must not become anonymous access");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer stale-facade-token"
    );

    // The failed token read must not install or cache an anonymous credential.
    let mut retry = original.clone();
    signer.sign(&mut retry, None).await?;
    assert_eq!(
        retry.headers[http::header::AUTHORIZATION],
        "Bearer cli-token"
    );
    assert_eq!(retry.uri, original.uri);
    Ok(())
}
