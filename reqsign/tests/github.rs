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
use reqsign::{CommandExecute, CommandOutput, Context, ErrorKind, Result, StaticEnv};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Clone)]
struct MockCommandExecute {
    results: Arc<StdMutex<VecDeque<CommandOutput>>>,
}

impl std::fmt::Debug for MockCommandExecute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockCommandExecute").finish_non_exhaustive()
    }
}

impl MockCommandExecute {
    fn sequence(results: impl IntoIterator<Item = CommandOutput>) -> Self {
        Self {
            results: Arc::new(StdMutex::new(results.into_iter().collect())),
        }
    }
}

impl CommandExecute for MockCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Ok(self
            .results
            .lock()
            .expect("result lock")
            .pop_front()
            .expect("mock result must exist"))
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
        CommandOutput {
            status: 0,
            stdout: b"facade-cli-user\n".to_vec(),
            stderr: Vec::new(),
        },
        CommandOutput {
            status: 0,
            stdout: b"first\nsecond".to_vec(),
            stderr: Vec::new(),
        },
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
