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

#![cfg(target_arch = "wasm32")]

use reqsign_core::{CommandExecute, CommandOutput, Context, Error, Result, Signer, StaticEnv};
use reqsign_github::{DefaultCredentialProvider, RequestSigner, StaticCredentialProvider};
use std::collections::HashMap;
use wasm_bindgen_test::*;

/// A command adapter that reports no typed I/O cause, like the no-op adapter
/// and the WASM `TokioCommandExecute`.
#[derive(Debug)]
struct UnavailableCommandExecute;

impl CommandExecute for UnavailableCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Err(Error::unexpected("fabricated unavailable command adapter"))
    }
}

/// A command adapter that reports a typed missing executable.
#[derive(Debug)]
struct MissingCommandExecute;

impl CommandExecute for MissingCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Err(
            Error::unexpected("fabricated spawn failure").with_source(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "fabricated",
            )),
        )
    }
}

/// A command adapter that reports a typed execution failure.
#[derive(Debug)]
struct FailingCommandExecute;

impl CommandExecute for FailingCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Err(
            Error::unexpected("fabricated spawn failure").with_source(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fabricated",
            )),
        )
    }
}

/// A command adapter that confirms that no account is stored.
#[derive(Debug)]
struct MissingAccountCommandExecute;

impl CommandExecute for MissingAccountCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Ok(CommandOutput {
            status: 1,
            stdout: Vec::new(),
            stderr: b"could not find key \"user\"\n".to_vec(),
        })
    }
}

/// A command adapter that reports a successful but unusable account lookup.
#[derive(Debug)]
struct MalformedAccountCommandExecute;

impl CommandExecute for MalformedAccountCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Ok(CommandOutput {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}

#[wasm_bindgen_test]
async fn env_token_signs_without_a_clock() {
    let context = Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([("GH_TOKEN".to_string(), "wasm-github-token".to_string())]),
    });
    let signer = Signer::new(context, DefaultCredentialProvider::new(), RequestSigner);
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("GitHub signing must succeed");

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(authorization, "Bearer wasm-github-token");
    assert!(authorization.is_sensitive());
}

#[wasm_bindgen_test]
async fn static_token_signs_without_a_command_adapter() {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new("wasm-static-github-token"),
        RequestSigner,
    );
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("static GitHub signing must succeed");

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer wasm-static-github-token"
    );
}

#[wasm_bindgen_test]
async fn no_token_falls_back_to_anonymous_without_a_command_adapter() {
    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .header(
            http::header::AUTHORIZATION,
            "Bearer stale-wasm-github-token",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("anonymous GitHub signing must succeed");

    assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
}

#[wasm_bindgen_test]
async fn unavailable_or_missing_command_adapter_falls_back_to_anonymous() {
    for ctx in [
        Context::new().with_command_execute(UnavailableCommandExecute),
        Context::new().with_command_execute(MissingCommandExecute),
    ] {
        let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
        let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
            .header(
                http::header::AUTHORIZATION,
                "Bearer stale-wasm-github-token",
            )
            .body(())
            .expect("request must build")
            .into_parts()
            .0;

        signer
            .sign(&mut parts, None)
            .await
            .expect("an unavailable CLI must fall back to anonymous signing");

        assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
    }
}

#[wasm_bindgen_test]
async fn failing_command_adapter_does_not_fall_back_to_anonymous() {
    let signer = Signer::new(
        Context::new().with_command_execute(FailingCommandExecute),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let original = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .header(
            http::header::AUTHORIZATION,
            "Bearer stale-wasm-github-token",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("a typed execution failure must not become anonymous access");

    assert_eq!(error.kind(), reqsign_core::ErrorKind::Unexpected);
    assert_eq!(parts.headers, original.headers);
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer stale-wasm-github-token"
    );
}

#[wasm_bindgen_test]
async fn confirmed_missing_account_falls_back_to_anonymous() {
    let signer = Signer::new(
        Context::new().with_command_execute(MissingAccountCommandExecute),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .header(
            http::header::AUTHORIZATION,
            "Bearer stale-wasm-github-token",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;

    signer
        .sign(&mut parts, None)
        .await
        .expect("a confirmed missing account must reach anonymous signing");

    assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));
}

#[wasm_bindgen_test]
async fn malformed_account_success_does_not_fall_back() {
    let signer = Signer::new(
        Context::new().with_command_execute(MalformedAccountCommandExecute),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let original = http::Request::get("https://api.github.com/repos/apache/reqsign")
        .header(
            http::header::AUTHORIZATION,
            "Bearer stale-wasm-github-token",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an empty successful account lookup must not become anonymous access");

    assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
    assert_eq!(parts.headers, original.headers);
    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        "Bearer stale-wasm-github-token"
    );
}
