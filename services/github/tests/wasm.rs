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

/// A command adapter that explicitly reports the command as unavailable, like
/// the no-op adapter and the WASM `TokioCommandExecute`.
#[derive(Debug)]
struct UnavailableCommandExecute;

impl CommandExecute for UnavailableCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Err(Error::command_unavailable(
            "fabricated unavailable command adapter",
        ))
    }
}

/// A command adapter that fails with a raw `NotFound` I/O source. That is an
/// adapter failure, not the typed command-unavailable marker.
#[derive(Debug)]
struct RawNotFoundCommandExecute;

impl CommandExecute for RawNotFoundCommandExecute {
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

/// A command adapter that reports the missing-account diagnostic with the
/// wrong exit status.
#[derive(Debug)]
struct WrongStatusMissingAccountCommandExecute;

impl CommandExecute for WrongStatusMissingAccountCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Ok(CommandOutput {
            status: 2,
            stdout: Vec::new(),
            stderr: b"could not find key \"user\"\n".to_vec(),
        })
    }
}

/// A command adapter that returns one fixed output for every call.
#[derive(Debug)]
struct FixedOutputCommandExecute(CommandOutput);

impl CommandExecute for FixedOutputCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Ok(self.0.clone())
    }
}

/// A command adapter that returns a fixed sequence of outputs.
#[derive(Debug)]
struct SequenceCommandExecute {
    outputs: std::sync::Mutex<std::collections::VecDeque<CommandOutput>>,
}

impl SequenceCommandExecute {
    fn new(outputs: impl IntoIterator<Item = CommandOutput>) -> Self {
        Self {
            outputs: std::sync::Mutex::new(outputs.into_iter().collect()),
        }
    }
}

impl CommandExecute for SequenceCommandExecute {
    async fn command_execute(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput> {
        Ok(self
            .outputs
            .lock()
            .expect("output lock")
            .pop_front()
            .expect("mock output must exist"))
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
async fn command_unavailable_falls_back_to_anonymous() {
    for ctx in [
        // The real no-op executor on a bare context.
        Context::new(),
        // A custom executor that explicitly reports the command as unavailable.
        Context::new().with_command_execute(UnavailableCommandExecute),
        // The real WASM Tokio executor reports the command as unavailable.
        Context::new().with_command_execute(reqsign_command_execute_tokio::TokioCommandExecute),
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
async fn unknown_adapter_failures_do_not_fall_back_to_anonymous() {
    for ctx in [
        Context::new().with_command_execute(RawNotFoundCommandExecute),
        Context::new().with_command_execute(FailingCommandExecute),
    ] {
        let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
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
            .expect_err("an unmarked execution failure must not become anonymous access");

        assert_eq!(error.kind(), reqsign_core::ErrorKind::Unexpected);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer stale-wasm-github-token"
        );
    }
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

#[wasm_bindgen_test]
async fn supported_account_names_sign_with_the_stored_token() {
    // Ordinary logins keep their mixed case and legacy forms, and managed
    // names append the enterprise shortcode; the setup user form fits the same
    // shape.
    for name in [
        "The-Octocat",
        "A-",
        "john--doe",
        "mona-cat_octo",
        "The-Octocat_octo",
        "octo_admin",
    ] {
        let command = SequenceCommandExecute::new([
            CommandOutput {
                status: 0,
                stdout: format!("{name}\n").into_bytes(),
                stderr: Vec::new(),
            },
            CommandOutput {
                status: 0,
                stdout: b"wasm-cli-token\n".to_vec(),
                stderr: Vec::new(),
            },
        ]);
        let signer = Signer::new(
            Context::new().with_command_execute(command),
            DefaultCredentialProvider::new(),
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
            .unwrap_or_else(|error| panic!("name {name} must reach the token query: {error}"));

        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer wasm-cli-token",
            "name {name}"
        );
        assert!(parts.headers[http::header::AUTHORIZATION].is_sensitive());
    }
}

#[wasm_bindgen_test]
async fn unconfirmed_or_invalid_account_responses_do_not_fall_back() {
    let contexts = [
        Context::new().with_command_execute(WrongStatusMissingAccountCommandExecute),
        Context::new().with_command_execute(FixedOutputCommandExecute(CommandOutput {
            status: 0,
            stdout: b"...\n".to_vec(),
            stderr: Vec::new(),
        })),
        Context::new().with_command_execute(FixedOutputCommandExecute(CommandOutput {
            status: 0,
            stdout: b"The--Octocat_octo\n".to_vec(),
            stderr: Vec::new(),
        })),
        Context::new().with_command_execute(FixedOutputCommandExecute(CommandOutput {
            status: 0,
            stdout: b"mona-cat_oc\n".to_vec(),
            stderr: Vec::new(),
        })),
    ];

    for ctx in contexts {
        let signer = Signer::new(ctx, DefaultCredentialProvider::new(), RequestSigner);
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
            .expect_err("an unconfirmed account response must not become anonymous access");

        assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);
        assert_eq!(
            parts.headers[http::header::AUTHORIZATION],
            "Bearer stale-wasm-github-token"
        );
    }
}
