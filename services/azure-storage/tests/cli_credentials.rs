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

use reqsign_azure_storage::{
    AzureCliCredentialProvider, AzureDeveloperCliCredentialProvider, Credential,
    DefaultCredentialProvider,
};
use reqsign_core::time::Timestamp;
use reqsign_core::{
    CommandExecute, CommandOutput, Context, ErrorKind, ProvideCredential, StaticEnv,
};

const AZ_ARGS: &[&str] = &[
    "account",
    "get-access-token",
    "--resource",
    "https://storage.azure.com/",
    "--output",
    "json",
];
const AZD_ARGS: &[&str] = &[
    "auth",
    "token",
    "--scope",
    "https://storage.azure.com/.default",
    "--output",
    "json",
    "--no-prompt",
];
const TOKEN: &str = "example-cli-token";
const EXPIRY_SECONDS: i64 = 1_893_456_000;
const AZ_RESPONSE: &[u8] = br#"{
    "accessToken": "example-cli-token",
    "expires_on": 1893456000,
    "expiresOn": "2029-12-31 19:00:00.000000",
    "tokenType": "Bearer"
}"#;

#[derive(Debug)]
struct MockCommand {
    program: &'static str,
    args: Vec<&'static str>,
    output: CommandOutput,
}

impl CommandExecute for MockCommand {
    async fn command_execute(
        &self,
        program: &str,
        args: &[&str],
    ) -> reqsign_core::Result<CommandOutput> {
        assert_eq!(program, self.program);
        assert_eq!(args, self.args);
        Ok(self.output.clone())
    }
}

fn command_context(program: &'static str, args: &[&'static str], stdout: &[u8]) -> Context {
    Context::new().with_command_execute(MockCommand {
        program,
        args: args.to_vec(),
        output: CommandOutput {
            status: 0,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        },
    })
}

fn assert_bearer_token(credential: Option<Credential>) {
    let Some(Credential::BearerToken { token, expires_in }) = credential else {
        panic!("expected a bearer token");
    };
    assert_eq!(token, TOKEN);
    assert_eq!(
        expires_in,
        Some(Timestamp::from_second(EXPIRY_SECONDS).unwrap())
    );
}

#[tokio::test]
async fn azure_cli_public_slot_keeps_the_storage_argv_and_prefers_epoch_expiry() {
    let ctx = command_context("az", AZ_ARGS, AZ_RESPONSE);
    let provider = DefaultCredentialProvider::builder()
        .azure_cli(AzureCliCredentialProvider {})
        .build();
    assert_bearer_token(provider.provide_credential(&ctx).await.unwrap());

    let provider = DefaultCredentialProvider::builder()
        .azure_cli(Default::default())
        .no_azure_cli()
        .no_imds()
        .build();
    assert!(provider.provide_credential(&ctx).await.unwrap().is_none());
}

#[tokio::test]
async fn azure_cli_uses_the_context_tenant_and_accepts_legacy_expiry() {
    let args = [AZ_ARGS, &["--tenant", "context-tenant"]].concat();
    let ctx = command_context(
        "az",
        &args,
        br#"{
            "accessToken": "example-cli-token",
            "expiresOn": "2030-01-01 00:00:00.000000",
            "tokenType": "Bearer"
        }"#,
    )
    .with_env(StaticEnv {
        envs: [("AZURE_TENANT_ID".into(), "context-tenant".into())].into(),
        ..Default::default()
    });
    assert_bearer_token(
        AzureCliCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn azure_cli_uses_one_token_target_and_prefers_the_explicit_tenant() {
    const RESOURCE: &str = "https://vault.azure.net";
    const SCOPE: &str = "https://management.core.windows.net//.default";
    let cases = [
        (
            AzureCliCredentialProvider::new()
                .with_resource(RESOURCE)
                .with_scope(SCOPE),
            "--scope",
            SCOPE,
            "context-tenant",
        ),
        (
            AzureCliCredentialProvider::new()
                .with_tenant_id("explicit-tenant")
                .with_scope(SCOPE)
                .with_resource(RESOURCE),
            "--resource",
            RESOURCE,
            "explicit-tenant",
        ),
    ];
    for (provider, flag, target, tenant) in cases {
        let ctx = command_context(
            "az",
            &[
                "account",
                "get-access-token",
                flag,
                target,
                "--output",
                "json",
                "--tenant",
                tenant,
            ],
            AZ_RESPONSE,
        )
        .with_env(StaticEnv {
            envs: [("AZURE_TENANT_ID".into(), "context-tenant".into())].into(),
            ..Default::default()
        });
        assert_bearer_token(provider.provide_credential(&ctx).await.unwrap());
    }
}

#[tokio::test]
async fn azure_cli_rejects_blank_resource_before_the_cli_can_default_to_arm() {
    let error = AzureCliCredentialProvider::new()
        .with_resource("")
        .provide_credential(&Context::new())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(error.to_string().contains("--resource"));
}

#[tokio::test]
async fn azure_developer_cli_requests_a_scope_without_prompting_and_preserves_expiry() {
    let ctx = command_context(
        "azd",
        AZD_ARGS,
        br#"{"token":"example-cli-token","expiresOn":"2030-01-01T00:00:00Z"}"#,
    );
    assert_bearer_token(
        AzureDeveloperCliCredentialProvider::new()
            .provide_credential(&ctx)
            .await
            .unwrap(),
    );

    const SCOPE: &str = "https://vault.azure.net/.default";
    let ctx = command_context(
        "azd",
        &[
            "auth",
            "token",
            "--scope",
            SCOPE,
            "--output",
            "json",
            "--no-prompt",
        ],
        br#"{"token":"example-cli-token","expiresOn":"2030-01-01T05:30:00+05:30"}"#,
    );
    let provider = AzureDeveloperCliCredentialProvider::new().with_scope(SCOPE);
    assert_bearer_token(provider.provide_credential(&ctx).await.unwrap());
}

#[tokio::test]
async fn azure_developer_cli_rejects_failed_or_malformed_output_without_leaking_it() {
    let cases: &[(i32, &[u8], ErrorKind, &str)] = &[
        (
            1,
            b"example-cli-token",
            ErrorKind::CredentialInvalid,
            "exit status: 1",
        ),
        (
            0,
            br#"{"token":"example-cli-token"}"#,
            ErrorKind::Unexpected,
            "failed to parse azd token output",
        ),
        (
            0,
            br#"{"token":"example-cli-token","expiresOn":"example-cli-token"}"#,
            ErrorKind::Unexpected,
            "invalid expiresOn timestamp",
        ),
        (
            0,
            br#"{"token":"","expiresOn":"2030-01-01T00:00:00Z"}"#,
            ErrorKind::CredentialInvalid,
            "empty token",
        ),
    ];
    let provider = AzureDeveloperCliCredentialProvider::new();
    for &(status, stdout, kind, message) in cases {
        let ctx = Context::new().with_command_execute(MockCommand {
            program: "azd",
            args: AZD_ARGS.to_vec(),
            output: CommandOutput {
                status,
                stdout: stdout.to_vec(),
                stderr: TOKEN.as_bytes().to_vec(),
            },
        });
        let error = provider.provide_credential(&ctx).await.unwrap_err();
        assert_eq!(error.kind(), kind);
        let diagnostic = format!("{error:?}");
        assert!(diagnostic.contains(message), "{diagnostic}");
        assert!(!diagnostic.contains(TOKEN));
    }

    let error = provider
        .provide_credential(&Context::new())
        .await
        .unwrap_err();
    assert!(error.is_command_unavailable());
}
