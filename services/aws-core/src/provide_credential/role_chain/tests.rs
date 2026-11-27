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

use super::*;
use crate::{DefaultCredentialProvider, DefaultCredentialProviderBuilder};
use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use reqsign_core::hash::hex_sha1;
use reqsign_core::{CommandExecute, CommandOutput, ErrorKind, FileRead, HttpSend, StaticEnv};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const REGION: &str = "us-east-1";
const OPERATOR_ROLE: &str = "arn:aws:iam::111122223333:role/Operator";
const INTERMEDIATE_ROLE: &str = "arn:aws:iam::111122223333:role/Intermediate";
const SOURCE_ACCESS_KEY: &str = "ASIASOURCE0000000001";
const INTERMEDIATE_ACCESS_KEY: &str = "ASIAINTERMEDIATE001";
const OPERATOR_ACCESS_KEY: &str = "ASIAOPERATOR0000001";
const SSO_SOURCE_ACCESS_KEY: &str = "ASIASSOSOURCE000001";
const SSO_ACCESS_TOKEN: &str = "cached-sso-access-token";

#[derive(Debug, Default)]
struct Files(Mutex<HashMap<String, Vec<u8>>>);

impl FileRead for Files {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.0
            .lock()
            .expect("lock poisoned")
            .get(path)
            .cloned()
            .ok_or_else(|| Error::unexpected("file not found"))
    }
}

impl Files {
    fn put(&self, path: &str, content: impl Into<Vec<u8>>) {
        self.0
            .lock()
            .expect("lock poisoned")
            .insert(path.to_owned(), content.into());
    }

    fn sso_token(&self, home: &str, session: &str) {
        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let digest = hex_sha1(&provider, session.as_bytes()).expect("SSO cache key must hash");
        self.put(
            &format!("{home}/.aws/sso/cache/{digest}.json"),
            json!({
                "accessToken": SSO_ACCESS_TOKEN,
                "expiresAt": "2099-01-01T00:00:00Z",
            })
            .to_string(),
        );
    }
}

#[derive(Debug, Default)]
struct Http {
    requests: Mutex<Vec<Request<Bytes>>>,
    responses: Mutex<VecDeque<Response<Bytes>>>,
}

impl HttpSend for Http {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        self.requests.lock().expect("lock poisoned").push(request);
        self.responses
            .lock()
            .expect("lock poisoned")
            .pop_front()
            .ok_or_else(|| Error::unexpected("unexpected HTTP request"))
    }
}

impl Http {
    fn reply(&self, response: Response<Bytes>) {
        self.responses
            .lock()
            .expect("lock poisoned")
            .push_back(response);
    }

    fn ok(&self, body: impl Into<Bytes>) {
        self.reply(Response::new(body.into()));
    }

    fn sso_role(&self) {
        self.reply(
            Response::builder()
                .status(StatusCode::OK)
                .body(Bytes::from(
                    json!({
                        "roleCredentials": {
                            "accessKeyId": SSO_SOURCE_ACCESS_KEY,
                            "secretAccessKey": "sso-source-secret",
                            "sessionToken": "sso-source-session-token",
                            "expiration": 2000000000000i64,
                        }
                    })
                    .to_string(),
                ))
                .expect("response must build"),
        );
    }

    fn assumed_role(&self, access_key: &str, token: &str) {
        self.reply(
            Response::builder()
                .status(StatusCode::OK)
                .body(Bytes::from(format!(
                    "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
                     <AccessKeyId>{access_key}</AccessKeyId>\
                     <SecretAccessKey>{access_key}-secret</SecretAccessKey>\
                     <SessionToken>{token}</SessionToken>\
                     <Expiration>2099-11-09T13:34:41Z</Expiration>\
                     </Credentials></AssumeRoleResult></AssumeRoleResponse>"
                )))
                .expect("response must build"),
        );
    }

    fn web_identity_role(&self) {
        self.ok(format!(
            "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>\
             <AccessKeyId>{OPERATOR_ACCESS_KEY}</AccessKeyId>\
             <SecretAccessKey>operator-secret</SecretAccessKey>\
             <SessionToken>operator-token</SessionToken>\
             <Expiration>2099-01-01T00:00:00Z</Expiration>\
             </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
        ));
    }

    fn calls(&self) -> usize {
        self.requests.lock().expect("lock poisoned").len()
    }

    fn requests(&self) -> Vec<Request<Bytes>> {
        self.requests.lock().expect("lock poisoned").clone()
    }
}

fn sso_chain_config() -> String {
    format!(
        "[profile operator]\n\
         role_arn = {OPERATOR_ROLE}\n\
         source_profile = intermediate\n\
         role_session_name = operator-session\n\
         region = {REGION}\n\
         \n\
         [profile intermediate]\n\
         role_arn = {INTERMEDIATE_ROLE}\n\
         source_profile = sso-source\n\
         role_session_name = intermediate-session\n\
         \n\
         [profile sso-source]\n\
         sso_session = example-session\n\
         sso_account_id = 111122223333\n\
         sso_role_name = ExampleAccess\n\
         \n\
         [sso-session example-session]\n\
         sso_start_url = https://example.awsapps.com/start\n\
         sso_region = {REGION}\n"
    )
}

fn single_hop_sso_config() -> String {
    format!(
        "[profile operator]\n\
         role_arn = {OPERATOR_ROLE}\n\
         source_profile = sso-source\n\
         role_session_name = operator-session\n\
         region = {REGION}\n\
         \n\
         [profile sso-source]\n\
         sso_session = example-session\n\
         sso_account_id = 111122223333\n\
         sso_role_name = ExampleAccess\n\
         \n\
         [sso-session example-session]\n\
         sso_start_url = https://example.awsapps.com/start\n\
         sso_region = {REGION}\n\
         \n\
         [profile other]\n\
         aws_access_key_id = ASIAOTHER00000000001\n\
         aws_secret_access_key = other-secret\n\
         region = {REGION}\n"
    )
}

fn single_hop_static_config() -> String {
    format!(
        "[profile operator]\n\
         role_arn = {OPERATOR_ROLE}\n\
         source_profile = static-source\n\
         role_session_name = operator-session\n\
         {AWS_EXTERNAL_ID} = local-tenant\n\
         duration_seconds = 3600\n\
         region = {REGION}\n\
         \n\
         [profile static-source]\n\
         aws_access_key_id = {SOURCE_ACCESS_KEY}\n\
         aws_secret_access_key = source-secret\n"
    )
}

fn fixture(config: &str, envs: HashMap<String, String>) -> (Context, Arc<Http>) {
    let files = Arc::new(Files::default());
    files.put("/config", config.to_owned());
    files.sso_token("/home", "example-session");
    fixture_with_files(files, envs)
}

fn fixture_with_files(files: Arc<Files>, envs: HashMap<String, String>) -> (Context, Arc<Http>) {
    let http = Arc::new(Http::default());
    let ctx = crate::test_context()
        .with_file_read(files)
        .with_http_send(http.clone())
        .with_env(StaticEnv {
            home_dir: Some("/home".into()),
            envs: HashMap::from([
                ("AWS_CONFIG_FILE".to_owned(), "/config".to_owned()),
                (
                    "AWS_SHARED_CREDENTIALS_FILE".to_owned(),
                    "/credentials".to_owned(),
                ),
            ])
            .into_iter()
            .chain(envs)
            .collect(),
        });
    (ctx, http)
}

fn isolated_builder(profile: &str) -> DefaultCredentialProviderBuilder {
    DefaultCredentialProvider::builder()
        .no_env()
        .no_web_identity()
        .no_process()
        .no_ecs()
        .no_imds()
        .with_profile(profile)
}

fn query_value(request: &Request<Bytes>, key: &str) -> String {
    form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("query parameter {key} is missing"))
}

fn authorization_access_key(request: &Request<Bytes>) -> String {
    let authorization = request.headers()[header::AUTHORIZATION]
        .to_str()
        .expect("authorization must be text");
    let credential = authorization
        .split_once("Credential=")
        .expect("credential must be present")
        .1;
    credential
        .split_once('/')
        .expect("credential scope must be present")
        .0
        .to_owned()
}

#[tokio::test]
async fn resolves_explicit_role_profile_through_named_sso_in_order() {
    let (ctx, http) = fixture(&sso_chain_config(), HashMap::new());
    http.sso_role();
    http.assumed_role(INTERMEDIATE_ACCESS_KEY, "intermediate-token");
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

    let credential = isolated_builder("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect("role chain must resolve")
        .expect("role chain must return a credential");

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    assert_eq!(credential.session_token.as_deref(), Some("operator-token"));
    let requests = http.requests();
    assert_eq!(requests.len(), 3);

    assert_eq!(
        requests[0].uri().to_string(),
        format!(
            "https://portal.sso.{REGION}.amazonaws.com/federation/credentials?role_name=ExampleAccess&account_id=111122223333"
        )
    );
    assert_eq!(
        requests[0].headers()["x-amz-sso_bearer_token"],
        SSO_ACCESS_TOKEN
    );

    assert_eq!(query_value(&requests[1], "RoleArn"), INTERMEDIATE_ROLE);
    assert_eq!(
        query_value(&requests[1], "RoleSessionName"),
        "intermediate-session"
    );
    assert_eq!(
        authorization_access_key(&requests[1]),
        SSO_SOURCE_ACCESS_KEY
    );
    assert_eq!(
        requests[1].headers()["x-amz-security-token"],
        "sso-source-session-token"
    );
    assert!(requests[1].headers().get("x-amz-s3session-token").is_none());

    assert_eq!(query_value(&requests[2], "RoleArn"), OPERATOR_ROLE);
    assert_eq!(
        query_value(&requests[2], "RoleSessionName"),
        "operator-session"
    );
    assert_eq!(
        authorization_access_key(&requests[2]),
        INTERMEDIATE_ACCESS_KEY
    );
    assert_eq!(
        requests[2].headers()["x-amz-security-token"],
        "intermediate-token"
    );
}

#[tokio::test]
async fn aws_profile_selects_role_chain_through_default_provider() {
    let (ctx, http) = fixture(
        &single_hop_sso_config(),
        HashMap::from([("AWS_PROFILE".to_owned(), "operator".to_owned())]),
    );
    http.sso_role();
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

    let credential = DefaultCredentialProvider::new()
        .provide_credential(&ctx)
        .await
        .expect("default provider must resolve the selected role profile")
        .expect("default provider must return a credential");

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].headers()["x-amz-sso_bearer_token"],
        SSO_ACCESS_TOKEN
    );
    assert_eq!(query_value(&requests[1], "RoleArn"), OPERATOR_ROLE);
}

#[tokio::test]
async fn explicit_profile_overrides_aws_profile_for_role_chain() {
    let (ctx, http) = fixture(
        &single_hop_sso_config(),
        HashMap::from([("AWS_PROFILE".to_owned(), "other".to_owned())]),
    );
    http.sso_role();
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

    let credential = isolated_builder("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect("explicit profile must resolve")
        .expect("role chain must return a credential");

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(query_value(&requests[1], "RoleArn"), OPERATOR_ROLE);
}

#[tokio::test]
async fn static_source_profile_chains_with_the_source_credential() {
    let (ctx, http) = fixture(&single_hop_static_config(), HashMap::new());
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

    let credential = isolated_builder("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect("static source must resolve")
        .expect("role chain must return a credential");

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(query_value(&requests[0], "RoleArn"), OPERATOR_ROLE);
    assert_eq!(query_value(&requests[0], "ExternalId"), "local-tenant");
    assert_eq!(query_value(&requests[0], "DurationSeconds"), "3600");
    assert_eq!(authorization_access_key(&requests[0]), SOURCE_ACCESS_KEY);
    assert!(requests[0].headers().get("x-amz-security-token").is_none());
}

#[tokio::test]
async fn explicit_environment_role_chain_uses_env_credentials_as_its_source() {
    let config = format!(
        "[profile operator]\nrole_arn = {OPERATOR_ROLE}\nsource_profile = intermediate\nregion = {REGION}\n\
         [profile intermediate]\nrole_arn = {INTERMEDIATE_ROLE}\ncredential_source = Environment\n"
    );
    let mut envs = environment_credentials();
    envs.insert("AWS_PROFILE".into(), "operator".into());
    let (ctx, http) = fixture(&config, envs);

    let ambient = DefaultCredentialProvider::builder()
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ambient.access_key_id, SOURCE_ACCESS_KEY);

    let prepended = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .push_front(crate::StaticCredentialProvider::new(
            "preferred-key",
            "preferred-secret",
        ))
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prepended.access_key_id, "preferred-key");
    assert_eq!(http.calls(), 0);

    http.assumed_role(INTERMEDIATE_ACCESS_KEY, "intermediate-token");
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");
    let credential = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    assert_eq!(credential.session_token.as_deref(), Some("operator-token"));
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(query_value(&requests[0], "RoleArn"), INTERMEDIATE_ROLE);
    assert_eq!(authorization_access_key(&requests[0]), SOURCE_ACCESS_KEY);
    assert_eq!(
        requests[0].headers()["x-amz-security-token"],
        "environment-token"
    );
    assert_eq!(query_value(&requests[1], "RoleArn"), OPERATOR_ROLE);
    assert_eq!(
        authorization_access_key(&requests[1]),
        INTERMEDIATE_ACCESS_KEY
    );
}

fn environment_credentials() -> HashMap<String, String> {
    HashMap::from([
        ("AWS_ACCESS_KEY_ID".into(), SOURCE_ACCESS_KEY.into()),
        ("AWS_SECRET_ACCESS_KEY".into(), "environment-secret".into()),
        ("AWS_SESSION_TOKEN".into(), "environment-token".into()),
    ])
}

#[tokio::test]
async fn explicit_profile_without_an_environment_source_keeps_env_precedence() {
    let (ctx, http) = fixture(&single_hop_static_config(), environment_credentials());
    let credential = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        credential.session_token.as_deref(),
        Some("environment-token")
    );
    assert_eq!(http.calls(), 0);
}

fn operator_config(source_config: &str) -> String {
    format!("[profile operator]\nrole_arn = {OPERATOR_ROLE}\nregion = {REGION}\n{source_config}\n")
}

fn metadata_credentials() -> String {
    json!({
        "Code": "Success",
        "AccessKeyId": SOURCE_ACCESS_KEY,
        "SecretAccessKey": "metadata-source-secret",
        "Token": "metadata-source-token",
        "Expiration": "2099-01-01T00:00:00Z",
    })
    .to_string()
}

fn assert_operator_role_request(request: &Request<Bytes>, token: &str) {
    assert_eq!(query_value(request, "RoleArn"), OPERATOR_ROLE);
    assert_eq!(authorization_access_key(request), SOURCE_ACCESS_KEY);
    assert_eq!(request.headers()["x-amz-security-token"], token);
}

#[tokio::test]
async fn ec2_source_uses_the_configured_imdsv2_slot() {
    let (ctx, http) = fixture(
        &operator_config("credential_source = Ec2InstanceMetadata"),
        HashMap::from([(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT".into(),
            "http://ambient-imds.example.test".into(),
        )]),
    );
    http.ok("imdsv2-token");
    http.ok("instance-profile");
    http.ok(metadata_credentials());
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

    let credential = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .imds(IMDSv2CredentialProvider::new().with_endpoint("http://imds.example.test"))
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    let requests = http.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].method(), http::Method::PUT);
    assert_eq!(
        requests[0].uri(),
        "http://imds.example.test/latest/api/token"
    );
    assert_eq!(
        requests[1].uri().path(),
        "/latest/meta-data/iam/security-credentials/"
    );
    assert_eq!(
        requests[2].uri().path(),
        "/latest/meta-data/iam/security-credentials/instance-profile"
    );
    for request in &requests[1..3] {
        assert_eq!(request.uri().host(), Some("imds.example.test"));
        assert_eq!(
            request.headers()["x-aws-ec2-metadata-token"],
            "imdsv2-token"
        );
    }
    assert_operator_role_request(&requests[3], "metadata-source-token");
}

#[tokio::test]
async fn ec2_source_does_not_downgrade_or_fall_through_by_default() {
    let (ctx, http) = fixture(
        &operator_config("credential_source = Ec2InstanceMetadata"),
        HashMap::from([(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
            "http://fallback-ecs.example.test/credentials".into(),
        )]),
    );
    http.reply(
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Bytes::new())
            .unwrap(),
    );

    let error = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect_err("the selected IMDSv2 failure must be returned");

    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method(), http::Method::PUT);
    assert_eq!(requests[0].uri(), "http://169.254.169.254/latest/api/token");
}

#[tokio::test]
async fn ecs_source_uses_the_configured_container_slot() {
    let (ctx, http) = fixture(
        &operator_config("credential_source = EcsContainer"),
        HashMap::from([(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
            "http://ambient-ecs.example.test/credentials".into(),
        )]),
    );
    http.ok(metadata_credentials());
    http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

    let credential = DefaultCredentialProvider::builder()
        .ecs(
            ECSCredentialProvider::new()
                .with_endpoint("http://ecs.example.test/task")
                .with_auth_token("configured-ecs-token"),
        )
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    let requests = http.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].uri(), "http://ecs.example.test/task");
    assert_eq!(
        requests[0].headers()[header::AUTHORIZATION],
        "configured-ecs-token"
    );
    assert_operator_role_request(&requests[1], "metadata-source-token");
}

#[derive(Debug)]
struct ProcessMock {
    program: &'static str,
    args: &'static [&'static str],
    status: i32,
}

impl CommandExecute for ProcessMock {
    async fn command_execute<'a>(
        &'a self,
        program: &'a str,
        args: &'a [&'a str],
    ) -> Result<CommandOutput> {
        assert_eq!(program, self.program);
        assert_eq!(args, self.args);
        Ok(CommandOutput {
            status: self.status,
            stdout: serde_json::to_vec(&json!({
                "Version": 1,
                "AccessKeyId": SOURCE_ACCESS_KEY,
                "SecretAccessKey": "process-source-secret",
                "SessionToken": "process-source-token",
            }))
            .unwrap(),
            stderr: b"mock diagnostic with a process secret".to_vec(),
        })
    }
}

#[tokio::test]
async fn process_source_uses_the_leaf_config_and_explicit_command_override() {
    let config = operator_config(
        "source_profile = process-source\n\n[profile process-source]\ncredential_process = leaf-helper --tenant \"test account\"",
    );
    for (provider, program) in [
        (ProcessCredentialProvider::new(), "leaf-helper"),
        (
            ProcessCredentialProvider::new()
                .with_command("configured-helper --tenant \"test account\""),
            "configured-helper",
        ),
    ] {
        let files = Arc::new(Files::default());
        files.put("/selected-config", config.as_str());
        files.put(
            "/config",
            "[profile process-source]\ncredential_process = ambient-helper\n",
        );
        let (ctx, http) = fixture_with_files(files, HashMap::new());
        let ctx = ctx.with_command_execute(ProcessMock {
            program,
            args: &["--tenant", "test account"],
            status: 0,
        });
        http.assumed_role(OPERATOR_ACCESS_KEY, "operator-token");

        let credential = DefaultCredentialProvider::builder()
            .with_profile("replaced")
            .profile(
                ProfileCredentialProvider::new()
                    .with_profile("operator")
                    .with_config_file("/selected-config"),
            )
            .process(provider)
            .build()
            .provide_credential(&ctx)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_operator_role_request(&requests[0], "process-source-token");
    }
}

#[tokio::test]
async fn process_source_failure_returns_status_without_command_output() {
    let config = operator_config(
        "source_profile = process-source\n[profile process-source]\ncredential_process = leaf-helper",
    );
    let (ctx, http) = fixture(&config, HashMap::new());
    let ctx = ctx.with_command_execute(ProcessMock {
        program: "leaf-helper",
        args: &[],
        status: 7,
    });
    let error = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect_err("a failed source process must stop the selected role chain");
    assert_eq!(error.kind(), ErrorKind::Unexpected);
    assert!(error.to_string().contains("failed with status 7"));
    assert!(!format!("{error:?}").contains("mock diagnostic with a process secret"));
    assert_eq!(http.calls(), 0);
}

#[tokio::test]
async fn removed_source_slots_fail_selected_roles_before_io() {
    let builder = DefaultCredentialProvider::builder;
    let cases = [
        (
            builder().no_env(),
            "credential_source = Environment",
            "env",
            environment_credentials(),
        ),
        (
            builder().no_imds(),
            "credential_source = Ec2InstanceMetadata",
            "imds",
            HashMap::new(),
        ),
        (
            builder().no_ecs(),
            "credential_source = EcsContainer",
            "ecs",
            HashMap::from([(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                "http://ecs.example.test/task".into(),
            )]),
        ),
        (
            builder().no_process(),
            "source_profile = process-source\n\n[profile process-source]\ncredential_process = leaf-helper",
            "process",
            HashMap::new(),
        ),
        (
            builder().no_web_identity(),
            "web_identity_token_file = /subject-token",
            "web_identity",
            HashMap::new(),
        ),
    ];

    for (builder, source_config, slot, envs) in cases {
        let (ctx, http) = fixture(&operator_config(source_config), envs);
        let error = builder
            .with_profile("operator")
            .build()
            .provide_credential(&ctx)
            .await
            .expect_err("a selected role cannot use a removed source");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert!(
            error
                .to_string()
                .contains(&format!("{slot} provider is disabled")),
            "{error}"
        );
        assert_eq!(http.calls(), 0, "{slot} must fail before HTTP");
    }
}

#[tokio::test]
async fn conflicting_environment_source_profile_does_not_return_raw_env_credentials() {
    let (ctx, http) = fixture(
        &operator_config("credential_source = Environment\nsource_profile = other"),
        environment_credentials(),
    );
    let error = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect_err("conflicting selected environment role must fail");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(
        error
            .to_string()
            .contains("both source_profile and credential_source")
    );
    assert_eq!(http.calls(), 0);
}

#[tokio::test]
async fn profile_web_identity_uses_the_selected_config_file_and_sts_settings() {
    let files = Arc::new(Files::default());
    files.put(
        "/selected-config",
        operator_config(
            "web_identity_token_file = /subject-token
role_session_name = operator-session
endpoint_url = https://profile-sts.example.test/prefix",
        ),
    );
    files.put(
        "/config",
        "[profile operator]
endpoint_url = https://wrong-file.example.test
",
    );
    files.put(
        "/subject-token",
        "  profile.subject.token
",
    );
    let (ctx, http) = fixture_with_files(
        files,
        HashMap::from([
            ("AWS_PROFILE".into(), "ambient".into()),
            ("AWS_ROLE_ARN".into(), INTERMEDIATE_ROLE.into()),
        ]),
    );
    http.web_identity_role();

    let credential = DefaultCredentialProvider::builder()
        .profile(ProfileCredentialProvider::new().with_config_file("/selected-config"))
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    assert_eq!(credential.session_token.as_deref(), Some("operator-token"));
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.uri(), "https://profile-sts.example.test/prefix/");
    assert_eq!(request.method(), http::Method::POST);
    assert!(!request.headers().contains_key(header::AUTHORIZATION));
    let form: HashMap<_, _> = form_urlencoded::parse(request.body()).collect();
    assert_eq!(form["Action"], "AssumeRoleWithWebIdentity");
    assert_eq!(form["RoleArn"], OPERATOR_ROLE);
    assert_eq!(form["RoleSessionName"], "operator-session");
    assert_eq!(form["WebIdentityToken"], "profile.subject.token");
}

#[tokio::test]
async fn no_profile_keeps_the_web_identity_slot_and_its_profile_selection() {
    let files = Arc::new(Files::default());
    files.put(
        "/config",
        operator_config("web_identity_token_file = /subject-token"),
    );
    files.put("/subject-token", "profile.subject.token");
    let (ctx, http) = fixture_with_files(
        files,
        HashMap::from([
            ("AWS_PROFILE".into(), "ambient".into()),
            (
                "AWS_ENDPOINT_URL_STS".into(),
                "https://env-sts.example.test".into(),
            ),
        ]),
    );
    http.web_identity_role();

    let credential = DefaultCredentialProvider::builder()
        .no_profile()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(credential.access_key_id, OPERATOR_ACCESS_KEY);
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].uri(), "https://env-sts.example.test/");
    let form: HashMap<_, _> = form_urlencoded::parse(requests[0].body()).collect();
    assert_eq!(form["RoleArn"], OPERATOR_ROLE);
    assert_eq!(form["WebIdentityToken"], "profile.subject.token");
}

#[tokio::test]
async fn selected_web_identity_profile_failure_does_not_fall_through() {
    let config = operator_config(
        "web_identity_token_file = /missing-subject-token
aws_access_key_id = unrelated-key
aws_secret_access_key = unrelated-secret",
    );
    let (ctx, http) = fixture(&config, HashMap::new());
    let error = DefaultCredentialProvider::builder()
        .with_profile("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect_err("the selected role must not fall back after a token file error");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(
        error
            .to_string()
            .contains("failed to read web identity token file")
    );
    assert_eq!(http.calls(), 0);
}

#[tokio::test]
async fn rejects_invalid_role_graphs_before_http() {
    let cases = [
        (
            "missing source profile",
            format!(
                "[profile operator]\nrole_arn = {OPERATOR_ROLE}\nsource_profile = missing\nregion = {REGION}\n"
            ),
            "missing source profile",
        ),
        (
            "cycle",
            format!(
                "[profile operator]\nrole_arn = {OPERATOR_ROLE}\nsource_profile = second\nregion = {REGION}\n\
                 [profile second]\nrole_arn = {INTERMEDIATE_ROLE}\nsource_profile = operator\n"
            ),
            "cycle",
        ),
        (
            "conflicting source_profile and credential_source",
            format!(
                "[profile operator]\nrole_arn = {OPERATOR_ROLE}\nsource_profile = source\ncredential_source = Environment\nregion = {REGION}\n\
                 [profile source]\naws_access_key_id = {SOURCE_ACCESS_KEY}\naws_secret_access_key = source-secret\n"
            ),
            "both source_profile and credential_source",
        ),
        (
            "unsupported credential_source",
            format!(
                "[profile operator]\nrole_arn = {OPERATOR_ROLE}\ncredential_source = UnknownSource\nregion = {REGION}\n"
            ),
            "unsupported credential_source",
        ),
        (
            "missing region",
            format!(
                "[profile operator]\nrole_arn = {OPERATOR_ROLE}\nsource_profile = source\n\
                 [profile source]\naws_access_key_id = {SOURCE_ACCESS_KEY}\naws_secret_access_key = source-secret\n"
            ),
            "requires a region",
        ),
        (
            "invalid role ARN",
            format!(
                "[profile operator]\nrole_arn = not-an-arn\nsource_profile = source\nregion = {REGION}\n\
                 [profile source]\naws_access_key_id = {SOURCE_ACCESS_KEY}\naws_secret_access_key = source-secret\n"
            ),
            "role ARN",
        ),
    ];

    for (name, config, expected) in cases {
        let (ctx, http) = fixture(&config, HashMap::new());
        let error = isolated_builder("operator")
            .build()
            .provide_credential(&ctx)
            .await
            .expect_err(name);
        assert!(
            error.to_string().contains(expected),
            "{name}: unexpected error: {error}"
        );
        assert!(
            matches!(
                error.kind(),
                ErrorKind::ConfigInvalid | ErrorKind::RequestInvalid
            ),
            "{name}: unexpected error kind"
        );
        assert_eq!(http.calls(), 0, "{name} must fail before HTTP");
    }
}

#[tokio::test]
async fn no_sso_disables_the_sso_source_without_fallback() {
    let (ctx, http) = fixture(&single_hop_sso_config(), HashMap::new());
    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .no_sso()
        .no_web_identity()
        .no_process()
        .no_ecs()
        .no_imds()
        .with_profile("operator")
        .build();

    let error = provider
        .provide_credential(&ctx)
        .await
        .expect_err("a role profile that requires SSO must not use a removed slot");
    assert!(
        error
            .to_string()
            .contains("requires SSO, but the SSO provider is disabled")
    );
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(http.calls(), 0);
}

#[tokio::test]
async fn sso_source_failure_is_not_swallowed() {
    let files = Arc::new(Files::default());
    files.put("/config", single_hop_sso_config());
    let http = Arc::new(Http::default());
    // No cached token exists, so the SSO source must fail before STS.
    let ctx = crate::test_context()
        .with_file_read(files)
        .with_http_send(http.clone())
        .with_env(StaticEnv {
            home_dir: Some("/home".into()),
            envs: HashMap::from([
                ("AWS_CONFIG_FILE".to_owned(), "/config".to_owned()),
                (
                    "AWS_SHARED_CREDENTIALS_FILE".to_owned(),
                    "/credentials".to_owned(),
                ),
            ]),
        });

    let error = isolated_builder("operator")
        .build()
        .provide_credential(&ctx)
        .await
        .expect_err("the selected SSO source must not fall back");
    assert!(error.to_string().contains("SSO token cache not found"));
    assert_eq!(http.calls(), 0);
}
