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
use reqsign_core::{ErrorKind, FileRead, HttpSend, StaticEnv};
use serde_json::json;
use sha1::{Digest, Sha1};
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
        let digest = Sha1::digest(session.as_bytes());
        self.put(
            &format!("{home}/.aws/sso/cache/{}.json", hex::encode(digest)),
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
    let http = Arc::new(Http::default());
    let ctx = Context::new()
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
                "[profile operator]\nrole_arn = {OPERATOR_ROLE}\ncredential_source = Environment\nregion = {REGION}\n"
            ),
            "credential_source",
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
    let ctx = Context::new()
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
