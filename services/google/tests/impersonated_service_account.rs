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

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Method, Request, Response, header};
use reqsign_core::{
    CommandExecute, CommandOutput, Context, Error, ErrorKind, FileRead, HttpSend,
    ProvideCredential, Result, StaticEnv,
};
use reqsign_google::{Credential, FileCredentialProvider};
use serde_json::{Value, json};

const ADC_PATH: &str = "/adc.json";
const SUBJECT_PATH: &str = "/subject-token";
const EXECUTABLE_OUTPUT_PATH: &str = "/executable-output.json";
const OAUTH_URL: &str = "https://oauth2.googleapis.com/token";
const STS_URL: &str = "https://sts.example.test/v1/token";
const SOURCE_IAM_URL: &str = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/source%40example.test:generateAccessToken";
const TARGET_IAM_URL: &str = "https://iamcredentials.example.test/v1/projects/-/serviceAccounts/target%40example.test:generateAccessToken";
const SOURCE_SCOPE: &str = "https://www.googleapis.com/auth/iam";
const TARGET_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const TARGET_EXPIRATION: &str = "2100-01-01T00:00:00Z";
const DELEGATES: [&str; 2] = [
    "projects/-/serviceAccounts/z-delegate@example.test",
    "projects/-/serviceAccounts/a-delegate@example.test",
];
const AUDIENCE: &str =
    "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/oidc";
const SUBJECT_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

#[derive(Debug)]
enum Call {
    Read(String),
    Command(String),
    Http(Box<Request<Bytes>>),
}

#[derive(Clone, Debug)]
struct MockIo {
    adc: Arc<[u8]>,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl MockIo {
    fn new(source: Value) -> Self {
        Self {
            adc: impersonation_file(source).to_string().into_bytes().into(),
            calls: Arc::default(),
        }
    }

    fn context(&self) -> Context {
        common::test_context()
            .with_file_read(self.clone())
            .with_http_send(self.clone())
            .with_command_execute(self.clone())
    }
}

impl FileRead for MockIo {
    async fn file_read(&self, path: &str) -> Result<Vec<u8>> {
        self.calls.lock().unwrap().push(Call::Read(path.to_owned()));
        match path {
            ADC_PATH => Ok(self.adc.to_vec()),
            SUBJECT_PATH => Ok(b"subject-from-file\n".to_vec()),
            EXECUTABLE_OUTPUT_PATH => Err(Error::unexpected("no cached executable response")),
            _ => panic!("unexpected file read: {path}"),
        }
    }
}

impl CommandExecute for MockIo {
    async fn command_execute(&self, _program: &str, args: &[&str]) -> Result<CommandOutput> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Command(args.last().unwrap().to_string()));
        Ok(CommandOutput {
            status: 0,
            stdout: json!({
                "version": 1,
                "success": true,
                "token_type": SUBJECT_TYPE,
                "id_token": "subject-from-command",
                "expiration_time": 4_102_444_800_i64,
            })
            .to_string()
            .into_bytes(),
            stderr: Vec::new(),
        })
    }
}

impl HttpSend for MockIo {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        let body = match request.uri().to_string().as_str() {
            OAUTH_URL => json!({"access_token": "oauth-token", "expires_in": 3600}),
            STS_URL => json!({"access_token": "sts-token", "expires_in": 3600}),
            SOURCE_IAM_URL => {
                json!({"accessToken": "source-token", "expireTime": TARGET_EXPIRATION})
            }
            TARGET_IAM_URL => {
                json!({"accessToken": "target-token", "expireTime": TARGET_EXPIRATION})
            }
            uri => panic!("unexpected HTTP request: {uri}"),
        };
        self.calls
            .lock()
            .unwrap()
            .push(Call::Http(Box::new(request)));
        Ok(Response::new(body.to_string().into()))
    }
}

fn impersonation_file(source: Value) -> Value {
    json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": TARGET_IAM_URL,
        "source_credentials": source,
        "delegates": DELEGATES,
    })
}

fn user_source() -> Value {
    json!({
        "type": "authorized_user",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "refresh_token": "test-refresh-token",
        "token_uri": "https://unused.example.test/token",
    })
}

fn external_source(credential_source: Value) -> Value {
    json!({
        "type": "external_account",
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TYPE,
        "token_url": STS_URL,
        "credential_source": credential_source,
    })
}

async fn load_target(ctx: &Context, provider: FileCredentialProvider) -> Result<()> {
    let Credential {
        service_account,
        token,
        signer_email,
    } = provider
        .provide_credential(ctx)
        .await?
        .expect("target credential");
    assert!(service_account.is_none());
    assert_eq!(signer_email.as_deref(), Some("target@example.test"));
    let token = token.expect("target token");
    assert_eq!(token.access_token, "target-token");
    assert_eq!(token.expires_at, Some(TARGET_EXPIRATION.parse()?));
    Ok(())
}

fn assert_iam_request(request: &Request<Bytes>, uri: &str, bearer: &str, body: Value) {
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri(), uri);
    let authorization = &request.headers()[header::AUTHORIZATION];
    assert_eq!(authorization, &format!("Bearer {bearer}"));
    assert!(authorization.is_sensitive());
    assert_eq!(
        serde_json::from_slice::<Value>(request.body()).unwrap(),
        body
    );
}

fn assert_target_request(request: &Request<Bytes>, bearer: &str) {
    assert_iam_request(
        request,
        TARGET_IAM_URL,
        bearer,
        json!({"scope": [TARGET_SCOPE], "delegates": DELEGATES, "lifetime": "3600s"}),
    );
}

fn assert_sts_request(request: &Request<Bytes>, subject_token: &str) {
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri(), STS_URL);
    let form: HashMap<_, _> = form_urlencoded::parse(request.body()).collect();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(form["scope"], SOURCE_SCOPE);
    assert_eq!(form["audience"], AUDIENCE);
    assert_eq!(form["subject_token"], subject_token);
    assert_eq!(form["subject_token_type"], SUBJECT_TYPE);
}

#[tokio::test]
async fn exchanges_tagged_and_legacy_authorized_users() -> Result<()> {
    let tagged = user_source();
    let mut legacy = tagged.clone();
    legacy.as_object_mut().unwrap().remove("type");

    for source in [tagged, legacy] {
        let io = MockIo::new(source);
        load_target(
            &io.context(),
            FileCredentialProvider::new(ADC_PATH).with_scope(TARGET_SCOPE),
        )
        .await?;
        let calls = io.calls.lock().unwrap();
        let [Call::Read(adc), Call::Http(refresh), Call::Http(target)] = calls.as_slice() else {
            panic!("expected ADC read, OAuth refresh and target IAM call: {calls:?}");
        };
        assert_eq!(adc, ADC_PATH);
        assert_eq!(refresh.uri(), OAUTH_URL);
        assert_eq!(refresh.method(), Method::POST);
        assert_eq!(refresh.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            serde_json::from_slice::<Value>(refresh.body()).unwrap(),
            json!({"grant_type": "refresh_token", "client_id": "test-client", "client_secret": "test-secret", "refresh_token": "test-refresh-token"}),
        );
        assert_target_request(target, "oauth-token");
    }
    Ok(())
}

#[tokio::test]
async fn exchanges_service_account_assertion_with_iam_scope() -> Result<()> {
    let io = MockIo::new(json!({
        "type": "service_account",
        "client_email": "source@example.test",
        "private_key": include_str!("fixtures/rsa_pkcs8.pem"),
        "token_uri": "https://unused.example.test/token",
    }));
    let context = io.context().with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([("GOOGLE_SCOPE".into(), TARGET_SCOPE.into())]),
    });
    load_target(&context, FileCredentialProvider::new(ADC_PATH)).await?;

    let calls = io.calls.lock().unwrap();
    let [Call::Read(adc), Call::Http(oauth), Call::Http(target)] = calls.as_slice() else {
        panic!("expected ADC read, JWT bearer exchange and target IAM call: {calls:?}");
    };
    assert_eq!(adc, ADC_PATH);
    assert_eq!(oauth.uri(), OAUTH_URL);
    assert_eq!(oauth.method(), Method::POST);
    assert_eq!(
        oauth.headers()[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    let form: HashMap<_, _> = form_urlencoded::parse(oauth.body()).collect();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let claims = URL_SAFE_NO_PAD
        .decode(form["assertion"].split('.').nth(1).unwrap())
        .unwrap();
    let claims: Value = serde_json::from_slice(&claims).unwrap();
    assert_eq!(claims["aud"], OAUTH_URL);
    assert_eq!(claims["iss"], "source@example.test");
    assert_eq!(claims["scope"], SOURCE_SCOPE);
    assert_target_request(target, "oauth-token");
    Ok(())
}

#[tokio::test]
async fn exchanges_external_account_file_sources_with_iam_scope() -> Result<()> {
    for impersonate_source in [false, true] {
        let mut source = external_source(json!({"file": SUBJECT_PATH}));
        if impersonate_source {
            source["service_account_impersonation_url"] = SOURCE_IAM_URL.into();
            source["service_account_impersonation"] = json!({"token_lifetime_seconds": 600});
        }
        let io = MockIo::new(source);
        load_target(
            &io.context(),
            FileCredentialProvider::new(ADC_PATH).with_scope(TARGET_SCOPE),
        )
        .await?;

        let calls = io.calls.lock().unwrap();
        let [
            Call::Read(adc),
            Call::Read(subject),
            Call::Http(sts),
            iam @ ..,
        ] = calls.as_slice()
        else {
            panic!("expected ADC and subject reads followed by STS: {calls:?}");
        };
        assert_eq!(adc, ADC_PATH);
        assert_eq!(subject, SUBJECT_PATH);
        assert_sts_request(sts, "subject-from-file");
        match (impersonate_source, iam) {
            (false, [Call::Http(target)]) => assert_target_request(target, "sts-token"),
            (true, [Call::Http(source), Call::Http(target)]) => {
                assert_iam_request(
                    source,
                    SOURCE_IAM_URL,
                    "sts-token",
                    json!({"scope": [SOURCE_SCOPE], "lifetime": "600s"}),
                );
                assert_target_request(target, "source-token");
            }
            _ => panic!("unexpected IAM exchanges: {iam:?}"),
        }
    }
    Ok(())
}

#[tokio::test]
async fn rejects_nested_impersonation_before_source_io() {
    // The type tag wins even when the object also has legacy OAuth fields.
    let mut nested = user_source();
    nested["type"] = "impersonated_service_account".into();
    nested["service_account_impersonation_url"] = SOURCE_IAM_URL.into();
    nested["source_credentials"] = user_source();
    let io = MockIo::new(nested);
    let error = FileCredentialProvider::new(ADC_PATH)
        .provide_credential(&io.context())
        .await
        .expect_err("nested impersonation must be rejected");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(error.to_string().contains("delegates"));
    assert!(matches!(io.calls.lock().unwrap().as_slice(), [Call::Read(path)] if path == ADC_PATH));
}

#[tokio::test]
async fn requires_explicit_opt_in_for_executable_external_account_sources() -> Result<()> {
    let io = MockIo::new(external_source(json!({"executable": {
        "command": "fetch-test-subject",
        "output_file": EXECUTABLE_OUTPUT_PATH,
    }})));
    let provider = FileCredentialProvider::new(ADC_PATH).with_scope(TARGET_SCOPE);
    let allow_executables = "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES";
    let context = io.context();
    let error = provider
        .provide_credential(&context)
        .await
        .expect_err("executable source must be disabled by default");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(error.to_string().contains(allow_executables));
    assert!(matches!(io.calls.lock().unwrap().as_slice(), [Call::Read(path)] if path == ADC_PATH));
    io.calls.lock().unwrap().clear();

    let context = context.with_env(StaticEnv {
        home_dir: None,
        envs: HashMap::from([(allow_executables.into(), "1".into())]),
    });
    load_target(&context, provider).await?;
    let calls = io.calls.lock().unwrap();
    let [
        Call::Read(adc),
        Call::Read(cache),
        Call::Command(command),
        Call::Http(sts),
        Call::Http(target),
    ] = calls.as_slice()
    else {
        panic!("expected ADC read, cache lookup, command and token exchanges: {calls:?}");
    };
    assert_eq!(adc, ADC_PATH);
    assert_eq!(cache, EXECUTABLE_OUTPUT_PATH);
    assert!(command.ends_with("fetch-test-subject"));
    assert_sts_request(sts, "subject-from-command");
    assert_target_request(target, "sts-token");
    Ok(())
}
