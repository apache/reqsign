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

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use reqsign_azure_storage::{
    Credential, DefaultCredentialProvider, ImdsCredentialProvider, StaticCredentialProvider,
};
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, ErrorKind, HttpSend, ProvideCredential, ProvideCredentialChain, Result,
    StaticEnv,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const APP_ENDPOINT: &str = "http://modern.example/msi%2Ftoken?fixed=a%2Fb";
const LEGACY_ENDPOINT: &str = "http://legacy.example/token";
const APP_HEADER: &str = "mock-app-identity-header";
const LEGACY_SECRET: &str = "mock-legacy-identity-secret";
const OVERRIDE_SECRET: &str = "mock-override-identity-secret";
const ACCESS_TOKEN: &str = "mock-managed-identity-token";
const STORAGE_QUERY: &str = "resource=https%3A%2F%2Fstorage.azure.com%2F";
const TOKEN_BODY: &str =
    r#"{"access_token":"mock-managed-identity-token","expires_on":"2524608000"}"#;

const APP_ENV: &[(&str, &str)] = &[
    ("IDENTITY_ENDPOINT", APP_ENDPOINT),
    ("IDENTITY_HEADER", APP_HEADER),
];
const LEGACY_ENV: &[(&str, &str)] = &[
    ("MSI_ENDPOINT", LEGACY_ENDPOINT),
    ("MSI_SECRET", LEGACY_SECRET),
];

type CapturedRequests = Arc<Mutex<Vec<Request<Bytes>>>>;

#[derive(Debug)]
struct MockHttpSend {
    requests: CapturedRequests,
    response: Mutex<Option<Result<Response<Bytes>>>>,
}

impl HttpSend for MockHttpSend {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        self.requests.lock().unwrap().push(request);
        self.response
            .lock()
            .unwrap()
            .take()
            .expect("one token request expected")
    }
}

fn mock_context(
    env: &[(&str, &str)],
    response: Result<Response<Bytes>>,
) -> (Context, CapturedRequests) {
    let requests = CapturedRequests::default();
    let context = Context::new()
        .with_env(StaticEnv {
            home_dir: None,
            envs: env
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        })
        .with_http_send(MockHttpSend {
            requests: requests.clone(),
            response: Mutex::new(Some(response)),
        });
    (context, requests)
}

fn token_response(body: impl Into<Bytes>) -> Result<Response<Bytes>> {
    Ok(Response::new(body.into()))
}

fn assert_token(credential: Option<Credential>, expiry: &str) {
    let Some(Credential::BearerToken { token, expires_in }) = credential else {
        panic!("expected a managed identity bearer credential");
    };
    assert_eq!(token, ACCESS_TOKEN);
    assert_eq!(expires_in, Some(expiry.parse::<Timestamp>().unwrap()));
}

fn assert_request(requests: &CapturedRequests, uri: &str, headers: &[(&str, &str)]) {
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method(), Method::GET);
    assert!(request.body().is_empty());
    assert_eq!(request.uri().to_string(), uri);
    assert_eq!(request.headers().len(), headers.len());
    for &(name, expected) in headers {
        let actual = &request.headers()[name];
        assert_eq!(actual.as_bytes(), expected.as_bytes(), "header {name}");
        assert_eq!(actual.is_sensitive(), name != "metadata", "header {name}");
    }
}

#[tokio::test]
async fn modern_protocol_wins_and_selects_one_identity_for_the_configured_resource() {
    let provider = DefaultCredentialProvider::builder()
        .imds(ImdsCredentialProvider::new().with_resource("api://test+audience/"))
        .build();
    let cases: &[(&[(&str, &str)], &str)] = &[
        (
            &[
                ("AZURE_OBJECT_ID", "object-id"),
                ("AZURE_CLIENT_ID", "client-id"),
                ("AZURE_MSI_RESOURCE_ID", "/identity"),
            ],
            "object_id=object-id",
        ),
        (
            &[
                ("AZURE_CLIENT_ID", "client-id"),
                ("AZURE_MSI_RESOURCE_ID", "/identity"),
            ],
            "client_id=client-id",
        ),
        (
            &[
                ("AZURE_MSI_RESOURCE_ID", "/identity"),
                ("AZURE_MSI_RES_ID", "/ignored"),
            ],
            "mi_res_id=%2Fidentity",
        ),
    ];
    for &(selectors, expected_selector) in cases {
        let mut env = [
            APP_ENV,
            LEGACY_ENV,
            &[("AZURE_MSI_SECRET", OVERRIDE_SECRET)],
        ]
        .concat();
        env.extend_from_slice(selectors);
        let (context, requests) = mock_context(&env, token_response(TOKEN_BODY));
        let credential = provider.provide_credential(&context).await.unwrap();
        assert_token(credential, "2050-01-01T00:00:00Z");
        assert_request(
            &requests,
            &format!(
                "{APP_ENDPOINT}&api-version=2019-08-01&resource=api%3A%2F%2Ftest%2Baudience%2F&{expected_selector}"
            ),
            &[("x-identity-header", APP_HEADER)],
        );
    }
}

#[tokio::test]
async fn legacy_protocol_uses_clientid_and_accepts_epoch_and_utc_dates() {
    let provider = ImdsCredentialProvider::new().with_resource("https://management.azure.com/");
    let env = [
        LEGACY_ENV,
        &[
            ("AZURE_CLIENT_ID", "legacy-client"),
            ("AZURE_MSI_SECRET", OVERRIDE_SECRET),
        ],
    ]
    .concat();
    let cases = [
        (serde_json::json!(2524608000_i64), "2050-01-01T00:00:00Z"),
        (
            serde_json::json!("1/2/2050 18:24:12 +00:00"),
            "2050-01-02T18:24:12Z",
        ),
        (
            serde_json::json!("1/2/2050 12:24:12 AM +00:00"),
            "2050-01-02T00:24:12Z",
        ),
        (
            serde_json::json!("1/2/2050 5:24:12 PM +00:00"),
            "2050-01-02T17:24:12Z",
        ),
        (
            serde_json::json!("01/02/2050 00:00:00 PM +00:00"),
            "2050-01-02T12:00:00Z",
        ),
    ];
    for (wire_expiry, expiry) in cases {
        let body = serde_json::json!({"access_token": ACCESS_TOKEN, "expires_on": wire_expiry})
            .to_string();
        let (context, requests) = mock_context(&env, token_response(body));
        assert_token(provider.provide_credential(&context).await.unwrap(), expiry);
        assert_request(
            &requests,
            &format!(
                "{LEGACY_ENDPOINT}?api-version=2017-09-01&resource=https%3A%2F%2Fmanagement.azure.com%2F&clientid=legacy-client"
            ),
            &[("secret", LEGACY_SECRET)],
        );
    }
}

#[tokio::test]
async fn explicit_and_environment_overrides_keep_the_vm_protocol() {
    let provider = ImdsCredentialProvider::new();
    let env = [
        APP_ENV,
        LEGACY_ENV,
        &[
            ("AZURE_IMDS_ENDPOINT", "http://override.example/azure"),
            ("AZURE_MSI_SECRET", OVERRIDE_SECRET),
            ("AZURE_MSI_RES_ID", "/vm-alias"),
        ],
    ]
    .concat();
    let cases = [
        (
            provider
                .clone()
                .with_endpoint("http://override.example/explicit?"),
            &[("AZBLOB_ENDPOINT", "http://override.example/azblob")][..],
            "explicit",
        ),
        (
            provider.clone(),
            &[("AZBLOB_ENDPOINT", "http://override.example/azblob")][..],
            "azblob",
        ),
        (provider, &[][..], "azure"),
    ];
    for (provider, overrides, path) in cases {
        let env = [env.as_slice(), overrides].concat();
        let body = include_str!("fixtures/imds_token_response.json");
        let (context, requests) = mock_context(&env, token_response(body));
        assert_token(
            provider.provide_credential(&context).await.unwrap(),
            "2050-01-01T00:00:00Z",
        );
        assert_request(
            &requests,
            &format!(
                "http://override.example/{path}?api-version=2018-02-01&{STORAGE_QUERY}&msi_res_id=%2Fvm-alias"
            ),
            &[("metadata", "true"), ("x-identity-header", OVERRIDE_SECRET)],
        );
    }
}

#[tokio::test]
async fn vm_fallback_has_no_secret_and_retains_empty_expiry_compatibility() {
    let body = r#"{"access_token":"mock-managed-identity-token","expires_on":""}"#;
    let (context, requests) = mock_context(
        &[("AZURE_MSI_SECRET", OVERRIDE_SECRET)],
        token_response(body),
    );
    let before = Timestamp::now();
    let credential = ImdsCredentialProvider::new()
        .provide_credential(&context)
        .await
        .unwrap();
    let Some(Credential::BearerToken {
        expires_in: Some(expiry),
        ..
    }) = credential
    else {
        panic!("expected a managed identity bearer credential with expiration");
    };
    assert!(expiry >= before + Duration::from_secs(600));
    assert!(expiry <= Timestamp::now() + Duration::from_secs(600));
    assert_request(
        &requests,
        &format!(
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&{STORAGE_QUERY}"
        ),
        &[("metadata", "true")],
    );
}

#[tokio::test]
async fn incomplete_pairs_and_invalid_configuration_fail_before_http() {
    let cases: &[(&[(&str, &str)], &str)] = &[
        (
            &[
                ("IDENTITY_ENDPOINT", APP_ENDPOINT),
                ("MSI_SECRET", LEGACY_SECRET),
            ],
            "IDENTITY_HEADER",
        ),
        (
            &[
                ("IDENTITY_HEADER", APP_HEADER),
                ("MSI_ENDPOINT", LEGACY_ENDPOINT),
                ("MSI_SECRET", LEGACY_SECRET),
            ],
            "IDENTITY_ENDPOINT",
        ),
        (
            &[("MSI_ENDPOINT", LEGACY_ENDPOINT), ("MSI_SECRET", "")],
            "MSI_SECRET",
        ),
        (&[("MSI_SECRET", LEGACY_SECRET)], "MSI_ENDPOINT"),
        (
            &[
                ("IDENTITY_ENDPOINT", APP_ENDPOINT),
                ("IDENTITY_HEADER", "mock-app-identity-header\ninvalid"),
            ],
            "IDENTITY_HEADER",
        ),
        (
            &[("MSI_ENDPOINT", LEGACY_ENDPOINT), ("MSI_SECRET", " \t ")],
            "MSI_SECRET",
        ),
        (
            &[
                ("IDENTITY_ENDPOINT", "/relative"),
                ("IDENTITY_HEADER", APP_HEADER),
            ],
            "endpoint URL",
        ),
        (
            &[
                (
                    "IDENTITY_ENDPOINT",
                    "http://modern.example/token?res%6furce=wrong",
                ),
                ("IDENTITY_HEADER", APP_HEADER),
            ],
            "reserved query parameter",
        ),
        (
            &[
                ("IDENTITY_ENDPOINT", APP_ENDPOINT),
                ("IDENTITY_HEADER", APP_HEADER),
                ("IDENTITY_SERVER_THUMBPRINT", "mock-thumbprint"),
            ],
            "Service Fabric",
        ),
        (
            &[
                ("MSI_ENDPOINT", LEGACY_ENDPOINT),
                ("MSI_SECRET", LEGACY_SECRET),
                ("AZURE_OBJECT_ID", "unsupported-object"),
            ],
            "AZURE_CLIENT_ID",
        ),
        (
            &[
                ("MSI_ENDPOINT", LEGACY_ENDPOINT),
                ("MSI_SECRET", LEGACY_SECRET),
                ("AZURE_MSI_RESOURCE_ID", "/unsupported-identity"),
            ],
            "AZURE_CLIENT_ID",
        ),
    ];
    for &(env, message) in cases {
        let (context, requests) = mock_context(env, token_response(TOKEN_BODY));
        let err = ImdsCredentialProvider::new()
            .provide_credential(&context)
            .await
            .unwrap_err();
        assert_redacted_error(&err, ErrorKind::ConfigInvalid, message);
        assert!(requests.lock().unwrap().is_empty());
    }

    let (context, requests) = mock_context(APP_ENV, token_response(TOKEN_BODY));
    let err = ImdsCredentialProvider::new()
        .with_resource(" ")
        .provide_credential(&context)
        .await
        .unwrap_err();
    assert_redacted_error(&err, ErrorKind::ConfigInvalid, "resource is empty");
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn selected_endpoint_errors_are_redacted_without_retrying_another_protocol() {
    let env = [APP_ENV, LEGACY_ENV].concat();
    let cases = [
        (
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Bytes::from_static(APP_HEADER.as_bytes()))
                .unwrap()),
            ErrorKind::CredentialInvalid,
            "http_status: 400",
            false,
        ),
        (
            token_response(
                r#"{"access_token":"mock-managed-identity-token","expires_on":{"invalid":"mock-app-identity-header"}}"#,
            ),
            ErrorKind::Unexpected,
            "failed to parse",
            false,
        ),
        (
            token_response(
                r#"{"access_token":"mock-managed-identity-token","expires_on":"mock-app-identity-header"}"#,
            ),
            ErrorKind::Unexpected,
            "expires_on",
            false,
        ),
        (
            Err(Error::permission_denied(APP_HEADER)
                .with_source(anyhow::anyhow!(ACCESS_TOKEN))
                .set_retryable(true)),
            ErrorKind::PermissionDenied,
            "failed to send",
            true,
        ),
    ];
    for (response, kind, message, retryable) in cases {
        let (context, requests) = mock_context(&env, response);
        let err = ImdsCredentialProvider::new()
            .provide_credential(&context)
            .await
            .unwrap_err();
        assert_redacted_error(&err, kind, message);
        assert_eq!(err.is_retryable(), retryable);
        assert_request(
            &requests,
            &format!("{APP_ENDPOINT}&api-version=2019-08-01&{STORAGE_QUERY}"),
            &[("x-identity-header", APP_HEADER)],
        );
    }
}

fn assert_redacted_error(err: &Error, kind: ErrorKind, message: &str) {
    assert_eq!(err.kind(), kind);
    let rendered = format!("{err}\n{err:?}");
    assert!(rendered.contains(message), "{rendered}");
    for secret in [APP_HEADER, LEGACY_SECRET, OVERRIDE_SECRET, ACCESS_TOKEN] {
        assert!(!rendered.contains(secret));
    }
}

#[tokio::test]
async fn no_imds_removes_every_managed_identity_source() {
    let provider = DefaultCredentialProvider::builder().no_imds().build();
    for env in [APP_ENV, LEGACY_ENV, &[]] {
        let (context, requests) = mock_context(env, token_response(TOKEN_BODY));
        assert!(
            provider
                .provide_credential(&context)
                .await
                .unwrap()
                .is_none()
        );
        assert!(requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn default_and_generic_chains_continue_after_a_managed_identity_error() {
    let (context, requests) = mock_context(
        &[("IDENTITY_HEADER", APP_HEADER)],
        token_response(TOKEN_BODY),
    );
    assert!(
        DefaultCredentialProvider::new()
            .provide_credential(&context)
            .await
            .unwrap()
            .is_none()
    );

    let chain = ProvideCredentialChain::new()
        .push(ImdsCredentialProvider::new())
        .push(StaticCredentialProvider::new_shared_key(
            "mock-storage-account",
            "mock-storage-key",
        ));
    assert!(
        matches!(chain.provide_credential(&context).await.unwrap(), Some(Credential::SharedKey { account_name, .. }) if account_name == "mock-storage-account")
    );
    assert!(requests.lock().unwrap().is_empty());
}
