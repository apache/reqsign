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

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, Request, Response, header};
use reqsign_azure_storage::{
    AzurePipelinesCredentialProvider, ClientSecretCredentialProvider, Credential,
    DefaultCredentialProvider, WorkloadIdentityCredentialProvider,
};
use reqsign_core::{Context, ErrorKind, HttpSend, ProvideCredential, StaticEnv};

const ARM_SCOPE: &str = "https://management.core.windows.net//.default";
const PUBLIC_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token";
const US_TOKEN_ENDPOINT: &str = "https://login.microsoftonline.us/tenant/oauth2/v2.0/token";
const CHINA_TOKEN_ENDPOINT: &str = "https://login.chinacloudapi.cn/tenant/oauth2/v2.0/token";
const PIPELINES_OIDC_ENDPOINT: &str =
    "https://pipelines.example.test/oidc?api-version=7.1&serviceConnectionId=connection";
const STORAGE_SCOPE: &str = "https://storage.azure.com/.default";

#[derive(Clone, Debug, Default)]
struct CaptureRequests(Arc<Mutex<Vec<Request<Bytes>>>>);

impl HttpSend for CaptureRequests {
    async fn http_send(&self, request: Request<Bytes>) -> reqsign_core::Result<Response<Bytes>> {
        let body = if request.uri() == PIPELINES_OIDC_ENDPOINT {
            br#"{"oidcToken":"issuer.opaque+assertion/="}"#.as_slice()
        } else {
            br#"{"access_token":"test-access-token","expires_in":3600}"#.as_slice()
        };
        self.0.lock().unwrap().push(request);
        Ok(Response::new(Bytes::from_static(body)))
    }
}

async fn capture_token_requests(
    provider: impl ProvideCredential<Credential = Credential>,
    env: &[(&str, &str)],
) -> Vec<Request<Bytes>> {
    let requests = CaptureRequests::default();
    let context = Context::new()
        .with_env(StaticEnv {
            envs: env
                .iter()
                .map(|&(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            ..Default::default()
        })
        .with_http_send(requests.clone());
    let credential = provider.provide_credential(&context).await.unwrap();
    assert!(matches!(
        credential,
        Some(Credential::BearerToken { token, expires_in: Some(_) }) if token == "test-access-token"
    ));
    std::mem::take(&mut *requests.0.lock().unwrap())
}

fn assert_form_request(request: &Request<Bytes>, endpoint: &str) {
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri(), endpoint);
    assert_eq!(
        request.headers()[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
}

#[tokio::test]
async fn client_secret_preserves_storage_form_bytes_and_accepts_an_explicit_target() {
    let provider = ClientSecretCredentialProvider::new()
        .with_tenant_id("tenant")
        .with_client_id("client")
        .with_client_secret("test+secret");
    let cases = [
        (
            provider.clone(),
            &[][..],
            PUBLIC_TOKEN_ENDPOINT,
            "scope=https%3A%2F%2Fstorage.azure.com%2F.default&client_id=client&client_secret=test%2Bsecret&grant_type=client_credentials",
        ),
        (
            provider
                .with_scope(ARM_SCOPE)
                .with_authority_host("https://login.microsoftonline.us/"),
            &[("AZURE_AUTHORITY_HOST", "https://login.chinacloudapi.cn")][..],
            US_TOKEN_ENDPOINT,
            "scope=https%3A%2F%2Fmanagement.core.windows.net%2F%2F.default&client_id=client&client_secret=test%2Bsecret&grant_type=client_credentials",
        ),
    ];
    for (provider, env, endpoint, body) in cases {
        let requests = capture_token_requests(provider, env).await;
        let [request] = requests.as_slice() else {
            panic!("expected one token request");
        };
        assert_form_request(request, endpoint);
        assert_eq!(request.body().as_ref(), body.as_bytes());
    }
}

#[tokio::test]
async fn workload_scope_preserves_provider_configuration_and_later_replacement_wins() {
    const APP_SCOPE: &str = "api://application/.default";
    let workload = WorkloadIdentityCredentialProvider::new()
        .with_tenant_id("tenant")
        .with_client_id("configured-client")
        .with_subject_token("workload.subject+token/")
        .with_authority_host("https://login.microsoftonline.us/")
        .with_scope(APP_SCOPE);
    let cases = [
        (
            DefaultCredentialProvider::builder()
                .workload_identity(workload.clone())
                .with_scope(ARM_SCOPE)
                .unwrap()
                .build(),
            ARM_SCOPE,
        ),
        (
            DefaultCredentialProvider::builder()
                .with_scope(ARM_SCOPE)
                .unwrap()
                .workload_identity(workload)
                .build(),
            APP_SCOPE,
        ),
    ];
    for (provider, scope) in cases {
        let requests = capture_token_requests(provider, &[]).await;
        let [request] = requests.as_slice() else {
            panic!("expected one token request");
        };
        assert_form_request(request, US_TOKEN_ENDPOINT);
        let fields = form_urlencoded::parse(request.body()).collect::<Vec<_>>();
        assert_eq!(
            fields
                .iter()
                .map(|(k, v)| (k.as_ref(), v.as_ref()))
                .collect::<Vec<_>>(),
            [
                ("scope", scope),
                ("client_id", "configured-client"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
                ("client_assertion", "workload.subject+token/"),
                ("grant_type", "client_credentials"),
            ],
        );
    }
}

#[tokio::test]
async fn pipelines_uses_the_selected_authority_and_preserves_the_issued_oidc_assertion() {
    let builder = || DefaultCredentialProvider::builder().no_imds();
    let mut env = vec![
        ("SYSTEM_ACCESSTOKEN", "test-system-token"),
        (
            "SYSTEM_OIDCREQUESTURI",
            "https://pipelines.example.test/oidc",
        ),
        ("ARM_OIDC_AZURE_SERVICE_CONNECTION_ID", "connection"),
        ("ARM_TENANT_ID", "tenant"),
        ("ARM_CLIENT_ID", "client"),
    ];
    let default = capture_token_requests(builder().build(), &env).await;
    env.push(("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us/"));
    let from_environment =
        capture_token_requests(builder().with_scope(ARM_SCOPE).unwrap().build(), &env).await;
    let explicit = capture_token_requests(
        AzurePipelinesCredentialProvider::new()
            .with_scope(ARM_SCOPE)
            .with_authority_host("https://login.chinacloudapi.cn/"),
        &env,
    )
    .await;

    for (requests, endpoint, scope) in [
        (default, PUBLIC_TOKEN_ENDPOINT, STORAGE_SCOPE),
        (from_environment, US_TOKEN_ENDPOINT, ARM_SCOPE),
        (explicit, CHINA_TOKEN_ENDPOINT, ARM_SCOPE),
    ] {
        let [oidc, exchange] = requests.as_slice() else {
            panic!("expected an OIDC request followed by one token exchange");
        };
        assert_eq!(oidc.method(), Method::POST);
        assert_eq!(oidc.uri(), PIPELINES_OIDC_ENDPOINT);
        assert_eq!(
            oidc.headers()[header::AUTHORIZATION],
            "Bearer test-system-token"
        );
        assert_form_request(exchange, endpoint);
        let mut fields = form_urlencoded::parse(exchange.body()).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields
                .iter()
                .map(|(k, v)| (k.as_ref(), v.as_ref()))
                .collect::<Vec<_>>(),
            [
                ("client_assertion", "issuer.opaque+assertion/="),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
                ("client_id", "client"),
                ("grant_type", "client_credentials"),
                ("scope", scope),
            ],
        );
    }
}

#[tokio::test]
async fn rejects_targets_that_are_not_a_single_client_credentials_scope() {
    for scope in [
        "",
        "/.default",
        "https://vault.azure.net",
        "api://a/.default api://b/.default",
    ] {
        let Err(error) = DefaultCredentialProvider::builder().with_scope(scope) else {
            panic!("malformed scope accepted by builder");
        };
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);

        let error = ClientSecretCredentialProvider::new()
            .with_tenant_id("tenant")
            .with_client_id("client")
            .with_client_secret("test-secret")
            .with_scope(scope)
            .provide_credential(&Context::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
}
