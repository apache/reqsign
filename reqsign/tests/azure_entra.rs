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

#![cfg(feature = "azure")]

use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, header};
use reqsign::azure::{
    Credential, DefaultCredentialProvider, ImdsCredentialProvider, RequestSigner, default_signer,
};
use reqsign::{Context, ErrorKind, HttpSend, ProvideCredential, SignRequest, Signer, StaticEnv};

const ARM_SCOPE: &str = "https://management.core.windows.net//.default";
const ARM_REQUEST: &str = "https://management.azure.com/subscriptions/a%2Fb?tag=one&tag=%2f";
const METADATA_ENDPOINT: &str = "http://metadata.example.test/metadata/identity/oauth2/token";

#[derive(Debug)]
struct ManagedIdentity;

impl HttpSend for ManagedIdentity {
    async fn http_send(&self, request: Request<Bytes>) -> reqsign::Result<Response<Bytes>> {
        assert_eq!(request.method(), Method::GET);
        assert_eq!(
            request.uri(),
            concat!(
                "http://metadata.example.test/metadata/identity/oauth2/token",
                "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.core.windows.net%2F",
            ),
        );
        assert_eq!(request.headers()["Metadata"], "true");
        Ok(Response::new(Bytes::from_static(
            br#"{"access_token":"arm-access-token","expires_on":"4102444800"}"#,
        )))
    }
}

#[tokio::test]
async fn scoped_default_chain_signs_only_a_bearer_header_for_arm() -> anyhow::Result<()> {
    let context = Context::new()
        .with_env(StaticEnv {
            envs: [
                (
                    "AZURE_STORAGE_ACCOUNT_NAME".into(),
                    "storage-account".into(),
                ),
                (
                    "AZURE_STORAGE_ACCOUNT_KEY".into(),
                    "test-account-key".into(),
                ),
                (
                    "AZURE_STORAGE_BEARER_TOKEN".into(),
                    "test-storage-token".into(),
                ),
            ]
            .into(),
            ..Default::default()
        })
        .with_http_send(ManagedIdentity);
    let disabled = DefaultCredentialProvider::builder()
        .no_env()
        .no_imds()
        .with_scope(ARM_SCOPE)?
        .build();
    assert!(disabled.provide_credential(&context).await?.is_none());

    let provider = DefaultCredentialProvider::builder()
        .no_env()
        .imds(ImdsCredentialProvider::new().with_endpoint(METADATA_ENDPOINT))
        .with_scope(ARM_SCOPE)?
        .build();
    let signer = Signer::new(context, provider, RequestSigner::bearer());
    let mut request = Request::get(ARM_REQUEST)
        .header(header::AUTHORIZATION, "Bearer previous-token")
        .header(header::IF_MATCH, "test-etag")
        .body(())?
        .into_parts()
        .0;
    let mut expected_headers = request.headers.clone();
    expected_headers.remove(header::AUTHORIZATION);

    signer.sign(&mut request, None).await?;

    assert_eq!(request.uri, ARM_REQUEST);
    let authorization = request.headers.remove(header::AUTHORIZATION).unwrap();
    assert_eq!(authorization, "Bearer arm-access-token");
    assert!(authorization.is_sensitive());
    assert_eq!(request.headers, expected_headers);
    Ok(())
}

#[tokio::test]
async fn default_storage_bearer_signing_adds_the_storage_date() -> anyhow::Result<()> {
    let context = Context::new().with_env(StaticEnv {
        envs: [(
            "AZURE_STORAGE_BEARER_TOKEN".into(),
            "test-storage-token".into(),
        )]
        .into(),
        ..Default::default()
    });
    let signer = default_signer(context);
    let mut request = Request::get("https://account.blob.core.windows.net/container/blob")
        .body(())?
        .into_parts()
        .0;
    signer.sign(&mut request, None).await?;
    assert!(request.headers.contains_key("x-ms-date"));
    assert_eq!(
        request.headers[header::AUTHORIZATION],
        "Bearer test-storage-token"
    );
    Ok(())
}

#[tokio::test]
async fn generic_bearer_rejects_other_credentials_and_presigning_without_changing_the_request() {
    let signer = RequestSigner::bearer();
    let context = Context::new();
    for (credential, expires_in, kind) in [
        (None, None, ErrorKind::CredentialInvalid),
        (
            Some(Credential::with_shared_key("account", "test-key")),
            None,
            ErrorKind::CredentialInvalid,
        ),
        (
            Some(Credential::with_sas_token("sig=test-sas")),
            None,
            ErrorKind::CredentialInvalid,
        ),
        (
            Some(Credential::with_bearer_token("test-token", None)),
            Some(Duration::from_secs(60)),
            ErrorKind::RequestInvalid,
        ),
    ] {
        let mut request = Request::get(ARM_REQUEST)
            .header(header::AUTHORIZATION, "Bearer previous-token")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let original_headers = request.headers.clone();
        let error = signer
            .sign_request(&context, &mut request, credential.as_ref(), expires_in)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(request.uri, ARM_REQUEST);
        assert_eq!(request.headers, original_headers);
    }
}
