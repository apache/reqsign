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

use bytes::Bytes;
use http::{Request, Response, header};
use reqsign::{Context, Result, azure};
use reqsign_core::{HttpSend, StaticEnv};
use std::collections::HashMap;

#[derive(Debug)]
struct AppServiceEndpoint;

impl HttpSend for AppServiceEndpoint {
    async fn http_send(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        assert_eq!(request.uri().authority().unwrap(), "app.example");
        assert_eq!(request.uri().path(), "/msi/token");
        assert_eq!(
            request.uri().query(),
            Some("api-version=2019-08-01&resource=https%3A%2F%2Fstorage.azure.com%2F")
        );
        assert_eq!(
            request.headers()["x-identity-header"],
            "mock-platform-header"
        );
        Ok(Response::new(Bytes::from_static(
            br#"{"access_token":"mock-storage-token","expires_on":2524608000}"#,
        )))
    }
}

#[tokio::test]
async fn default_azure_signer_uses_managed_identity_from_its_context() -> Result<()> {
    let ctx = Context::new()
        .with_env(StaticEnv {
            home_dir: None,
            envs: HashMap::from([
                (
                    "IDENTITY_ENDPOINT".into(),
                    "http://app.example/msi/token".into(),
                ),
                ("IDENTITY_HEADER".into(), "mock-platform-header".into()),
            ]),
        })
        .with_http_send(AppServiceEndpoint);
    let signer = azure::default_signer(ctx);
    let mut request = Request::get("https://example.blob.core.windows.net/container/object")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    signer.sign(&mut request, None).await?;

    assert_eq!(
        request.headers[header::AUTHORIZATION],
        "Bearer mock-storage-token"
    );
    Ok(())
}
