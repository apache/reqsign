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

#![cfg(feature = "yandex-disk")]

use reqsign::yandex_disk::{
    DefaultSigner, RequestSigner, StaticCredentialProvider, default_signer,
};
use reqsign::{Context, ErrorKind, Result, Signer};

const TOKEN: &str = "fake-dpfk-zhwmp-gmmr-mhwjj-S8";
const OVERRIDE_TOKEN: &str = "fake-dpfk-zhwmp-gmmr-mhwjj-T9";

fn request() -> http::request::Parts {
    http::Request::get(
        "https://cloud-api.yandex.net/v1/disk/resources?path=disk%3A%2Ffolder%2Ffile",
    )
    .header(http::header::ACCEPT, "application/json")
    .body(())
    .expect("request must build")
    .into_parts()
    .0
}

#[tokio::test]
async fn facade_default_signer_uses_the_explicit_token() -> Result<()> {
    let signer: DefaultSigner = default_signer(Context::new(), TOKEN);
    let original = request();
    let mut parts = original.clone();

    signer.sign(&mut parts, None).await?;

    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(
        authorization.to_str().expect("Authorization must be text"),
        format!("OAuth {TOKEN}")
    );
    assert!(authorization.is_sensitive());
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers[http::header::ACCEPT], "application/json");

    Ok(())
}

#[tokio::test]
async fn facade_default_signer_can_be_reconfigured_with_a_provider() -> Result<()> {
    let signer = default_signer(Context::new(), TOKEN)
        .with_credential_provider(StaticCredentialProvider::new(OVERRIDE_TOKEN));
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        format!("OAuth {OVERRIDE_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn facade_default_signer_rejects_an_invalid_token_without_mutating_the_request() -> Result<()>
{
    let signer = default_signer(Context::new(), "fake-dpfk-invalid-\u{00e9}");
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an invalid explicit token must fail");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn facade_request_signer_is_an_ordinary_signer_component() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(TOKEN),
        RequestSigner,
    );
    let mut parts = request();

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[http::header::AUTHORIZATION],
        format!("OAuth {TOKEN}")
    );

    Ok(())
}
