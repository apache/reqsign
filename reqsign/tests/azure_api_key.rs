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

use http::{HeaderValue, Request, Version, request::Parts};
use reqsign::azure::api_key::{
    Credential, EnvCredentialProvider, RequestSigner, StaticCredentialProvider,
};
use reqsign::{Context, ErrorKind, ProvideCredential, Result, SignRequest, Signer, StaticEnv};

const URI: &str = "https://azure.example/deployments/a%2Fb?tag=%2f&tag=a+b&empty=";
const KEY_VARIABLE: &str = "EXAMPLE_AZURE_KEY";
const INVALID_KEY: &str = "fake-malformed-key\r\nInjected: header";

fn context(variables: &[(&str, &str)]) -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: None,
        envs: variables
            .iter()
            .map(|&(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
    })
}

fn request(header: &'static str) -> Parts {
    Request::post(URI)
        .version(Version::HTTP_2)
        .header(header, "old-key")
        .header(header, "another-old-key")
        .header("content-type", "application/json")
        .extension("caller extension")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn assert_same_request(actual: &Parts, expected: &Parts) {
    assert_eq!(actual.method, expected.method);
    assert_eq!(actual.version, expected.version);
    assert_eq!(actual.uri.to_string(), expected.uri.to_string());
    assert_eq!(actual.headers, expected.headers);
    assert_eq!(
        actual.extensions.get::<&str>(),
        expected.extensions.get::<&str>()
    );
}

#[tokio::test]
async fn static_key_replaces_only_the_selected_header_and_is_redacted() -> Result<()> {
    const KEY: &str = "zX9-fake-azure-static-key+/_==";
    let provider = StaticCredentialProvider::new(KEY)?;
    let provider_debug = format!("{provider:?}");
    let signer = Signer::new(Context::new(), provider, RequestSigner::api_key());
    let mut parts = request("api-key");
    signer.sign(&mut parts, None).await?;

    let mut expected = request("api-key");
    expected
        .headers
        .insert("api-key", HeaderValue::from_static(KEY));
    assert_same_request(&parts, &expected);
    assert_eq!(parts.headers.get_all("api-key").iter().count(), 1);
    assert!(parts.headers["api-key"].is_sensitive());

    let credential = signer.credential_for(None).await?;
    for debug in [
        provider_debug,
        format!("{credential:?}"),
        format!("{parts:?}"),
    ] {
        assert!(!debug.contains("zX9"));
        assert!(!debug.contains("fake-azure-static-key"));
        assert!(!debug.contains("_=="));
    }
    Ok(())
}

#[tokio::test]
async fn named_environment_keys_sign_subscription_and_custom_headers() -> Result<()> {
    let ctx = context(&[
        (KEY_VARIABLE, "fake-subscription-key"),
        ("EXAMPLE_GATEWAY_KEY", "fake-gateway-key"),
    ]);
    for (variable, request_signer, header, key) in [
        (
            KEY_VARIABLE,
            RequestSigner::subscription_key(),
            "ocp-apim-subscription-key",
            "fake-subscription-key",
        ),
        (
            "EXAMPLE_GATEWAY_KEY",
            RequestSigner::new("X-Gateway-Key")?,
            "x-gateway-key",
            "fake-gateway-key",
        ),
    ] {
        let signer = Signer::new(
            ctx.clone(),
            EnvCredentialProvider::new(variable)?,
            request_signer,
        );
        let mut parts = request(header);
        signer.sign(&mut parts, None).await?;

        let mut expected = request(header);
        expected
            .headers
            .insert(header, HeaderValue::from_static(key));
        assert_same_request(&parts, &expected);
        assert!(parts.headers[header].is_sensitive());
    }
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected_at_construction() {
    for header in ["", "bad header", "bad:header", "bad\r\nheader"] {
        let error = RequestSigner::new(header).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
    for variable in ["", " \t", "name=value", "name\0value"] {
        let error = EnvCredentialProvider::new(variable).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }
    for key in ["", " \t", "embedded space", "non-ascii-é", INVALID_KEY] {
        let error = StaticCredentialProvider::new(key).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert!(!format!("{error:?} {error}").contains("fake-malformed-key"));
    }
}

#[tokio::test]
async fn missing_or_invalid_environment_keys_fail_without_fallback_or_mutation() -> Result<()> {
    let provider = EnvCredentialProvider::new(KEY_VARIABLE)?;
    let original = request("api-key");
    for key in [None, Some(""), Some(INVALID_KEY)] {
        let mut variables = vec![("AZURE_OPENAI_API_KEY", "fake-unselected-key")];
        if let Some(key) = key {
            variables.push((KEY_VARIABLE, key));
        }
        let ctx = context(&variables);
        match key {
            Some(_) => {
                let error = provider.provide_credential(&ctx).await.unwrap_err();
                assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
            }
            None => assert!(provider.provide_credential(&ctx).await?.is_none()),
        }
        let signer = Signer::new(ctx, provider.clone(), RequestSigner::api_key());
        let mut parts = original.clone();
        let error = signer.sign(&mut parts, None).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert!(!format!("{error:?} {error}").contains("fake-malformed-key"));
        assert_same_request(&parts, &original);
    }
    Ok(())
}

#[tokio::test]
async fn presigning_and_requests_without_an_authority_fail_atomically() -> Result<()> {
    let ctx = Context::new();
    let provider = StaticCredentialProvider::new("fake-static-key")?;
    let signer = Signer::new(ctx.clone(), provider, RequestSigner::api_key());
    let credential: Credential = signer.credential_for(None).await?;
    let request_signer = RequestSigner::api_key();

    for (uri, expires_in) in [(URI, Some(Duration::ZERO)), ("/deployments/test", None)] {
        let mut original = request("api-key");
        original.uri = uri.parse().unwrap();
        let mut parts = original.clone();
        let error = signer.sign(&mut parts, expires_in).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert_same_request(&parts, &original);

        let error = request_signer
            .sign_request(&ctx, &mut parts, Some(&credential), expires_in)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert_same_request(&parts, &original);
    }
    Ok(())
}
