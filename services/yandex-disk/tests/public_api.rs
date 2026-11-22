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

use std::collections::HashMap;
use std::time::Duration;

use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, ErrorKind, ProvideCredential, ProvideCredentialChain, Result, SignRequest, Signer,
    SigningCredential, StaticEnv,
};
use reqsign_yandex_disk::{
    AccessToken, Credential, DefaultCredentialProvider, RequestSigner, StaticCredentialProvider,
};

const STATIC_TOKEN: &str = "fake-yandex-disk-static-token-A1";
const STALE_TOKEN: &str = "fake-yandex-disk-stale-token-B2";
const AUTHORIZATION: http::header::HeaderName = http::header::AUTHORIZATION;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CallerExtension(&'static str);

fn request() -> http::request::Parts {
    let mut parts = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://cloud-api.yandex.net/v1/disk/resources?path=disk%3A%2Ffolder%2Ffile&sort=%2Bname")
        .header(http::header::ACCEPT, "application/json")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    parts.extensions.insert(CallerExtension("caller-owned"));
    parts
}

fn context_with_fabricated_environment() -> Context {
    Context::new().with_env(StaticEnv {
        home_dir: Some("/tmp/fake-yandex-disk-home".into()),
        envs: HashMap::from([
            (
                "YANDEX_DISK_ACCESS_TOKEN".to_string(),
                "fake-yandex-disk-ambient-token-C3".to_string(),
            ),
            (
                "YANDEX_DISK_TOKEN".to_string(),
                "fake-yandex-disk-ambient-token-D4".to_string(),
            ),
        ]),
    })
}

#[tokio::test]
async fn static_signer_adds_a_sensitive_oauth_header_and_preserves_request() -> Result<()> {
    let original = request();
    let mut parts = original.clone();
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );

    signer.sign(&mut parts, None).await?;

    let authorization = parts
        .headers
        .get(AUTHORIZATION)
        .expect("Authorization must be present");
    assert_eq!(
        authorization.to_str().expect("Authorization must be text"),
        format!("OAuth {STATIC_TOKEN}")
    );
    assert!(authorization.is_sensitive());
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.method, original.method);
    assert_eq!(parts.version, original.version);
    assert_eq!(
        parts.extensions.get::<CallerExtension>(),
        Some(&CallerExtension("caller-owned"))
    );
    assert_eq!(parts.headers[http::header::ACCEPT], "application/json");
    assert_eq!(
        parts.headers[http::header::CONTENT_TYPE],
        "application/json"
    );
    assert_eq!(parts.headers.len(), original.headers.len() + 1);

    Ok(())
}

#[tokio::test]
async fn signing_replaces_stale_authorization() -> Result<()> {
    let mut parts = request();
    parts.headers.insert(
        AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {STALE_TOKEN}"))
            .expect("stale header must be valid"),
    );
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );

    signer.sign(&mut parts, None).await?;

    assert_eq!(
        parts.headers[AUTHORIZATION],
        format!("OAuth {STATIC_TOKEN}")
    );

    Ok(())
}

#[tokio::test]
async fn default_provider_has_no_implicit_source() -> Result<()> {
    let context = context_with_fabricated_environment();

    for provider in [
        DefaultCredentialProvider::new(),
        DefaultCredentialProvider::default(),
        DefaultCredentialProvider::builder().build(),
    ] {
        assert!(
            provider.provide_credential(&context).await?.is_none(),
            "the default provider must not invent an environment or file source"
        );
    }

    Ok(())
}

#[tokio::test]
async fn default_provider_composes_explicit_sources_and_fails_closed() -> Result<()> {
    let context = Context::new();
    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(STATIC_TOKEN));
    let credential = provider
        .provide_credential(&context)
        .await?
        .expect("the prepended static provider must supply a credential");
    assert_eq!(credential.access_token().as_str(), STATIC_TOKEN);

    let chain = ProvideCredentialChain::new().push(StaticCredentialProvider::new(STATIC_TOKEN));
    let provider = DefaultCredentialProvider::with_chain(chain);
    let credential = provider
        .provide_credential(&context)
        .await?
        .expect("the caller-supplied chain must supply a credential");
    assert_eq!(credential.access_token().as_str(), STATIC_TOKEN);

    let secret = "fake-yandex-disk-invalid-token-\u{00e9}";
    let provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(secret));
    let error = provider
        .provide_credential(&context)
        .await
        .expect_err("an invalid prepended provider must not fall through");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(!format!("{error}").contains(secret));
    assert!(!format!("{error:?}").contains(secret));

    Ok(())
}

#[tokio::test]
async fn access_token_validation_is_opaque_and_strict() -> Result<()> {
    let token = AccessToken::new("plain_OAuth-token.123~")?;
    assert_eq!(token.as_str(), "plain_OAuth-token.123~");
    assert_eq!(
        Credential::from_access_token(token).access_token().as_str(),
        "plain_OAuth-token.123~"
    );
    assert!(Credential::new("plain_OAuth-token.123~").is_ok());

    for invalid in [
        "",
        "token with a space",
        "token-with\nnewline",
        "token-\u{00e9}",
    ] {
        let error = AccessToken::new(invalid).expect_err("invalid token must fail");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    }

    Ok(())
}

#[tokio::test]
async fn expiration_controls_refresh_and_exact_signing_deadline() -> Result<()> {
    let now = Timestamp::now();
    let expires_at = now + Duration::from_secs(10);
    let expiring = Credential::new(STATIC_TOKEN)?.with_expires_at(expires_at);

    assert!(
        !expiring.is_valid(),
        "a credential inside the refresh window must not be reused"
    );
    assert!(expiring.is_valid_at(now + Duration::from_secs(9)));
    assert!(!expiring.is_valid_at(expires_at));
    assert_eq!(expiring.expires_at(), Some(expires_at));

    let static_credential = Credential::new(STATIC_TOKEN)?;
    assert!(static_credential.is_valid());
    assert!(static_credential.is_valid_at(now));
    assert_eq!(static_credential.expires_at(), None);

    let provider = StaticCredentialProvider::new(STATIC_TOKEN).with_expires_at(expires_at);
    let credential = provider
        .provide_credential(&Context::new())
        .await?
        .expect("the static provider must return a credential");
    assert_eq!(credential.expires_at(), Some(expires_at));

    Ok(())
}

#[tokio::test]
async fn expired_static_credential_fails_without_mutating_the_request() -> Result<()> {
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN)
            .with_expires_at(Timestamp::now() - Duration::from_secs(1)),
        RequestSigner,
    );
    let original = request();
    let mut parts = original.clone();

    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an expired credential must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn debug_output_redacts_tokens() -> Result<()> {
    let token = "fake-yandex-disk-secret-token-E5";
    let access_token = AccessToken::new(token)?;
    let credential = Credential::from_access_token(access_token);
    let static_provider = StaticCredentialProvider::new(token);
    let default_provider =
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(token));

    for debug in [
        format!("{credential:?}"),
        format!("{static_provider:?}"),
        format!("{default_provider:?}"),
    ] {
        assert!(!debug.contains(token), "Debug must not reveal the token");
    }
    assert!(!format!("{:?}", credential.access_token()).contains(token));

    let error =
        Credential::new(format!("{token}-\u{00e9}")).expect_err("non-ASCII token must fail");
    assert!(!format!("{error}").contains(token));
    assert!(!format!("{error:?}").contains(token));

    Ok(())
}

#[tokio::test]
async fn missing_credentials_and_expires_in_fail_without_mutating_the_request() -> Result<()> {
    let original = request();

    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new(),
        RequestSigner,
    );
    let mut parts = original.clone();
    let error = signer
        .sign(&mut parts, None)
        .await
        .expect_err("an empty default chain must not sign");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(STATIC_TOKEN),
        RequestSigner,
    );
    let mut parts = original.clone();
    let error = signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .expect_err("Yandex Disk has no query authentication");
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    let mut parts = original.clone();
    let error = RequestSigner
        .sign_request(&Context::new(), &mut parts, None, None)
        .await
        .expect_err("direct signing requires a credential");
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    assert_eq!(parts.uri, original.uri);
    assert_eq!(parts.headers, original.headers);

    Ok(())
}

#[tokio::test]
async fn empty_default_provider_and_invalid_static_token_do_not_leak_into_the_request() -> Result<()>
{
    let original = request();
    let signer = Signer::new(
        Context::new(),
        DefaultCredentialProvider::new().push_front(StaticCredentialProvider::new(
            "fake-yandex-disk-invalid-\u{00e9}",
        )),
        RequestSigner,
    );

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
