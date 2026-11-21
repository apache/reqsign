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

use crate::request_signer::{TargetContext, signature_base, signature_parameters};
use crate::{Component, Credential, RequestSigner, StaticCredentialProvider};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, DATE, HOST, HeaderName};
use http::request::Parts;
use reqsign_core::hash::base64_decode;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ErrorKind, SignRequest, Signer};
use reqsign_crypto_rustcrypto::RustCryptoProvider;
use std::time::Duration;

const CONTENT_DIGEST: HeaderName = HeaderName::from_static("content-digest");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
const SIGNATURE: HeaderName = HeaderName::from_static("signature");
const SIGNATURE_INPUT: HeaderName = HeaderName::from_static("signature-input");
const X_TEST: HeaderName = HeaderName::from_static("x-test");

const B25_BASE: &str = include_str!("../tests/fixtures/b25_base.txt");
const B25_SIGNATURE_INPUT: &str = include_str!("../tests/fixtures/b25_signature_input.txt");
const B25_SIGNATURE: &str = include_str!("../tests/fixtures/b25_signature.txt");
const B25_SECRET: &str = include_str!("../tests/fixtures/shared_secret.b64");
const PROXY_BASE: &str = include_str!("../tests/fixtures/proxy_base.txt");
const PROXY_SIGNATURE_INPUT: &str = include_str!("../tests/fixtures/proxy_signature_input.txt");
const PROXY_SIGNATURE: &str = include_str!("../tests/fixtures/proxy_signature.txt");
const RSA_PRIVATE_KEY: &str = include_str!("../tests/fixtures/rsa_private.pem");

const SEARCH_DIGEST: &str = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";
const FORWARDED_VALUE: &str = "for=192.0.2.123;host=example.com;proto=https";

fn fixture(value: &str) -> &str {
    value.strip_suffix('\n').unwrap_or(value)
}

fn hmac_credential() -> Credential {
    let secret = base64_decode(fixture(B25_SECRET)).unwrap();
    Credential::hmac_sha256("test-shared-secret", secret).unwrap()
}

fn signing_context() -> Context {
    Context::new().with_crypto(RustCryptoProvider::new())
}

fn official_b25_request() -> Parts {
    http::Request::builder()
        .method("POST")
        .uri("https://example.com/foo?param=Value&Pet=dog")
        .header(HOST, "example.com")
        .header(DATE, "Tue, 20 Apr 2021 02:07:55 GMT")
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_DIGEST, SEARCH_DIGEST)
        .header(CONTENT_LENGTH, "18")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn official_proxy_request() -> Parts {
    http::Request::builder()
        .method("POST")
        .uri("https://origin.host.internal.example/foo?param=Value&Pet=dog")
        .header(HOST, "origin.host.internal.example")
        .header(DATE, "Tue, 20 Apr 2021 02:07:56 GMT")
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, "18")
        .header(FORWARDED, FORWARDED_VALUE)
        .header(CONTENT_DIGEST, SEARCH_DIGEST)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[tokio::test]
async fn matches_rfc_9421_b25_hmac_vector() {
    let request_signer = RequestSigner::new(
        "sig-b25",
        [
            Component::Header(DATE),
            Component::Authority,
            Component::Header(CONTENT_TYPE),
        ],
    )
    .unwrap()
    .with_algorithm(false)
    .with_time(Timestamp::from_second(1_618_884_473).unwrap());
    let signer = Signer::new(
        signing_context(),
        StaticCredentialProvider::new(hmac_credential()),
        request_signer,
    );

    let mut parts = official_b25_request();
    signer.sign(&mut parts, None).await.unwrap();

    assert_eq!(
        parts
            .headers
            .get(SIGNATURE_INPUT)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("sig-b25={}", fixture(B25_SIGNATURE_INPUT))
    );
    assert_eq!(
        parts.headers.get(SIGNATURE).unwrap().to_str().unwrap(),
        format!("sig-b25={}", fixture(B25_SIGNATURE))
    );
    assert!(parts.headers.get(SIGNATURE).unwrap().is_sensitive());
    assert!(parts.headers.get(SIGNATURE_INPUT).unwrap().is_sensitive());
}

#[tokio::test]
async fn matches_rfc_9421_proxy_sig_rsa_vector() {
    let request_signer = RequestSigner::new(
        "proxy_sig",
        [
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::Header(CONTENT_DIGEST),
            Component::Header(CONTENT_TYPE),
            Component::Header(CONTENT_LENGTH),
            Component::Header(FORWARDED),
        ],
    )
    .unwrap()
    .with_time(Timestamp::from_second(1_618_884_480).unwrap());
    let credential = Credential::rsa_v1_5_sha256("test-key-rsa", RSA_PRIVATE_KEY).unwrap();
    let signer = Signer::new(
        signing_context(),
        StaticCredentialProvider::new(credential),
        request_signer,
    );

    let mut parts = official_proxy_request();
    signer
        .sign(&mut parts, Some(Duration::from_secs(60)))
        .await
        .unwrap();

    assert_eq!(
        parts
            .headers
            .get(SIGNATURE_INPUT)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("proxy_sig={}", fixture(PROXY_SIGNATURE_INPUT))
    );
    assert_eq!(
        parts.headers.get(SIGNATURE).unwrap().to_str().unwrap(),
        format!("proxy_sig={}", fixture(PROXY_SIGNATURE))
    );
}

#[test]
fn preserves_target_uri_path_query_and_escapes() {
    let parts = http::Request::builder()
        .method("GET")
        .uri("https://example.com/a%2Fb?b=2&a=1&a=1")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let base = base_for(
        &parts,
        &[Component::TargetUri, Component::Path, Component::Query],
    );

    assert!(base.contains("\"@target-uri\": https://example.com/a%2Fb?b=2&a=1&a=1\n"));
    assert!(base.contains("\"@path\": /a%2Fb\n"));
    assert!(base.contains("\"@query\": ?b=2&a=1&a=1\n"));
}

#[test]
fn preserves_method_case_and_escapes_signature_strings() {
    let parts = http::Request::builder()
        .method("PoSt")
        .uri("https://example.com/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let base = base_for(&parts, &[Component::Method]);
    assert!(base.contains("\"@method\": PoSt\n"));

    let credential = Credential::hmac_sha256("a\"b\\c", b"secret").unwrap();
    let parameters =
        signature_parameters(&credential, &[Component::Method], 1, None, false).unwrap();
    assert_eq!(parameters, "(\"@method\");created=1;keyid=\"a\\\"b\\\\c\"");
}

#[test]
fn handles_empty_path_absent_query_and_normalized_authority() {
    let parts = http::Request::builder()
        .method("GET")
        .uri("https://EXAMPLE.com:443")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let base = base_for(
        &parts,
        &[
            Component::Authority,
            Component::Scheme,
            Component::Path,
            Component::Query,
        ],
    );

    assert!(base.contains("\"@authority\": example.com\n"));
    assert!(base.contains("\"@scheme\": https\n"));
    assert!(base.contains("\"@path\": /\n"));
    assert!(base.contains("\"@query\": ?\n"));
}

#[test]
fn normalizes_ipv6_authority_and_omits_default_port() {
    let parts = http::Request::builder()
        .method("GET")
        .uri("https://[2001:DB8::1]:443/resource")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let base = base_for(&parts, &[Component::Authority]);

    assert!(base.contains("\"@authority\": [2001:db8::1]\n"));
}

#[test]
fn combines_ordered_header_values_and_trims_ows() {
    let mut request = http::Request::builder()
        .method("GET")
        .uri("https://example.com/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    request
        .headers
        .append(X_TEST, http::HeaderValue::from_bytes(b"  one  ").unwrap());
    request
        .headers
        .append(X_TEST, http::HeaderValue::from_bytes(b"\ttwo\t").unwrap());

    let base = base_for(&request, &[Component::Header(X_TEST)]);
    assert!(base.contains("\"x-test\": one, two\n"));
}

#[test]
fn rejects_obs_text_in_covered_headers() {
    let mut request = http::Request::builder()
        .method("GET")
        .uri("https://example.com/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    request
        .headers
        .insert(X_TEST, http::HeaderValue::from_bytes(b"caf\xe9").unwrap());

    let error = base_for_err(&request, &[Component::Header(X_TEST)]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
}

#[test]
fn rejects_missing_covered_header() {
    let parts = http::Request::builder()
        .method("GET")
        .uri("https://example.com/")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    let error = base_for_err(&parts, &[Component::Header(X_TEST)]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
}

#[test]
fn rejects_relative_unsupported_and_userinfo_uris() {
    for uri in [
        "/relative",
        "ftp://example.com/resource",
        "https://user@example.com/resource",
    ] {
        let parts = http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let error = base_for_err(&parts, &[Component::Method]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestInvalid, "{uri}");
    }
}

#[test]
fn rejects_duplicate_or_inconsistent_host_headers() {
    let mut parts = http::Request::builder()
        .method("GET")
        .uri("https://example.com/resource")
        .header(HOST, "example.com")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    parts
        .headers
        .append(HOST, http::HeaderValue::from_static("example.com"));
    let error = base_for_err(&parts, &[Component::Authority]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);

    let parts = http::Request::builder()
        .method("GET")
        .uri("https://example.com/resource")
        .header(HOST, "other.example")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let error = base_for_err(&parts, &[Component::Authority]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
}

#[test]
fn accepts_host_header_equal_to_uri_after_normalization() {
    let parts = http::Request::builder()
        .method("GET")
        .uri("https://example.com/resource")
        .header(HOST, "EXAMPLE.com:443")
        .body(())
        .unwrap()
        .into_parts()
        .0;

    let base = base_for(&parts, &[Component::Authority]);
    assert!(base.contains("\"@authority\": example.com\n"));
}

#[tokio::test]
async fn rejects_preexisting_signature_headers_without_mutating_the_head() {
    let request_signer =
        RequestSigner::new("sig1", [Component::Method, Component::Authority]).unwrap();
    let credential = hmac_credential();
    let mut parts = official_b25_request();
    parts
        .headers
        .insert(SIGNATURE, http::HeaderValue::from_static("existing=:AAAA:"));
    let before = parts.headers.clone();

    let error = request_signer
        .sign_request(&signing_context(), &mut parts, Some(&credential), None)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.headers, before);
}

#[tokio::test]
async fn rejects_missing_component_without_mutating_the_head() {
    let request_signer =
        RequestSigner::new("sig1", [Component::Method, Component::Header(X_TEST)]).unwrap();
    let credential = hmac_credential();
    let mut parts = official_b25_request();
    let before = parts.headers.clone();

    let error = request_signer
        .sign_request(&signing_context(), &mut parts, Some(&credential), None)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert_eq!(parts.headers, before);
}

#[tokio::test]
async fn missing_crypto_provider_returns_config_invalid() {
    let request_signer = RequestSigner::new("sig1", [Component::Method]).unwrap();
    let signer = Signer::new(
        Context::new(),
        StaticCredentialProvider::new(hmac_credential()),
        request_signer,
    );
    let mut parts = official_b25_request();
    let before = parts.headers.clone();

    let error = signer.sign(&mut parts, None).await.unwrap_err();

    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(parts.headers, before);
}

#[tokio::test]
async fn extreme_and_subsecond_durations_fail_without_panicking() {
    let request_signer = RequestSigner::new("sig1", [Component::Method]).unwrap();
    let signer = Signer::new(
        signing_context(),
        StaticCredentialProvider::new(hmac_credential()),
        request_signer,
    );

    let mut parts = official_b25_request();
    let error = signer
        .sign(&mut parts, Some(Duration::MAX))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
    assert!(!parts.headers.contains_key(SIGNATURE));
    assert!(!parts.headers.contains_key(SIGNATURE_INPUT));

    let request_signer = RequestSigner::new("sig1", [Component::Method]).unwrap();
    let mut parts = official_b25_request();
    let error = request_signer
        .sign_request(
            &signing_context(),
            &mut parts,
            Some(&hmac_credential()),
            Some(Duration::from_millis(1_500)),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestInvalid);
}

#[test]
fn rejects_empty_duplicate_and_invalid_policies() {
    assert!(RequestSigner::new("Sig1", [Component::Method]).is_err());
    assert!(RequestSigner::new("sig1", []).is_err());
    assert!(RequestSigner::new("sig1", [Component::Method, Component::Method]).is_err());
}

#[test]
fn signature_bases_match_official_rfc_vectors() {
    let parts = official_b25_request();
    let target = TargetContext::from_parts(&parts).unwrap();
    let credential = hmac_credential();
    let parameters = signature_parameters(
        &credential,
        &[
            Component::Header(DATE),
            Component::Authority,
            Component::Header(CONTENT_TYPE),
        ],
        1_618_884_473,
        None,
        false,
    )
    .unwrap();
    let base = signature_base(
        &parts,
        &target,
        &[
            Component::Header(DATE),
            Component::Authority,
            Component::Header(CONTENT_TYPE),
        ],
        &parameters,
    )
    .unwrap();
    assert_eq!(base, fixture(B25_BASE));

    let parts = official_proxy_request();
    let target = TargetContext::from_parts(&parts).unwrap();
    let credential = Credential::rsa_v1_5_sha256("test-key-rsa", RSA_PRIVATE_KEY).unwrap();
    let components = [
        Component::Method,
        Component::Authority,
        Component::Path,
        Component::Header(CONTENT_DIGEST),
        Component::Header(CONTENT_TYPE),
        Component::Header(CONTENT_LENGTH),
        Component::Header(FORWARDED),
    ];
    let parameters = signature_parameters(
        &credential,
        &components,
        1_618_884_480,
        Some(1_618_884_540),
        true,
    )
    .unwrap();
    let base = signature_base(&parts, &target, &components, &parameters).unwrap();
    assert_eq!(base, fixture(PROXY_BASE));
}

fn base_for(parts: &Parts, components: &[Component]) -> String {
    base_for_err(parts, components).unwrap()
}

fn base_for_err(parts: &Parts, components: &[Component]) -> reqsign_core::Result<String> {
    let target = TargetContext::from_parts(parts)?;
    let credential = Credential::hmac_sha256("test-key", b"secret").unwrap();
    let parameters = signature_parameters(&credential, components, 1_700_000_000, None, true)?;
    signature_base(parts, &target, components, &parameters)
}
