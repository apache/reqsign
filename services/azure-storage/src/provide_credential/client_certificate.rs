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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::credential::Credential;
use crate::provide_credential::entra::{
    EntraTokenResponse, client_credentials_scope, parse_token_response, token_endpoint,
    token_request_error,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, hash};
use serde::Serialize;
use std::fmt::{Debug, Formatter};

const REDACTED: &str = "REDACTED";

/// Generate a unique JWT ID using timestamp and a pseudo-random component
fn generate_jti(now: u64) -> String {
    // Use timestamp in nanoseconds + a hash of the timestamp for uniqueness
    let nano_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Create a pseudo-random component by hashing the nano time
    let random_part = (nano_time.wrapping_mul(6364136223846793005).wrapping_add(1)) % 1_000_000;

    format!("{}-{}-{}", now, nano_time % 1_000_000_000, random_part)
}

/// Provides Microsoft Entra ID credentials using a client certificate.
///
/// The PEM file must contain an unencrypted PKCS#8 or PKCS#1 RSA private key
/// and its certificate. Place the leaf certificate first, followed by any
/// issuer certificates in chain order. By default, the assertion uses PS256
/// and a SHA-256 thumbprint of the leaf certificate (`x5t#S256`).
#[derive(Clone)]
pub struct ClientCertificateCredentialProvider {
    tenant_id: Option<String>,
    client_id: Option<String>,
    certificate_path: Option<String>,
    certificate_password: Option<String>,
    send_certificate_chain: Option<bool>,
    assertion_algorithm: ClientAssertionAlgorithm,
    authority_host: Option<String>,
    scope: Option<String>,
}

impl Debug for ClientCertificateCredentialProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificateCredentialProvider")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("certificate_path", &self.certificate_path)
            .field(
                "certificate_password",
                &self.certificate_password.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

impl Default for ClientCertificateCredentialProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientCertificateCredentialProvider {
    pub fn new() -> Self {
        Self {
            tenant_id: None,
            client_id: None,
            certificate_path: None,
            certificate_password: None,
            send_certificate_chain: None,
            assertion_algorithm: ClientAssertionAlgorithm::Ps256,
            authority_host: None,
            scope: None,
        }
    }

    /// Set the tenant ID
    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    /// Set the client ID
    pub fn with_client_id(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self
    }

    /// Set the certificate path
    pub fn with_certificate_path(mut self, path: &str) -> Self {
        self.certificate_path = Some(path.to_string());
        self
    }

    /// Set a certificate password for compatibility with existing callers.
    ///
    /// Credential loading ignores this setting and requires an unencrypted RSA
    /// private key in the PEM file.
    pub fn with_certificate_password(mut self, password: &str) -> Self {
        self.certificate_password = Some(password.to_string());
        self
    }

    /// Include the public certificate chain in the assertion's `x5c` header.
    ///
    /// An explicit value overrides `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`,
    /// including `false`. Without an explicit value, only a case-insensitive
    /// `true` in the context environment enables the header.
    pub fn with_send_certificate_chain(mut self, send_certificate_chain: bool) -> Self {
        self.send_certificate_chain = Some(send_certificate_chain);
        self
    }

    /// Use RS256 with the SHA-1 certificate thumbprint (`x5t`).
    ///
    /// Select this explicitly for legacy configurations, including crypto
    /// providers that only implement RSA PKCS#1 v1.5 signing. By default the
    /// provider uses PS256 and propagates any error from that operation.
    pub fn with_legacy_rs256(mut self) -> Self {
        self.assertion_algorithm = ClientAssertionAlgorithm::Rs256;
        self
    }

    /// Set the authority host, overriding `AZURE_AUTHORITY_HOST` from the context.
    /// The client assertion uses the resolved token endpoint as its audience.
    pub fn with_authority_host(mut self, authority_host: impl Into<String>) -> Self {
        self.authority_host = Some(authority_host.into());
        self
    }

    /// Request a single `<resource>/.default` scope. Defaults to Azure Storage.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Load the certificates and private key from a PEM file.
    async fn load_certificate(
        &self,
        ctx: &Context,
        path: &str,
    ) -> Result<ClientCertificate, reqsign_core::Error> {
        let cert_data = ctx.file_read(path).await.map_err(|e| {
            reqsign_core::Error::credential_invalid(format!("Failed to read certificate file: {e}"))
        })?;

        let pem_str = String::from_utf8(cert_data).map_err(|e| {
            reqsign_core::Error::credential_invalid(format!(
                "Certificate file is not valid UTF-8: {e}"
            ))
        })?;

        let pems = pem::parse_many(&pem_str).map_err(|e| {
            reqsign_core::Error::credential_invalid(format!("Failed to parse PEM: {e}"))
        })?;

        let mut leaf_der = None;
        let mut issuer_chain_der = Vec::new();
        let mut private_key_pem = None;

        for pem_block in pems {
            match pem_block.tag() {
                "CERTIFICATE" if leaf_der.is_none() => {
                    leaf_der = Some(pem_block.into_contents());
                }
                "CERTIFICATE" => issuer_chain_der.push(pem_block.into_contents()),
                "PRIVATE KEY" | "RSA PRIVATE KEY" => {
                    private_key_pem = Some(pem::encode(&pem_block));
                }
                _ => {}
            }
        }

        let leaf_der = leaf_der.ok_or_else(|| {
            reqsign_core::Error::credential_invalid("PEM does not contain a certificate")
        })?;

        let private_key_pem = private_key_pem.ok_or_else(|| {
            reqsign_core::Error::credential_invalid("PEM does not contain a private key")
        })?;

        Ok(ClientCertificate {
            leaf_der,
            issuer_chain_der,
            private_key_pem: private_key_pem.into_bytes(),
        })
    }

    /// Format and sign the compact JWS with the algorithm in its header.
    fn encode_jws(
        provider: &dyn CryptoProvider,
        header: &ClientAssertionHeader,
        claims: &ClientAssertionClaims,
        private_key_pem: &[u8],
    ) -> Result<String, reqsign_core::Error> {
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize JWT JSON").with_source(e)
        })?);
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize JWT JSON").with_source(e)
        })?);
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = match header.alg {
            ClientAssertionAlgorithm::Ps256 => {
                provider.rsa_pss_sha256_sign(private_key_pem, signing_input.as_bytes())?
            }
            ClientAssertionAlgorithm::Rs256 => {
                provider.rsa_pkcs1v15_sha256_sign(private_key_pem, signing_input.as_bytes())?
            }
        };

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    /// Create JWT client assertion
    fn create_client_assertion(
        &self,
        provider: &dyn CryptoProvider,
        endpoint: &http::Uri,
        client_id: &str,
        certificate: &ClientCertificate,
        send_certificate_chain: bool,
    ) -> Result<String, reqsign_core::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                reqsign_core::Error::unexpected(format!("Failed to get current time: {e}"))
            })?
            .as_secs();

        let claims = ClientAssertionClaims {
            aud: endpoint.to_string(),
            exp: now + 600, // 10 minutes
            iss: client_id.to_string(),
            jti: generate_jti(now),
            nbf: now,
            sub: client_id.to_string(),
        };

        let (x5t, x5t_s256) = match self.assertion_algorithm {
            ClientAssertionAlgorithm::Ps256 => (
                None,
                Some(URL_SAFE_NO_PAD.encode(hash::sha256(provider, &certificate.leaf_der)?)),
            ),
            ClientAssertionAlgorithm::Rs256 => (
                Some(URL_SAFE_NO_PAD.encode(hash::sha1(provider, &certificate.leaf_der)?)),
                None,
            ),
        };
        let header = ClientAssertionHeader {
            alg: self.assertion_algorithm,
            typ: "JWT",
            x5t,
            x5t_s256,
            x5c: send_certificate_chain.then(|| {
                std::iter::once(&certificate.leaf_der)
                    .chain(&certificate.issuer_chain_der)
                    .map(|der| STANDARD.encode(der))
                    .collect()
            }),
        };

        Self::encode_jws(provider, &header, &claims, &certificate.private_key_pem)
    }

    /// Exchange client assertion for access token
    async fn exchange_token(
        &self,
        ctx: &Context,
        endpoint: http::Uri,
        client_id: &str,
        client_assertion: &str,
        scope: &str,
    ) -> Result<EntraTokenResponse, reqsign_core::Error> {
        let mut params = HashMap::new();
        params.insert("scope", scope);
        params.insert("client_id", client_id);
        params.insert(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        );
        params.insert("client_assertion", client_assertion);
        params.insert("grant_type", "client_credentials");

        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params)
            .finish();

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(bytes::Bytes::from(body))
            .map_err(|e| {
                reqsign_core::Error::unexpected(format!("Failed to build request: {e}"))
            })?;

        let resp = ctx.http_send(req).await?;

        if resp.status() != http::StatusCode::OK {
            return Err(token_request_error(
                "Microsoft Entra client certificate token request",
                resp.status(),
            ));
        }

        parse_token_response(resp.body(), "client certificate token response")
    }
}

struct ClientCertificate {
    leaf_der: Vec<u8>,
    issuer_chain_der: Vec<Vec<u8>>,
    private_key_pem: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ClientAssertionClaims {
    aud: String,
    exp: u64,
    iss: String,
    jti: String,
    nbf: u64,
    sub: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
enum ClientAssertionAlgorithm {
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "RS256")]
    Rs256,
}

#[derive(Debug, Serialize)]
struct ClientAssertionHeader {
    alg: ClientAssertionAlgorithm,
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5t: Option<String>,
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    x5t_s256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
}

impl ProvideCredential for ClientCertificateCredentialProvider {
    type Credential = Credential;

    async fn provide_credential(
        &self,
        ctx: &Context,
    ) -> Result<Option<Self::Credential>, reqsign_core::Error> {
        let envs = ctx.env_vars();

        // Try to get credentials from environment variables or configured values
        let tenant_id = self
            .tenant_id
            .as_ref()
            .or_else(|| envs.get("AZURE_TENANT_ID"))
            .cloned();

        let client_id = self
            .client_id
            .as_ref()
            .or_else(|| envs.get("AZURE_CLIENT_ID"))
            .cloned();

        let certificate_path = self
            .certificate_path
            .as_ref()
            .or_else(|| envs.get("AZURE_CLIENT_CERTIFICATE_PATH"))
            .cloned();

        // Check if all required parameters are present
        let (tenant_id, client_id, certificate_path) =
            match (tenant_id, client_id, certificate_path) {
                (Some(t), Some(c), Some(p)) => (t, c, p),
                _ => return Ok(None),
            };

        let send_certificate_chain = self.send_certificate_chain.unwrap_or_else(|| {
            envs.get("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        });

        let scope = client_credentials_scope(self.scope.as_deref())?;
        let endpoint = token_endpoint(&tenant_id, self.authority_host.as_deref(), &envs)?;
        let provider = ctx.crypto_provider()?;
        let certificate = self.load_certificate(ctx, &certificate_path).await?;
        let client_assertion = self.create_client_assertion(
            provider,
            &endpoint,
            &client_id,
            &certificate,
            send_certificate_chain,
        )?;

        // Exchange for access token
        let token_response = self
            .exchange_token(ctx, endpoint, &client_id, &client_assertion, scope)
            .await?;

        // Calculate expiration time
        let expires_on = token_response.expires_at(Timestamp::now())?;

        Ok(Some(Credential::with_bearer_token(
            &token_response.access_token,
            Some(expires_on),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use reqsign_core::{FileRead, HttpSend, StaticEnv};
    use serde_json::{Value, json};

    // The leaf certificate matches the existing RSA signing fixture.
    const LEAF_PEM: &[u8] = include_bytes!("../../tests/fixtures/client_cert_leaf.pem");
    const ISSUER_PEM: &[u8] = include_bytes!("../../tests/fixtures/client_cert_issuer.pem");
    const ROOT_PEM: &[u8] = include_bytes!("../../tests/fixtures/client_cert_root.pem");
    const RSA_PKCS8: &[u8] = include_bytes!("../../tests/fixtures/rsa_pkcs8.pem");
    // Leaf DER thumbprints computed independently using OpenSSL and Python.
    const LEAF_SHA1_THUMBPRINT: &str = "49Y8PKhJSB3Xrhw3Xl1ubzZbydY";
    const LEAF_SHA256_THUMBPRINT: &str = "taSqlR5mGn8jo8b2egtzYP-eVvcHO9-AST0l8XpRL38";
    const CERTIFICATE_PATH: &str = "/test/client-certificate.pem";
    const PUBLIC_ENDPOINT: &str = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token";
    const TEST_SCOPE: &str = "https://vault.azure.net/.default";

    #[derive(Debug)]
    struct CertificateFile(Vec<u8>);

    impl FileRead for CertificateFile {
        async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
            assert_eq!(path, CERTIFICATE_PATH);
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct TokenEndpoint {
        expected_header: Value,
        expected_uri: &'static str,
        expected_scope: &'static str,
    }

    impl HttpSend for TokenEndpoint {
        async fn http_send(
            &self,
            req: http::Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            assert_eq!(req.method(), http::Method::POST);
            assert_eq!(req.uri(), self.expected_uri);
            let form: HashMap<_, _> = form_urlencoded::parse(req.body()).collect();
            assert_eq!(form["scope"], self.expected_scope);
            let mut segments = form["client_assertion"].split('.');
            let encoded_header = segments.next().expect("JWS must have a header");
            let encoded_claims = segments.next().expect("JWS must have claims");
            let header: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(encoded_header)
                    .expect("JWS header must decode"),
            )
            .expect("JWS header must be JSON");
            assert_eq!(header, self.expected_header);
            let claims: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(encoded_claims)
                    .expect("JWS claims must decode"),
            )
            .expect("JWS claims must be JSON");
            assert_eq!(claims["aud"], self.expected_uri);

            Ok(http::Response::new(Bytes::from_static(
                br#"{"access_token":"mock-entra-token","expires_in":3600}"#,
            )))
        }
    }

    fn certificate_context(pem: Vec<u8>, overrides: &[(&str, &str)]) -> Context {
        let mut env = StaticEnv {
            envs: HashMap::from([
                ("AZURE_TENANT_ID".to_string(), "test-tenant".to_string()),
                ("AZURE_CLIENT_ID".to_string(), "test-client".to_string()),
                (
                    "AZURE_CLIENT_CERTIFICATE_PATH".to_string(),
                    CERTIFICATE_PATH.to_string(),
                ),
            ]),
            ..Default::default()
        };
        env.envs.extend(
            overrides
                .iter()
                .map(|&(name, value)| (name.to_string(), value.to_string())),
        );

        crate::test_context()
            .with_env(env)
            .with_file_read(CertificateFile(pem))
    }

    async fn assert_certificate_exchange(
        provider: impl ProvideCredential<Credential = Credential>,
        ctx: Context,
        endpoint: TokenEndpoint,
    ) {
        let credential = provider
            .provide_credential(&ctx.with_http_send(endpoint))
            .await
            .expect("certificate token exchange must succeed");
        assert!(
            matches!(credential, Some(Credential::BearerToken { token, .. }) if token == "mock-entra-token")
        );
    }

    fn modern_assertion_header() -> Value {
        json!({"alg": "PS256", "typ": "JWT", "x5t#S256": LEAF_SHA256_THUMBPRINT})
    }

    #[tokio::test]
    async fn default_assertion_uses_first_certificate_in_pem() {
        for pem in [
            [LEAF_PEM, RSA_PKCS8].concat(),
            [LEAF_PEM, RSA_PKCS8, ISSUER_PEM, ROOT_PEM].concat(),
        ] {
            assert_certificate_exchange(
                ClientCertificateCredentialProvider::new(),
                certificate_context(pem, &[]),
                TokenEndpoint {
                    expected_header: modern_assertion_header(),
                    expected_uri: PUBLIC_ENDPOINT,
                    expected_scope: "https://storage.azure.com/.default",
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn assertion_sends_ordered_pem_chain_only_when_enabled() {
        // PEM bodies are already standard base64 DER. Compare against the fixture
        // text directly to check the alphabet, padding, and order independently.
        let expected_chain = [LEAF_PEM, ISSUER_PEM, ROOT_PEM].map(|pem| {
            std::str::from_utf8(pem)
                .expect("fixture PEM must be UTF-8")
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>()
        });

        for (configured, env, send_chain) in [
            (Some(true), Some("false"), true),
            (Some(false), Some("true"), false),
            (None, Some("TrUe"), true),
            (None, Some("false"), false),
            (None, Some("1"), false),
        ] {
            let mut provider = ClientCertificateCredentialProvider::new();
            if let Some(value) = configured {
                provider = provider.with_send_certificate_chain(value);
            }
            let mut expected_header = modern_assertion_header();
            if send_chain {
                expected_header["x5c"] = json!(expected_chain);
            }
            let env = env.map(|value| ("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", value));
            assert_certificate_exchange(
                provider,
                certificate_context(
                    [LEAF_PEM, RSA_PKCS8, ISSUER_PEM, ROOT_PEM].concat(),
                    env.as_slice(),
                ),
                TokenEndpoint {
                    expected_header,
                    expected_uri: PUBLIC_ENDPOINT,
                    expected_scope: "https://storage.azure.com/.default",
                },
            )
            .await;
        }
    }

    #[tokio::test]
    async fn assertion_audience_matches_the_selected_token_endpoint() {
        use crate::DefaultCredentialProvider;

        let context = || {
            certificate_context(
                [LEAF_PEM, RSA_PKCS8].concat(),
                &[("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us/")],
            )
        };
        let endpoint = |expected_uri| TokenEndpoint {
            expected_header: modern_assertion_header(),
            expected_uri,
            expected_scope: TEST_SCOPE,
        };
        let provider = DefaultCredentialProvider::builder()
            .no_azure_cli()
            .with_scope(TEST_SCOPE)
            .unwrap()
            .build();
        assert_certificate_exchange(
            provider,
            context(),
            endpoint("https://login.microsoftonline.us/test-tenant/oauth2/v2.0/token"),
        )
        .await;

        let provider = ClientCertificateCredentialProvider::new()
            .with_scope(TEST_SCOPE)
            .with_authority_host("https://login.chinacloudapi.cn/");
        assert_certificate_exchange(
            provider,
            context(),
            endpoint("https://login.chinacloudapi.cn/test-tenant/oauth2/v2.0/token"),
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_pem_reports_credential_error_before_token_exchange() {
        let encrypted_key =
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let malformed_certificate =
            b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n";

        for (pem, message) in [
            (RSA_PKCS8.to_vec(), "PEM does not contain a certificate"),
            (
                [LEAF_PEM, encrypted_key].concat(),
                "PEM does not contain a private key",
            ),
            (malformed_certificate.to_vec(), "Failed to parse PEM:"),
            (vec![0xff], "Certificate file is not valid UTF-8:"),
        ] {
            let ctx = certificate_context(pem, &[("AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", "true")]);
            let error = ClientCertificateCredentialProvider::new()
                .provide_credential(&ctx)
                .await
                .expect_err("invalid PEM must fail before token exchange");
            assert_eq!(error.kind(), reqsign_core::ErrorKind::CredentialInvalid);
            assert!(error.to_string().starts_with(message), "{error}");
        }
    }

    #[derive(Debug, Default)]
    struct Rs256OnlyProvider(reqsign_crypto_rustcrypto::RustCryptoProvider);

    impl CryptoProvider for Rs256OnlyProvider {
        fn sha1(&self, input: &[u8]) -> reqsign_core::Result<[u8; 20]> {
            self.0.sha1(input)
        }

        fn sha256(&self, input: &[u8]) -> reqsign_core::Result<[u8; 32]> {
            self.0.sha256(input)
        }

        fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> reqsign_core::Result<[u8; 20]> {
            self.0.hmac_sha1(key, input)
        }

        fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> reqsign_core::Result<[u8; 32]> {
            self.0.hmac_sha256(key, input)
        }

        fn rsa_pkcs1v15_sha256_sign(
            &self,
            private_key_pem: &[u8],
            message: &[u8],
        ) -> reqsign_core::Result<Vec<u8>> {
            self.0.rsa_pkcs1v15_sha256_sign(private_key_pem, message)
        }
    }

    #[tokio::test]
    async fn rs256_only_provider_requires_explicit_legacy_selection() {
        let ctx = certificate_context([LEAF_PEM, RSA_PKCS8, ISSUER_PEM, ROOT_PEM].concat(), &[])
            .with_crypto(Rs256OnlyProvider::default());
        let provider = ClientCertificateCredentialProvider::new();
        let error = provider
            .provide_credential(&ctx)
            .await
            .expect_err("default assertions must fail before exchange without RSA-PSS");
        assert_eq!(error.kind(), reqsign_core::ErrorKind::ConfigInvalid);
        assert!(error.to_string().contains("does not support RSA-PSS"));

        assert_certificate_exchange(
            provider.with_legacy_rs256(),
            ctx,
            TokenEndpoint {
                expected_header: json!({"alg": "RS256", "typ": "JWT", "x5t": LEAF_SHA1_THUMBPRINT}),
                expected_uri: PUBLIC_ENDPOINT,
                expected_scope: "https://storage.azure.com/.default",
            },
        )
        .await;
    }

    #[test]
    fn legacy_client_assertion_matches_the_rs256_vector_for_both_pem_formats() {
        const RSA_PKCS1: &[u8] = include_bytes!("../../tests/fixtures/rsa_pkcs1.pem");
        // Fixed RS256 vector for the fixture key. The signature was cross-checked
        // with an independent RSA implementation before being recorded here.
        const EXPECTED_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6Ijcxd3N5NGxsS0l6dFZyd25qa0U5RGMyVDY4YyJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL3Rva2VuIiwiZXhwIjoxLCJpc3MiOiJjbGllbnQiLCJqdGkiOiJqdGkiLCJuYmYiOjAsInN1YiI6ImNsaWVudCJ9.XrtIVf1jpj4EdPs4uEKh_MpYwk3ItE8ggsRe5ra4uTt4sRPIiKoNjGxG4FEJ_3Olo61tOhiBAxabdvq4Wo0JMEsrH2npV558kds9TYnsBdYKTPrWyqmJLRHAgDS5HW7shbCclHyKYPJUGbPCDmW14lCjZMWDP0ClJ6KoQjnkiO8R5RbhnqadxpDxPGJajQ1TMvlh55b8uTl8nY9MRJKCbZzFoGeYZOOET-Xasw73XKIlm0vb-Ke-GXvJMtjsfseMP5hP8RIRb8eKFHppta8FiAVEF_GJjLx7CmsRgoHjkl5UqwA86VW4NBwNj32XeSoVXtHQGBvXK3SV4aKgR9PWBg";
        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let thumbprint = "71wsy4llKIztVrwnjkE9Dc2T68c";
        let header = ClientAssertionHeader {
            alg: ClientAssertionAlgorithm::Rs256,
            typ: "JWT",
            x5t: Some(thumbprint.to_string()),
            x5t_s256: None,
            x5c: None,
        };
        let claims = ClientAssertionClaims {
            aud: "https://example.com/token".to_string(),
            exp: 1,
            iss: "client".to_string(),
            jti: "jti".to_string(),
            nbf: 0,
            sub: "client".to_string(),
        };

        for pem in [RSA_PKCS8, RSA_PKCS1] {
            let jwt =
                ClientCertificateCredentialProvider::encode_jws(&provider, &header, &claims, pem)
                    .expect("JWT encoding must succeed");
            assert_eq!(jwt, EXPECTED_JWT);
            let parts = jwt.split('.').collect::<Vec<_>>();
            assert_eq!(parts.len(), 3);
            assert!(parts.iter().all(|part| !part.contains('=')));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(
                    &URL_SAFE_NO_PAD
                        .decode(parts[0])
                        .expect("header must decode")
                )
                .expect("header must be JSON"),
                serde_json::json!({"alg": "RS256", "typ": "JWT", "x5t": thumbprint})
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(
                    &URL_SAFE_NO_PAD
                        .decode(parts[1])
                        .expect("claims must decode")
                )
                .expect("claims must be JSON"),
                serde_json::json!({
                    "aud": "https://example.com/token",
                    "exp": 1,
                    "iss": "client",
                    "jti": "jti",
                    "nbf": 0,
                    "sub": "client"
                })
            );
        }
    }

    #[test]
    fn malformed_client_certificate_private_key_is_credential_invalid() {
        let crypto = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let err = ClientCertificateCredentialProvider::encode_jws(
            &crypto,
            &ClientAssertionHeader {
                alg: ClientAssertionAlgorithm::Ps256,
                typ: "JWT",
                x5t: None,
                x5t_s256: Some(LEAF_SHA256_THUMBPRINT.to_string()),
                x5c: None,
            },
            &ClientAssertionClaims {
                aud: "aud".to_string(),
                exp: 1,
                iss: "iss".to_string(),
                jti: "jti".to_string(),
                nbf: 0,
                sub: "sub".to_string(),
            },
            b"not a private key",
        )
        .expect_err("malformed key must fail");
        assert_eq!(err.kind(), reqsign_core::ErrorKind::CredentialInvalid);
    }

    #[test]
    fn test_provider_configuration() {
        let provider = ClientCertificateCredentialProvider::new()
            .with_tenant_id("test-tenant")
            .with_client_id("test-client")
            .with_certificate_path("/path/to/cert.pem");

        assert_eq!(provider.tenant_id, Some("test-tenant".to_string()));
        assert_eq!(provider.client_id, Some("test-client".to_string()));
        assert_eq!(
            provider.certificate_path,
            Some("/path/to/cert.pem".to_string())
        );
    }

    #[test]
    fn debug_redacts_certificate_password_as_opaque_for_all_lengths() {
        const TENANT_ID: &str = "synthetic-tenant-id";
        const CLIENT_ID: &str = "synthetic-client-id";
        const CERTIFICATE_PATH: &str = "/synthetic/certificate.pem";
        let expected = format!(
            "ClientCertificateCredentialProvider {{ tenant_id: Some(\"{TENANT_ID}\"), client_id: Some(\"{CLIENT_ID}\"), certificate_path: Some(\"{CERTIFICATE_PATH}\"), certificate_password: Some(\"{REDACTED}\") }}"
        );

        for certificate_password in [
            "synthetic-certificate-password-with-long-prefix-and-suffix",
            "short",
            "証明書のパスワード",
        ] {
            let provider = ClientCertificateCredentialProvider::new()
                .with_tenant_id(TENANT_ID)
                .with_client_id(CLIENT_ID)
                .with_certificate_path(CERTIFICATE_PATH)
                .with_certificate_password(certificate_password);

            assert_eq!(format!("{provider:?}"), expected);
        }
    }
}
