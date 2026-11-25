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
    EntraTokenResponse, parse_token_response, token_request_error,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, ProvideCredential, hash};
use serde::Serialize;

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

/// ClientCertificateCredentialProvider provides credentials using a client certificate
#[derive(Clone, Debug)]
pub struct ClientCertificateCredentialProvider {
    tenant_id: Option<String>,
    client_id: Option<String>,
    certificate_path: Option<String>,
    certificate_password: Option<String>,
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

    /// Set the certificate password (for PFX files)
    pub fn with_certificate_password(mut self, password: &str) -> Self {
        self.certificate_password = Some(password.to_string());
        self
    }

    /// Load certificate and private key from file
    async fn load_certificate(
        &self,
        ctx: &Context,
        path: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), reqsign_core::Error> {
        let cert_data = ctx.file_read(path).await.map_err(|e| {
            reqsign_core::Error::credential_invalid(format!("Failed to read certificate file: {e}"))
        })?;

        // For now, we'll support PEM format. PFX support can be added later
        let pem_str = String::from_utf8(cert_data.clone()).map_err(|e| {
            reqsign_core::Error::credential_invalid(format!(
                "Certificate file is not valid UTF-8: {e}"
            ))
        })?;

        // Parse all PEM blocks
        let pems = pem::parse_many(&pem_str).map_err(|e| {
            reqsign_core::Error::credential_invalid(format!("Failed to parse PEM: {e}"))
        })?;

        // Find certificate and private key
        let mut cert_der = None;
        let mut private_key_pem = None;

        for pem_block in &pems {
            match pem_block.tag() {
                "CERTIFICATE" => {
                    cert_der = Some(pem_block.contents().to_vec());
                }
                "PRIVATE KEY" | "RSA PRIVATE KEY" => {
                    private_key_pem = Some(pem::encode(pem_block));
                }
                _ => {}
            }
        }

        let cert_der = cert_der.ok_or_else(|| {
            reqsign_core::Error::credential_invalid("PEM does not contain a certificate")
        })?;

        let private_key_pem = private_key_pem.ok_or_else(|| {
            reqsign_core::Error::credential_invalid("PEM does not contain a private key")
        })?;

        Ok((cert_der, private_key_pem.into_bytes()))
    }

    /// Format a JWS compact JWT using RS256 and the selected provider.
    fn encode_rs256_jws<H, C>(
        provider: &dyn CryptoProvider,
        header: &H,
        claims: &C,
        private_key_pem: &[u8],
    ) -> Result<String, reqsign_core::Error>
    where
        H: Serialize,
        C: Serialize,
    {
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize JWT JSON").with_source(e)
        })?);
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialize JWT JSON").with_source(e)
        })?);
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature =
            provider.rsa_pkcs1v15_sha256_sign(private_key_pem, signing_input.as_bytes())?;

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    /// Calculate certificate thumbprint (x5t)
    /// Azure AD expects SHA1 thumbprint for x5t field
    fn calculate_thumbprint(
        &self,
        provider: &dyn CryptoProvider,
        cert_der: &[u8],
    ) -> Result<String, reqsign_core::Error> {
        Ok(URL_SAFE_NO_PAD.encode(hash::sha1(provider, cert_der)?))
    }

    /// Create JWT client assertion
    fn create_client_assertion(
        &self,
        provider: &dyn CryptoProvider,
        tenant_id: &str,
        client_id: &str,
        cert_der: &[u8],
        private_key_pem: &[u8],
    ) -> Result<String, reqsign_core::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                reqsign_core::Error::unexpected(format!("Failed to get current time: {e}"))
            })?
            .as_secs();

        let claims = ClientAssertionClaims {
            aud: format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
            exp: now + 600, // 10 minutes
            iss: client_id.to_string(),
            jti: generate_jti(now),
            nbf: now,
            sub: client_id.to_string(),
        };

        let header = ClientAssertionHeader {
            alg: "RS256",
            typ: "JWT",
            x5t: self.calculate_thumbprint(provider, cert_der)?,
        };

        Self::encode_rs256_jws(provider, &header, &claims, private_key_pem)
    }

    /// Exchange client assertion for access token
    async fn exchange_token(
        &self,
        ctx: &Context,
        tenant_id: &str,
        client_id: &str,
        client_assertion: &str,
    ) -> Result<EntraTokenResponse, reqsign_core::Error> {
        let url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");

        let mut params = HashMap::new();
        params.insert("scope", "https://storage.azure.com/.default");
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
            .uri(url)
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

#[derive(Debug, Serialize)]
struct ClientAssertionClaims {
    aud: String,
    exp: u64,
    iss: String,
    jti: String,
    nbf: u64,
    sub: String,
}

#[derive(Debug, Serialize)]
struct ClientAssertionHeader {
    alg: &'static str,
    typ: &'static str,
    x5t: String,
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

        let provider = ctx.crypto_provider()?;

        // Load certificate and private key
        let (cert_der, private_key_pem) = self.load_certificate(ctx, &certificate_path).await?;

        // Create client assertion
        let client_assertion = self.create_client_assertion(
            provider,
            &tenant_id,
            &client_id,
            &cert_der,
            &private_key_pem,
        )?;

        // Exchange for access token
        let token_response = self
            .exchange_token(ctx, &tenant_id, &client_id, &client_assertion)
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

    #[test]
    fn test_calculate_thumbprint() {
        // Test certificate DER (simplified example)
        let cert_der = b"test certificate";
        let provider = ClientCertificateCredentialProvider::new();
        let crypto = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let thumbprint = provider
            .calculate_thumbprint(&crypto, cert_der)
            .expect("thumbprint calculation must succeed");

        // Should produce a valid base64url encoded hash
        assert!(!thumbprint.is_empty());
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));
        assert!(!thumbprint.contains('='));
    }

    #[test]
    fn client_assertion_is_three_unpadded_verifiable_segments_for_both_pem_formats() {
        const RSA_PKCS8: &[u8] = include_bytes!("../../tests/fixtures/rsa_pkcs8.pem");
        const RSA_PKCS1: &[u8] = include_bytes!("../../tests/fixtures/rsa_pkcs1.pem");
        // Fixed RS256 vector for the fixture key. The signature was cross-checked
        // with an independent RSA implementation before being recorded here.
        const EXPECTED_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6Ijcxd3N5NGxsS0l6dFZyd25qa0U5RGMyVDY4YyJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL3Rva2VuIiwiZXhwIjoxLCJpc3MiOiJjbGllbnQiLCJqdGkiOiJqdGkiLCJuYmYiOjAsInN1YiI6ImNsaWVudCJ9.XrtIVf1jpj4EdPs4uEKh_MpYwk3ItE8ggsRe5ra4uTt4sRPIiKoNjGxG4FEJ_3Olo61tOhiBAxabdvq4Wo0JMEsrH2npV558kds9TYnsBdYKTPrWyqmJLRHAgDS5HW7shbCclHyKYPJUGbPCDmW14lCjZMWDP0ClJ6KoQjnkiO8R5RbhnqadxpDxPGJajQ1TMvlh55b8uTl8nY9MRJKCbZzFoGeYZOOET-Xasw73XKIlm0vb-Ke-GXvJMtjsfseMP5hP8RIRb8eKFHppta8FiAVEF_GJjLx7CmsRgoHjkl5UqwA86VW4NBwNj32XeSoVXtHQGBvXK3SV4aKgR9PWBg";
        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let certificate_provider = ClientCertificateCredentialProvider::new();
        let cert_der = b"test certificate";
        let thumbprint = certificate_provider
            .calculate_thumbprint(&provider, cert_der)
            .expect("thumbprint calculation must succeed");
        let header = ClientAssertionHeader {
            alg: "RS256",
            typ: "JWT",
            x5t: thumbprint.clone(),
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
            let jwt = ClientCertificateCredentialProvider::encode_rs256_jws(
                &provider, &header, &claims, pem,
            )
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
        let err = ClientCertificateCredentialProvider::encode_rs256_jws(
            &crypto,
            &ClientAssertionHeader {
                alg: "RS256",
                typ: "JWT",
                x5t: "thumbprint".to_string(),
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
}
