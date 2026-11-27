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

use std::fmt::Write;
use std::time::Duration;

use http::request::Parts;
use http::{HeaderValue, header};
use log::debug;
use reqsign_aws_core::Credential;
use reqsign_aws_core::signing::{
    SIGV4A_ALGORITHM as ALGORITHM, X_AMZ_REGION_SET, append_query_fragment, append_query_pairs,
    canonical_request_string_with_signed_headers, canonicalize_headers_with_standard_session_token,
    canonicalize_query, signed_header_names, validate_presign_lifetime, with_unsigned_uri,
};
use reqsign_core::crypto;
use reqsign_core::hash::{hex_sha256, hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential, SigningRequest};
use zeroize::Zeroizing;

use crate::{PercentEncodingMode, SigningRegionSet, UriPathNormalizationMode};

// P-256 group order minus two: the largest KDF output k0 for which k0 + 1
// remains a valid private scalar (k0 + 1 <= n - 1).
const P256_ORDER_MINUS_2: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
];
const CREDENTIAL_OPERATION_HEADROOM: Duration = Duration::from_secs(10);

/// Request signer implementing
/// [AWS Signature Version 4A](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).
///
/// Presigned query authentication writes `X-Amz-Expires` in whole seconds and
/// accepts 1 through 604800 seconds (seven days). Other encoded values return
/// `RequestInvalid` before changing the request.
///
/// Re-signing refreshes previous AWS authentication using its algorithm and
/// credential scope. Header cleanup recognizes a single complete AWS
/// `Authorization` value with exactly one `Credential`, `SignedHeaders`, and
/// nonempty `Signature`. `SignedHeaders` can be empty after explicit exclusions.
/// Multiple complete AWS values return `RequestInvalid`. Presigning keeps other
/// `Authorization` values and requires a complete field set to refresh existing
/// query authentication.
///
/// After presigning, an absent query and a bare `?` have the same wire form.
/// A single trailing `&` can likewise have the same wire form as the separator
/// added for signing. Keep the original URI if those bytes need to be recovered.
///
/// Switching from header signing to presigning keeps a present
/// `x-amz-content-sha256` header. A generated `UNSIGNED-PAYLOAD` value has
/// the same bytes as an explicit one. Use the original request when it is
/// necessary to presign without that header.
///
/// - [AWS authentication methods](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-authentication-methods.html)
#[derive(Debug)]
pub struct RequestSigner {
    service: String,
    region_set: SigningRegionSet,
    percent_encoding_mode: PercentEncodingMode,
    uri_path_normalization_mode: UriPathNormalizationMode,
    excluded_headers: Vec<String>,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a SigV4a request signer.
    pub fn new(service: &str, region_set: SigningRegionSet) -> Self {
        Self {
            service: service.to_string(),
            region_set,
            percent_encoding_mode: PercentEncodingMode::default(),
            uri_path_normalization_mode: UriPathNormalizationMode::default(),
            excluded_headers: Vec::new(),
            time: None,
        }
    }

    /// Set the canonical URI percent-encoding mode for header and query signing.
    ///
    /// The default is [`PercentEncodingMode::Single`] for every signing service,
    /// preserving Reqsign's existing canonical URI and signature bytes. Select
    /// [`PercentEncodingMode::Double`] explicitly when the service expects one
    /// additional encoding pass over the encoded path. Path normalization is
    /// configured separately with [`Self::with_uri_path_normalization_mode`].
    ///
    /// # Example
    ///
    /// ```
    /// use reqsign_aws_v4a::{PercentEncodingMode, RequestSigner, SigningRegionSet};
    ///
    /// let signer = RequestSigner::new("execute-api", SigningRegionSet::new("*")?)
    ///     .with_percent_encoding_mode(PercentEncodingMode::Double);
    /// # Ok::<(), reqsign_core::Error>(())
    /// ```
    pub fn with_percent_encoding_mode(mut self, mode: PercentEncodingMode) -> Self {
        self.percent_encoding_mode = mode;
        self
    }

    /// Set canonical URI path normalization for header signing and presigning.
    ///
    /// [`UriPathNormalizationMode::Disabled`] is the default for every service,
    /// including S3. [`UriPathNormalizationMode::Enabled`] resolves literal `.`
    /// and `..` segments and collapses repeated slashes before applying
    /// [`PercentEncodingMode`]. The outgoing path and existing query bytes are
    /// preserved.
    pub fn with_uri_path_normalization_mode(mut self, mode: UriPathNormalizationMode) -> Self {
        self.uri_path_normalization_mode = mode;
        self
    }

    /// Set additional headers to omit from canonical headers and `SignedHeaders`.
    ///
    /// The additional list defaults to empty. Header names match case-insensitively,
    /// and `Authorization` is always excluded. Excluded headers still go on the
    /// wire. Include any headers required by the target AWS service in the signature.
    pub fn with_excluded_headers(
        mut self,
        names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        self.excluded_headers = names
            .into_iter()
            .map(|name| name.as_ref().to_owned())
            .collect();
        self
    }

    /// Use a fixed signing timestamp for header signing and presigning.
    ///
    /// This signer reuses `time` for every request. The credential deadline
    /// is measured from `time` at full precision, while generated AWS dates
    /// use whole seconds in UTC. On first header signing, a supplied
    /// `x-amz-date` header must match the chosen signing time. Re-signing a
    /// request with AWS `Authorization` replaces the previous authentication
    /// headers, including the signing date.
    ///
    /// To compensate for clock skew, pass the caller's adjusted timestamp.
    /// Build a new request signer when the adjusted time changes.
    /// [`reqsign_core::Signer::with_request_signer`] can replace it while
    /// retaining the credential cache. Without a fixed timestamp, the signer
    /// reads [`Timestamp::now`] when signing. Credential discovery and cache
    /// freshness keep using their own clocks.
    pub fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    fn get_time(&self) -> Timestamp {
        self.time.unwrap_or_else(Timestamp::now)
    }

    fn required_valid_until_at(
        &self,
        signing_time: Timestamp,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        signing_time.saturating_add(expires_in.unwrap_or(CREDENTIAL_OPERATION_HEADROOM))
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        self.required_valid_until_at(self.get_time(), expires_in)
    }

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(credential) = credential else {
            return Ok(());
        };
        let crypto = ctx.crypto_provider()?;

        let now = self.get_time();
        let required_until = self.required_valid_until_at(now, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }
        validate_presign_lifetime(expires_in)?;

        with_unsigned_uri(req, expires_in.is_some(), |candidate| {
            self.sign_at(crypto, candidate, credential, expires_in, now)
        })
    }
}

impl RequestSigner {
    fn sign_at(
        &self,
        crypto: &dyn crypto::CryptoProvider,
        req: &mut Parts,
        credential: &Credential,
        expires_in: Option<Duration>,
        now: Timestamp,
    ) -> Result<()> {
        let original_uri = req.uri.clone();
        let mut signing_request = SigningRequest::build(req)?;
        canonicalize_headers_with_standard_session_token(
            &mut signing_request,
            credential,
            expires_in,
            now,
        )?;

        if expires_in.is_none() {
            let region_set = HeaderValue::from_str(self.region_set.as_str()).map_err(|e| {
                Error::request_invalid("AWS signing region set is not a valid header value")
                    .with_source(e)
            })?;
            signing_request.headers.insert(X_AMZ_REGION_SET, region_set);
        }

        let signed_headers = signed_header_names(&signing_request, &self.excluded_headers);
        let authentication_query = authentication_query(
            &signed_headers,
            credential,
            expires_in,
            now,
            &self.service,
            &self.region_set,
        );
        let canonical_query = canonicalize_query(&signing_request, &authentication_query);
        let canonical_request = canonical_request_string_with_signed_headers(
            &signing_request,
            &canonical_query,
            self.percent_encoding_mode,
            self.uri_path_normalization_mode,
            &signed_headers,
        )?;
        let encoded_request = hex_sha256(crypto, canonical_request.as_bytes())?;

        let scope = format!("{}/{}/aws4_request", now.format_date(), self.service);
        debug!("calculated scope: {scope}");

        let string_to_sign = string_to_sign(now, &scope, &encoded_request)?;
        debug!("calculated string to sign: {string_to_sign}");

        let signing_key = generate_signing_key(
            crypto,
            &credential.access_key_id,
            &credential.secret_access_key,
        )?;
        let signature = calculate_signature(crypto, &signing_key, string_to_sign.as_bytes())?;

        let final_uri = if expires_in.is_some() {
            let unsigned_uri = append_query_pairs(&original_uri, &authentication_query)?;
            Some(append_query_fragment(
                &unsigned_uri,
                &format!("X-Amz-Signature={signature}"),
            )?)
        } else {
            let mut authorization = HeaderValue::from_str(&format!(
                "{ALGORITHM} Credential={}/{scope}, SignedHeaders={}, Signature={signature}",
                credential.access_key_id,
                signed_headers.join(";"),
            ))
            .map_err(|e| {
                Error::unexpected(format!("failed to create authorization header: {e}"))
            })?;
            authorization.set_sensitive(true);
            signing_request
                .headers
                .insert(header::AUTHORIZATION, authorization);
            None
        };

        signing_request.apply(req)?;
        if let Some(uri) = final_uri {
            req.uri = uri;
        }
        Ok(())
    }
}

fn authentication_query(
    signed_headers: &[&str],
    credential: &Credential,
    expires_in: Option<Duration>,
    now: Timestamp,
    service: &str,
    region_set: &SigningRegionSet,
) -> Vec<(String, String)> {
    let Some(expires_in) = expires_in else {
        return Vec::new();
    };

    let mut query = vec![
        ("X-Amz-Algorithm".to_string(), ALGORITHM.to_string()),
        (
            "X-Amz-Credential".to_string(),
            format!(
                "{}/{}/{}/aws4_request",
                credential.access_key_id,
                now.format_date(),
                service
            ),
        ),
        ("X-Amz-Date".to_string(), now.format_iso8601()),
        (
            "X-Amz-Expires".to_string(),
            expires_in.as_secs().to_string(),
        ),
        (
            "X-Amz-Region-Set".to_string(),
            region_set.as_str().to_string(),
        ),
        ("X-Amz-SignedHeaders".to_string(), signed_headers.join(";")),
    ];

    if let Some(token) = &credential.session_token {
        query.push(("X-Amz-Security-Token".to_string(), token.clone()));
    }
    query
}

fn string_to_sign(now: Timestamp, scope: &str, encoded_request: &str) -> Result<String> {
    let mut output = String::with_capacity(160);
    writeln!(output, "{ALGORITHM}")
        .map_err(|e| Error::unexpected(format!("failed to write algorithm: {e}")))?;
    writeln!(output, "{}", now.format_iso8601())
        .map_err(|e| Error::unexpected(format!("failed to write timestamp: {e}")))?;
    writeln!(output, "{scope}")
        .map_err(|e| Error::unexpected(format!("failed to write scope: {e}")))?;
    write!(output, "{encoded_request}")
        .map_err(|e| Error::unexpected(format!("failed to write encoded request: {e}")))?;
    Ok(output)
}

fn calculate_signature(
    provider: &dyn crypto::CryptoProvider,
    signing_key: &[u8; 32],
    string_to_sign: &[u8],
) -> Result<String> {
    let signature = provider.ecdsa_p256_sha256_sign(signing_key, string_to_sign)?;
    Ok(hex::encode(signature))
}

fn generate_signing_key(
    provider: &dyn crypto::CryptoProvider,
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut input_key = Zeroizing::new(Vec::with_capacity(secret_access_key.len() + 5));
    input_key.extend_from_slice(b"AWS4A");
    input_key.extend_from_slice(secret_access_key.as_bytes());

    for counter in 1_u8..=254 {
        let mut input = Vec::with_capacity(ALGORITHM.len() + access_key_id.len() + 11);
        input.extend_from_slice(&1_u32.to_be_bytes());
        input.extend_from_slice(ALGORITHM.as_bytes());
        input.push(0);
        input.extend_from_slice(access_key_id.as_bytes());
        input.push(counter);
        input.extend_from_slice(&256_u32.to_be_bytes());

        let digest = Zeroizing::new(hmac_sha256(
            provider,
            input_key.as_slice(),
            input.as_slice(),
        )?);
        if digest.as_slice() > P256_ORDER_MINUS_2.as_slice() {
            continue;
        }

        let mut scalar = Zeroizing::new([0_u8; 32]);
        scalar.copy_from_slice(digest.as_slice());
        increment_big_endian(scalar.as_mut());
        return Ok(scalar);
    }

    Err(Error::unexpected(
        "failed to derive a valid SigV4a signing key",
    ))
}

fn increment_big_endian(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result as AnyResult;
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode as AwsPercentEncodingMode, SessionTokenMode,
        SignableBody, SignableRequest, SignatureLocation, SigningSettings,
        UriPathNormalizationMode as AwsUriPathNormalizationMode,
    };
    use aws_sigv4::sign::v4a;
    use http::Request;
    use pretty_assertions::assert_eq;
    use reqsign_core::crypto::CryptoProvider;
    use reqsign_core::{ErrorKind, Signer, StaticEnv};
    use std::sync::{Arc, Mutex};

    use crate::{PercentEncodingMode, SharedConfig, StaticCredentialProvider};

    // AWS CRT SigV4a get-vanilla test vector.
    const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
    const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const HEADER_STRING_TO_SIGN: &str = "AWS4-ECDSA-P256-SHA256\n20150830T123600Z\n20150830/service/aws4_request\ncf59db423e841c8b7e3444158185aa261b724a5c27cbe762676f3eed19f4dc02";
    const SIGNING_KEY_SCALAR: &str =
        "7efc8c0e65a324242818c5a50c891c6060b6a00717b7ba3cbe3c5d765be9259c";
    // A fixed DER signature for the published SigV4a signing input above.
    const SIGNATURE_DER_HEX: &str = "304502206c8e97f7ed2541ed924ade73b4acf7c40156ee796b1f57156c77319278c93042022100f933779aa3fcbd0279217cd671618552026d099cd2e1770225a5167ac5b6bcfd";
    const RAW_QUERY: &str =
        "slash=%2F&literal-plus=+&double=%252F&dup=first&dup=second&empty=&flag&";
    const ENCODING_QUERY: &str = "key=value&slash=%2F&empty=&dup=first&dup=second";
    const CANONICAL_ENCODING_QUERY: &str = "dup=first&dup=second&empty=&key=value&slash=%2F";

    fn credential() -> Credential {
        Credential {
            access_key_id: ACCESS_KEY_ID.to_string(),
            secret_access_key: SECRET_ACCESS_KEY.to_string(),
            ..Default::default()
        }
    }

    fn signer() -> RequestSigner {
        signer_for("service")
    }

    fn signer_for(service: &str) -> RequestSigner {
        RequestSigner::new(
            service,
            SigningRegionSet::new("us-east-1").expect("region set must be valid"),
        )
        .with_time(
            "2015-08-30T12:36:00Z"
                .parse()
                .expect("timestamp must be valid"),
        )
    }

    fn comparable_headers(request: &Request<()>) -> Vec<String> {
        let mut headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                let value = value.to_str().expect("header must be valid UTF-8");
                if name == header::AUTHORIZATION {
                    let (prefix, _) = value
                        .rsplit_once(", Signature=")
                        .expect("authorization must contain signature");
                    format!("{name}:{prefix}, Signature=<signature>")
                } else {
                    format!("{name}:{value}")
                }
            })
            .collect::<Vec<_>>();
        if !headers.iter().any(|value| value.starts_with("host:")) {
            headers.push(format!(
                "host:{}",
                request.uri().authority().expect("URI must have authority")
            ));
        }
        headers.sort();
        headers
    }

    fn comparable_query(request: &Request<()>) -> Vec<String> {
        let mut query =
            form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .map(|(key, value)| {
                    if key == "X-Amz-Signature" {
                        format!("{key}=<signature>")
                    } else {
                        format!("{key}={value}")
                    }
                })
                .collect::<Vec<_>>();
        query.sort();
        query
    }

    #[test]
    fn signing_key_matches_aws_crt_vector() -> AnyResult<()> {
        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let scalar = generate_signing_key(&provider, ACCESS_KEY_ID, SECRET_ACCESS_KEY)?;

        // The scalar uniquely determines the AWS CRT public key (x, y); this
        // fixed value is the KDF output for the published get-vanilla vector.
        assert_eq!(hex::encode(scalar.as_slice()), SIGNING_KEY_SCALAR);
        Ok(())
    }

    #[test]
    fn signature_input_and_der_hex_are_recorded() -> AnyResult<()> {
        let der = hex::decode(SIGNATURE_DER_HEX)?;
        let provider = RecordingProvider::returning(der.clone());
        let scalar = *generate_signing_key(
            &reqsign_crypto_rustcrypto::RustCryptoProvider::new(),
            ACCESS_KEY_ID,
            SECRET_ACCESS_KEY,
        )?;

        let signature = calculate_signature(&provider, &scalar, HEADER_STRING_TO_SIGN.as_bytes())?;

        assert_eq!(signature, SIGNATURE_DER_HEX);
        let calls = provider.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].scalar, scalar);
        assert_eq!(calls[0].message, HEADER_STRING_TO_SIGN.as_bytes());
        assert_eq!(calls[0].signature, der);
        Ok(())
    }

    #[derive(Clone, Debug)]
    struct EcdsaCall {
        scalar: [u8; 32],
        message: Vec<u8>,
        signature: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingProvider {
        calls: Arc<Mutex<Vec<EcdsaCall>>>,
        response: Option<Vec<u8>>,
    }

    impl RecordingProvider {
        fn new() -> Self {
            Self::default()
        }

        fn returning(signature: Vec<u8>) -> Self {
            Self {
                response: Some(signature),
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<EcdsaCall> {
            self.calls.lock().expect("lock poisoned").clone()
        }
    }

    impl CryptoProvider for RecordingProvider {
        fn sha1(&self, input: &[u8]) -> reqsign_core::Result<[u8; 20]> {
            reqsign_crypto_rustcrypto::RustCryptoProvider::new().sha1(input)
        }

        fn sha256(&self, input: &[u8]) -> reqsign_core::Result<[u8; 32]> {
            reqsign_crypto_rustcrypto::RustCryptoProvider::new().sha256(input)
        }

        fn hmac_sha1(&self, key: &[u8], input: &[u8]) -> reqsign_core::Result<[u8; 20]> {
            reqsign_crypto_rustcrypto::RustCryptoProvider::new().hmac_sha1(key, input)
        }

        fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> reqsign_core::Result<[u8; 32]> {
            reqsign_crypto_rustcrypto::RustCryptoProvider::new().hmac_sha256(key, input)
        }

        fn ecdsa_p256_sha256_sign(
            &self,
            private_key_scalar: &[u8; 32],
            message: &[u8],
        ) -> reqsign_core::Result<Vec<u8>> {
            let signature = match &self.response {
                Some(signature) => signature.clone(),
                None => reqsign_crypto_rustcrypto::RustCryptoProvider::new()
                    .ecdsa_p256_sha256_sign(private_key_scalar, message)?,
            };
            self.calls.lock().expect("lock poisoned").push(EcdsaCall {
                scalar: *private_key_scalar,
                message: message.to_vec(),
                signature: signature.clone(),
            });
            Ok(signature)
        }
    }

    #[tokio::test]
    async fn signs_headers_with_configured_region_set_and_regionless_scope() -> AnyResult<()> {
        let ctx = crate::test_context().with_env(StaticEnv {
            home_dir: None,
            envs: [(
                "AWS_SIGV4A_SIGNING_REGION_SET".into(),
                " eu-west-1, , us-west-2, ".into(),
            )]
            .into(),
        });
        let profile = SharedConfig::new().load(&ctx).await?;
        let value = profile
            .sigv4a_signing_region_set()
            .expect("the configured region set must be present");
        let request_signer = RequestSigner::new("service", SigningRegionSet::new(value)?)
            .with_time("2015-08-30T12:36:00Z".parse()?);
        let signer = Signer::new(
            ctx,
            StaticCredentialProvider::new(ACCESS_KEY_ID, SECRET_ACCESS_KEY),
            request_signer,
        );
        let mut parts = Request::get("https://example.amazonaws.com/")
            .body(())?
            .into_parts()
            .0;
        signer.sign(&mut parts, None).await?;

        assert_eq!(parts.headers[X_AMZ_REGION_SET], "eu-west-1,us-west-2");
        assert_eq!(parts.headers["x-amz-date"], "20150830T123600Z");
        let authorization = parts.headers[header::AUTHORIZATION].to_str()?;
        assert!(authorization.starts_with(
            "AWS4-ECDSA-P256-SHA256 Credential=AKIDEXAMPLE/20150830/service/aws4_request"
        ));
        assert!(
            authorization
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set")
        );
        assert!(!authorization.contains("/eu-west-1/service/"));
        Ok(())
    }

    #[tokio::test]
    async fn presigns_with_region_set_query() -> AnyResult<()> {
        let mut parts = Request::get("https://example.amazonaws.com/")
            .body(())?
            .into_parts()
            .0;
        signer()
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential()),
                Some(Duration::from_secs(3600)),
            )
            .await?;

        let query = parts.uri.query().expect("presigned request has query");
        assert!(query.contains("X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256"));
        assert!(query.contains("X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fservice%2Faws4_request"));
        assert!(query.contains("X-Amz-Region-Set=us-east-1"));
        assert!(query.contains("X-Amz-Signature="));
        assert!(!parts.headers.contains_key(X_AMZ_REGION_SET));
        Ok(())
    }

    fn assert_parts_unchanged(actual: &http::request::Parts, expected: &http::request::Parts) {
        assert_eq!(actual.method, expected.method);
        assert_eq!(actual.uri, expected.uri);
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.headers, expected.headers);
    }

    #[test]
    fn presign_deadline_saturates_for_duration_max() {
        let max = signer()
            .required_valid_until(&credential(), Some(Duration::ZERO))
            .saturating_add(Duration::MAX);

        assert_eq!(
            signer().required_valid_until(&credential(), Some(Duration::MAX)),
            max
        );
    }

    #[tokio::test]
    async fn presign_rejects_invalid_lifetimes_without_changing_the_request() -> AnyResult<()> {
        for expires_in in [
            Duration::from_millis(500),
            Duration::from_secs(604_801),
            Duration::MAX,
        ] {
            let mut parts = Request::get("https://example.amazonaws.com/")
                .body(())?
                .into_parts()
                .0;
            let original = parts.clone();

            let err = signer()
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential()),
                    Some(expires_in),
                )
                .await
                .expect_err("invalid presigned URL lifetime must be rejected");

            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
            assert_parts_unchanged(&parts, &original);
        }
        Ok(())
    }

    #[tokio::test]
    async fn presign_rejects_oversized_lifetime_after_credential_validation() -> AnyResult<()> {
        let now: Timestamp = "2015-08-30T12:36:00Z"
            .parse()
            .expect("timestamp must parse");
        let finite = Credential {
            expires_in: Some(now + Duration::from_secs(3600)),
            ..credential()
        };
        let mut parts = Request::get("https://example.amazonaws.com/")
            .body(())?
            .into_parts()
            .0;
        let original = parts.clone();

        let err = signer()
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&finite),
                Some(Duration::MAX),
            )
            .await
            .expect_err("a finite credential cannot cover an unbounded lifetime");

        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_parts_unchanged(&parts, &original);
        Ok(())
    }

    #[tokio::test]
    async fn presign_accepts_the_encoded_lifetime_boundaries() -> AnyResult<()> {
        for (expires_in, encoded_seconds) in [
            (Duration::from_secs(1), "1"),
            (
                Duration::from_secs(604_800) + Duration::from_millis(500),
                "604800",
            ),
        ] {
            let mut parts = Request::get("https://example.amazonaws.com/")
                .body(())?
                .into_parts()
                .0;

            signer()
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential()),
                    Some(expires_in),
                )
                .await?;

            let query = parts.uri.query().expect("presigned request has query");
            assert!(query.contains(&format!("X-Amz-Expires={encoded_seconds}")));
            assert!(query.contains("X-Amz-Signature="));
        }
        Ok(())
    }

    // Assemble the expected canonical request independently of the production
    // canonicalization helpers so a shared encoding bug cannot mask a regression.
    fn encoding_string_to_sign(canonical_path: &str, expires_in: Option<Duration>) -> String {
        let canonical_request = if let Some(expires_in) = expires_in {
            format!(
                "GET\n{canonical_path}\n\
                 X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256\
                 &X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fservice%2Faws4_request\
                 &X-Amz-Date=20150830T123600Z&X-Amz-Expires={}\
                 &X-Amz-Region-Set=us-east-1&X-Amz-SignedHeaders=host\
                 &{CANONICAL_ENCODING_QUERY}\n\
                 host:example.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD",
                expires_in.as_secs(),
            )
        } else {
            format!(
                "GET\n{canonical_path}\n{CANONICAL_ENCODING_QUERY}\n\
                 host:example.amazonaws.com\n\
                 x-amz-content-sha256:UNSIGNED-PAYLOAD\n\
                 x-amz-date:20150830T123600Z\n\
                 x-amz-region-set:us-east-1\n\n\
                 host;x-amz-content-sha256;x-amz-date;x-amz-region-set\nUNSIGNED-PAYLOAD"
            )
        };
        format!(
            "AWS4-ECDSA-P256-SHA256\n20150830T123600Z\n20150830/service/aws4_request\n{}",
            hex_sha256(
                &reqsign_crypto_rustcrypto::RustCryptoProvider::new(),
                canonical_request.as_bytes(),
            )
            .expect("SHA-256 must succeed"),
        )
    }

    fn request_signature(request: &Request<()>) -> AnyResult<String> {
        if let Some((_, signature)) =
            form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .find(|(key, _)| key == "X-Amz-Signature")
        {
            return Ok(signature.into_owned());
        }
        Ok(request.headers()[header::AUTHORIZATION]
            .to_str()?
            .rsplit_once(", Signature=")
            .expect("authorization must contain signature")
            .1
            .to_string())
    }

    fn sdk_signature(string_to_sign: &str) -> String {
        let signing_key = v4a::generate_signing_key(ACCESS_KEY_ID, SECRET_ACCESS_KEY);
        v4a::calculate_signature(signing_key, string_to_sign.as_bytes())
    }

    fn assert_signature_matches_sdk(request: &Request<()>, string_to_sign: &str) -> AnyResult<()> {
        assert_eq!(
            request_signature(request)?,
            sdk_signature(string_to_sign),
            "wire signature must match the AWS SDK signature for the independently assembled canonical request for {}",
            request.uri(),
        );
        Ok(())
    }

    fn verify_encoding_signature(
        request: &Request<()>,
        string_to_sign: &str,
        provider: &RecordingProvider,
    ) -> AnyResult<()> {
        let signature = request_signature(request)?;

        let calls = provider.calls();
        assert_eq!(calls.len(), 1, "one ECDSA call per signed request");
        let call = &calls[0];
        assert_eq!(hex::encode(call.scalar), SIGNING_KEY_SCALAR);
        assert_eq!(
            call.message,
            string_to_sign.as_bytes(),
            "signature input must match the independently assembled canonical request for {}",
            request.uri(),
        );
        assert_eq!(
            signature,
            hex::encode(&call.signature),
            "wire signature must be the provider's DER bytes as hex for {}",
            request.uri(),
        );
        assert_signature_matches_sdk(request, string_to_sign)?;
        Ok(())
    }

    fn sign_with_aws_sdk(
        mut request: Request<()>,
        mode: AwsPercentEncodingMode,
        normalization_mode: AwsUriPathNormalizationMode,
        expires_in: Option<Duration>,
        excluded_headers: &[&'static str],
    ) -> AnyResult<Request<()>> {
        let now: Timestamp = "2015-08-30T12:36:00Z".parse()?;
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = mode;
        settings.uri_path_normalization_mode = normalization_mode;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.session_token_mode = SessionTokenMode::Include;
        settings.excluded_headers = Some(
            std::iter::once("authorization")
                .chain(excluded_headers.iter().copied())
                .map(Into::into)
                .collect(),
        );
        settings.expires_in = expires_in;
        settings.signature_location = if expires_in.is_some() {
            SignatureLocation::QueryParams
        } else {
            SignatureLocation::Headers
        };

        let identity = Credentials::new(
            ACCESS_KEY_ID,
            SECRET_ACCESS_KEY,
            None,
            None,
            "hardcoded-credentials",
        )
        .into();
        let params = v4a::SigningParams::builder()
            .identity(&identity)
            .region_set("us-east-1")
            .name("service")
            .time(now.as_system_time())
            .settings(settings)
            .build()?;
        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                request.method().as_str(),
                request.uri().to_string(),
                request.headers().iter().map(|(name, value)| {
                    (
                        name.as_str(),
                        std::str::from_utf8(value.as_bytes()).expect("header must be valid UTF-8"),
                    )
                }),
                SignableBody::UnsignedPayload,
            )?,
            &params.into(),
        )?;
        output.into_parts().0.apply_to_request_http1x(&mut request);
        Ok(request)
    }

    #[tokio::test]
    async fn encoding_modes_match_aws_sdk_signatures() -> AnyResult<()> {
        // SDK Single preserves the wire path verbatim, so compare using already
        // canonical escapes. Reqsign's legacy decode/re-encode cases are below.
        for (path, double_path) in [
            ("/object", "/object"),
            ("/percent%25name", "/percent%2525name"),
            ("/slash%2Fname", "/slash%252Fname"),
            ("/space%20name", "/space%2520name"),
            ("/at%40name", "/at%2540name"),
            ("/equal%3Dname", "/equal%253Dname"),
            ("/unicode%E4%B8%AD", "/unicode%25E4%25B8%25AD"),
            ("//a/./b/../c/", "//a/./b/../c/"),
        ] {
            for (mode, sdk_mode, canonical_path) in [
                (
                    PercentEncodingMode::Single,
                    AwsPercentEncodingMode::Single,
                    path,
                ),
                (
                    PercentEncodingMode::Double,
                    AwsPercentEncodingMode::Double,
                    double_path,
                ),
            ] {
                for expires_in in [None, Some(Duration::from_secs(3600))] {
                    let uri = format!("https://example.amazonaws.com{path}?{ENCODING_QUERY}");
                    let request = Request::get(&uri).body(())?;
                    let expected = sign_with_aws_sdk(
                        request.clone(),
                        sdk_mode,
                        AwsUriPathNormalizationMode::Disabled,
                        expires_in,
                        &[],
                    )?;
                    let (mut parts, body) = request.into_parts();
                    let provider = RecordingProvider::new();
                    let request_signer = signer().with_percent_encoding_mode(mode);
                    request_signer
                        .sign_request(
                            &crate::test_context().with_crypto(provider.clone()),
                            &mut parts,
                            Some(&credential()),
                            expires_in,
                        )
                        .await?;
                    let actual = Request::from_parts(parts, body);
                    assert_eq!(comparable_headers(&actual), comparable_headers(&expected));
                    assert_eq!(comparable_query(&actual), comparable_query(&expected));
                    assert_eq!(actual.uri().path(), path);
                    if expires_in.is_some() {
                        assert!(
                            actual
                                .uri()
                                .query()
                                .expect("presigned request has query")
                                .starts_with(&format!("{ENCODING_QUERY}&"))
                        );
                    } else {
                        assert_eq!(actual.uri().to_string(), uri);
                    }

                    // Compare both signatures against the independently
                    // assembled canonical request, not just against each other.
                    let string_to_sign = encoding_string_to_sign(canonical_path, expires_in);
                    assert_signature_matches_sdk(&expected, &string_to_sign)?;
                    verify_encoding_signature(&actual, &string_to_sign, &provider)?;
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn normalized_path_signatures_match_aws_sdk() -> AnyResult<()> {
        let ctx = crate::test_context();
        let credential = credential();
        for (path, single_encoding_path) in [
            ("", None),
            ("/", None),
            ("//", None),
            ("/./..", None),
            ("/a//b/.", None),
            ("/a//b/..", None),
            ("/../a//./%2e/%2E%2e/x%2F.%2f/", Some("/a/./../x%2F.%2F/")),
        ] {
            let request = Request::get(format!(
                "https://example.amazonaws.com{path}?{ENCODING_QUERY}"
            ))
            .body(())?;
            for (encoding, sdk_encoding) in [
                (PercentEncodingMode::Single, AwsPercentEncodingMode::Single),
                (PercentEncodingMode::Double, AwsPercentEncodingMode::Double),
            ] {
                // Disable SDK normalization for the expected Reqsign Single
                // path, where percent-decoding has made the dot segments literal.
                let (sdk_path, sdk_normalization) = match (encoding, single_encoding_path) {
                    (PercentEncodingMode::Single, Some(path)) => {
                        (path, AwsUriPathNormalizationMode::Disabled)
                    }
                    _ => (path, AwsUriPathNormalizationMode::Enabled),
                };
                let sdk_request = Request::get(format!(
                    "https://example.amazonaws.com{sdk_path}?{ENCODING_QUERY}"
                ))
                .body(())?;
                let signer = signer()
                    .with_percent_encoding_mode(encoding)
                    .with_uri_path_normalization_mode(UriPathNormalizationMode::Enabled);
                for expires_in in [None, Some(Duration::from_secs(3600))] {
                    let expected = sign_with_aws_sdk(
                        sdk_request.clone(),
                        sdk_encoding,
                        sdk_normalization,
                        expires_in,
                        &[],
                    )?;
                    let (mut parts, body) = request.clone().into_parts();
                    signer
                        .sign_request(&ctx, &mut parts, Some(&credential), expires_in)
                        .await?;
                    let actual = Request::from_parts(parts, body);
                    let name = format!("{encoding:?}, expires_in={expires_in:?}, path={path:?}");
                    assert_eq!(
                        request_signature(&actual)?,
                        request_signature(&expected)?,
                        "{name}"
                    );
                    if expires_in.is_some() {
                        let wire_prefix = format!("{}&", request.uri());
                        assert!(actual.uri().to_string().starts_with(&wire_prefix), "{name}");
                    } else {
                        assert_eq!(
                            actual.uri().to_string(),
                            request.uri().to_string(),
                            "{name}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn encoding_modes_preserve_their_path_semantics() -> AnyResult<()> {
        for (mode, path, canonical_path) in [
            (
                PercentEncodingMode::Single,
                "/raw@/a=b/%7E/%2f",
                "/raw%40/a%3Db/~/%2F",
            ),
            (
                PercentEncodingMode::Double,
                "/raw@/a=b/%7E/%2f/%FF//a/./b/../",
                "/raw%40/a%3Db/%257E/%252f/%25FF//a/./b/../",
            ),
        ] {
            for expires_in in [None, Some(Duration::from_secs(3600))] {
                let uri = format!("https://example.amazonaws.com{path}?{ENCODING_QUERY}");
                let (mut parts, body) = Request::get(&uri).body(())?.into_parts();
                let provider = RecordingProvider::new();
                let request_signer = signer().with_percent_encoding_mode(mode);
                request_signer
                    .sign_request(
                        &crate::test_context().with_crypto(provider.clone()),
                        &mut parts,
                        Some(&credential()),
                        expires_in,
                    )
                    .await?;
                let actual = Request::from_parts(parts, body);
                assert_eq!(actual.uri().path(), path);
                if expires_in.is_some() {
                    assert!(
                        actual
                            .uri()
                            .query()
                            .expect("presigned request has query")
                            .starts_with(&format!("{ENCODING_QUERY}&"))
                    );
                } else {
                    assert_eq!(actual.uri().to_string(), uri);
                }
                verify_encoding_signature(
                    &actual,
                    &encoding_string_to_sign(canonical_path, expires_in),
                    &provider,
                )?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn default_encoding_mode_is_single_for_every_service() -> AnyResult<()> {
        let uri = format!("https://example.amazonaws.com/object%2Fname?{ENCODING_QUERY}");
        for service in ["s3", "s3express", "service", "execute-api"] {
            for expires_in in [None, Some(Duration::from_secs(3600))] {
                let (mut parts, body) = Request::get(&uri).body(())?.into_parts();
                signer_for(service)
                    .sign_request(
                        &crate::test_context(),
                        &mut parts,
                        Some(&credential()),
                        expires_in,
                    )
                    .await?;
                let default = Request::from_parts(parts, body);

                let (mut parts, body) = Request::get(&uri).body(())?.into_parts();
                signer_for(service)
                    .with_percent_encoding_mode(PercentEncodingMode::Single)
                    .sign_request(
                        &crate::test_context(),
                        &mut parts,
                        Some(&credential()),
                        expires_in,
                    )
                    .await?;
                let single = Request::from_parts(parts, body);

                let (mut parts, body) = Request::get(&uri).body(())?.into_parts();
                signer_for(service)
                    .with_percent_encoding_mode(PercentEncodingMode::Double)
                    .sign_request(
                        &crate::test_context(),
                        &mut parts,
                        Some(&credential()),
                        expires_in,
                    )
                    .await?;
                let double = Request::from_parts(parts, body);

                assert_eq!(
                    comparable_headers(&default),
                    comparable_headers(&single),
                    "{service} should default to Single"
                );
                assert_eq!(
                    default.uri(),
                    single.uri(),
                    "{service} should default to Single"
                );
                assert_eq!(default.uri().path(), "/object%2Fname");
                if expires_in.is_some() {
                    assert!(
                        default
                            .uri()
                            .to_string()
                            .starts_with(&format!("{uri}&X-Amz-Algorithm="))
                    );
                    assert_ne!(
                        default.uri(),
                        double.uri(),
                        "{service} should only use Double when requested"
                    );
                } else {
                    assert_eq!(default.uri().to_string(), uri);
                    assert_eq!(
                        default.headers()[header::AUTHORIZATION],
                        single.headers()[header::AUTHORIZATION],
                        "{service} should default to Single"
                    );
                    assert_ne!(
                        default.headers()[header::AUTHORIZATION],
                        double.headers()[header::AUTHORIZATION],
                        "{service} should only use Double when requested"
                    );
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn excluded_headers_match_aws_sdk_signatures() -> AnyResult<()> {
        let signer = signer().with_excluded_headers(["UsEr-AgEnT", "X-AmZn-TrAcE-Id"]);
        let request = Request::get("https://example.com/object")
            .header(header::HOST, "example.com")
            .header(header::AUTHORIZATION, "Bearer fixture-token")
            .header(header::USER_AGENT, "  first    agent  ")
            .header(header::USER_AGENT, "second agent")
            .header("x-amzn-trace-id", "fixture-trace")
            .header("x-meta", "still signed")
            .body(())?;

        for expires_in in [None, Some(Duration::from_secs(60))] {
            let expected = sign_with_aws_sdk(
                request.clone(),
                AwsPercentEncodingMode::Single,
                AwsUriPathNormalizationMode::Disabled,
                expires_in,
                &["user-agent", "x-amzn-trace-id"],
            )?;
            let (mut parts, body) = request.clone().into_parts();
            signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential()),
                    expires_in,
                )
                .await?;
            let actual = Request::from_parts(parts, body);
            assert_eq!(actual.headers(), expected.headers());
            assert_eq!(comparable_query(&actual), comparable_query(&expected));
            assert_eq!(request_signature(&actual)?, request_signature(&expected)?);
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonical_headers_match_aws_sdk_signatures() -> AnyResult<()> {
        let signer = signer();
        let credential = credential();
        let ctx = crate::test_context();

        for (endpoint, supplied_host, expected_host) in [
            ("http://example.com:80", None, "example.com"),
            ("https://example.com:443", None, "example.com"),
            ("http://example.com:443", None, "example.com:443"),
            ("https://example.com:80", None, "example.com:80"),
            ("https://[2001:db8::1]:443", None, "[2001:db8::1]"),
            ("https://[2001:db8::1]:8443", None, "[2001:db8::1]:8443"),
            (
                "https://example.com:443",
                Some("[2001:db8::2]:443"),
                "[2001:db8::2]:443",
            ),
        ] {
            let uri = format!("{endpoint}/object%2Fname?z=%2f&dup=two&dup=one");
            let mut builder = Request::get(&uri)
                .header(header::USER_AGENT, "fixture-agent")
                .header("x-meta", "  z   word  ")
                .header("x-meta", "  \ta   word\t  ");
            if let Some(host) = supplied_host {
                builder = builder.header(header::HOST, host);
            }
            let original = builder.body(())?;

            for expires_in in [None, Some(Duration::from_secs(60))] {
                let mut expected = sign_with_aws_sdk(
                    original.clone(),
                    AwsPercentEncodingMode::Single,
                    AwsUriPathNormalizationMode::Disabled,
                    expires_in,
                    &[],
                )?;
                // The SDK synthesizes Host internally and only returns authentication fields.
                expected
                    .headers_mut()
                    .entry(header::HOST)
                    .or_insert(HeaderValue::from_static(expected_host));
                let (mut parts, body) = original.clone().into_parts();
                signer
                    .sign_request(&ctx, &mut parts, Some(&credential), expires_in)
                    .await?;
                let actual = Request::from_parts(parts, body);

                assert_eq!(
                    actual.headers(),
                    expected.headers(),
                    "{uri}, expiry={expires_in:?}"
                );
                if expires_in.is_some() {
                    assert!(
                        actual
                            .uri()
                            .to_string()
                            .starts_with(&format!("{uri}&X-Amz-Algorithm="))
                    );
                    assert_eq!(
                        comparable_query(&actual),
                        comparable_query(&expected),
                        "{uri}"
                    );
                    assert_eq!(
                        request_signature(&actual)?,
                        request_signature(&expected)?,
                        "{uri}"
                    );
                } else {
                    assert_eq!(actual.uri().to_string(), uri);
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonical_headers_reject_opaque_repeated_values_atomically() -> AnyResult<()> {
        let original = Request::get("https://example.com:443/object%2Fname?raw=%2f")
            .header("x-meta", "valid first value")
            .header("x-meta", HeaderValue::from_bytes(b"\xff")?)
            .extension("original extension")
            .body(())?
            .into_parts()
            .0;
        let signer = signer();
        let credential = credential();
        let ctx = crate::test_context();

        for expires_in in [None, Some(Duration::from_secs(60))] {
            let mut parts = original.clone();
            let error = signer
                .sign_request(&ctx, &mut parts, Some(&credential), expires_in)
                .await
                .expect_err("every signed header value must be valid text");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
            assert_parts_unchanged(&parts, &original);
            assert_eq!(parts.extensions.get::<&str>(), Some(&"original extension"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn preserves_existing_wire_query_in_both_encoding_modes() -> AnyResult<()> {
        let original_uri = format!("https://example.amazonaws.com/object%2Fname?{RAW_QUERY}");
        for mode in [PercentEncodingMode::Single, PercentEncodingMode::Double] {
            for expires_in in [None, Some(Duration::from_secs(60))] {
                let mut parts = Request::get(&original_uri).body(())?.into_parts().0;
                signer()
                    .with_percent_encoding_mode(mode)
                    .sign_request(
                        &crate::test_context(),
                        &mut parts,
                        Some(&credential()),
                        expires_in,
                    )
                    .await?;
                assert_eq!(parts.uri.path(), "/object%2Fname");
                if expires_in.is_some() {
                    assert!(
                        parts
                            .uri
                            .to_string()
                            .starts_with(&format!("{original_uri}X-Amz-Algorithm="))
                    );
                } else {
                    assert_eq!(parts.uri.to_string(), original_uri);
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn error_does_not_mutate_request() -> AnyResult<()> {
        let mut parts = Request::get("https://example.amazonaws.com/")
            .header("x-original", "value")
            .body(())?
            .into_parts()
            .0;
        let original_uri = parts.uri.clone();
        let original_headers = parts.headers.clone();
        let expired = Credential {
            expires_in: Some(
                "2015-08-30T12:36:00Z"
                    .parse()
                    .expect("timestamp must be valid"),
            ),
            ..credential()
        };

        let error = signer()
            .sign_request(&crate::test_context(), &mut parts, Some(&expired), None)
            .await
            .expect_err("expired credential must fail");

        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(parts.uri, original_uri);
        assert_eq!(parts.headers, original_headers);
        Ok(())
    }
}
