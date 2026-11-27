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

use crate::{Credential, PercentEncodingMode};
use http::request::Parts;
use reqsign_aws_core::signing::{SigV4SigningOptions, sign_request_parts};
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Result, SignRequest};
use std::time::Duration;

const CREDENTIAL_OPERATION_HEADROOM: Duration = Duration::from_secs(10);

/// RequestSigner that implements AWS SigV4.
///
/// - [Signature Version 4 signing process](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
///
/// Presigned query authentication writes `X-Amz-Expires` in whole seconds and
/// accepts 1 through 604800 seconds (seven days). Other encoded values return
/// `RequestInvalid` before changing the request.
///
/// Re-signing refreshes previous AWS authentication using its algorithm and
/// credential scope. Query cleanup requires a complete presign field set.
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
///
/// # Payload signing
///
/// The signer receives an `http::request::Parts` and does not read the body.
/// The caller owns the body and may stream it, so hashing it here would require
/// buffering the whole body or implementing a streaming signature. If
/// `x-amz-content-sha256` is present, its value is preserved and used as the
/// SigV4 payload hash. Otherwise, header signing adds
/// `x-amz-content-sha256: UNSIGNED-PAYLOAD`, including for an empty body.
/// Presigning does not add the header, but canonicalizes the missing header as
/// `UNSIGNED-PAYLOAD`.
///
/// `UNSIGNED-PAYLOAD` is an Amazon S3 payload mode, and the signer uses the
/// same default for every service name. Other AWS services define their own
/// payload requirements, and some require the actual payload hash. Check the
/// [AWS SigV4 documentation] and the service API reference when an endpoint
/// requires a signed payload.
///
/// To sign the actual payload, set the header before signing to the lowercase
/// hex SHA-256 of the exact transmitted bytes. Use [`EMPTY_STRING_SHA256`] for
/// an empty body; its value is the SHA-256 of the empty string,
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Use
/// [`reqsign_core::hash::hex_sha256`] for non-empty bytes. Hash after content
/// encoding or compression, and do not change the payload after signing.
/// Chunked or streaming payload signatures are not implemented.
///
/// The SigV4 signature covers the method, URI, signed headers, and declared
/// payload hash; it does not encrypt the body or replace TLS, and the HTTP
/// client owns transport security. It is not an S3 upload checksum. S3's
/// `Content-MD5` and `x-amz-checksum-*` headers are separate integrity checks:
/// their values are Base64 encoded, and their support depends on the operation,
/// bucket type, and transfer mode. `RequestSigner` does not add those headers.
/// See the [S3 upload integrity guide] for the operation-specific rules.
///
/// ```
/// use reqsign_aws_v4::EMPTY_STRING_SHA256;
/// use reqsign_core::hash::hex_sha256;
///
/// let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
/// let body: &[u8] = b"Hello, World!";
/// let payload_hash = if body.is_empty() {
///     EMPTY_STRING_SHA256.to_string()
/// } else {
///     hex_sha256(&provider, body).expect("SHA-256 must succeed")
/// };
///
/// let request = http::Request::put("https://s3.amazonaws.com/mybucket/hello.txt")
///     .header("x-amz-content-sha256", payload_hash)
///     .body(body)
///     .expect("request must be valid");
///
/// let empty_request = http::Request::put("https://s3.amazonaws.com/mybucket/empty.txt")
///     .header("x-amz-content-sha256", EMPTY_STRING_SHA256)
///     .body(())
///     .expect("request must be valid");
/// # let _ = (request, empty_request);
/// ```
///
/// If the header is set before presigning, it is included in
/// `X-Amz-SignedHeaders`, and the caller must send the same header with the
/// presigned request.
///
/// [AWS SigV4 documentation]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
/// [S3 upload integrity guide]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
/// [`EMPTY_STRING_SHA256`]: crate::EMPTY_STRING_SHA256
#[derive(Debug)]
pub struct RequestSigner {
    service: String,
    region: String,
    percent_encoding_mode: PercentEncodingMode,
    use_standard_session_token: bool,
    excluded_headers: Vec<String>,

    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a new builder for AWS V4 signer.
    pub fn new(service: &str, region: &str) -> Self {
        Self {
            service: service.into(),
            region: region.into(),
            percent_encoding_mode: PercentEncodingMode::default(),
            use_standard_session_token: false,
            excluded_headers: Vec::new(),

            time: None,
        }
    }

    /// Use the standard AWS session-token representation.
    ///
    /// This mode is required when an S3 Express request is authenticated with
    /// temporary IAM or STS credentials. Header authentication uses
    /// `x-amz-security-token`, and query authentication uses
    /// `X-Amz-Security-Token`.
    ///
    /// By default, requests signed with the `s3express` service use the
    /// [`CreateSession`] credential representation for any request authority:
    /// `x-amz-s3session-token` for header authentication and
    /// `X-Amz-S3session-Token` for query authentication. Other AWS signing
    /// services use the standard representation. The S3 Express [`CopyObject`],
    /// [`HeadBucket`], and [`UploadPartCopy`] operations require IAM
    /// credentials instead of CreateSession credentials.
    ///
    /// This setting only selects how an existing [`Credential`] session token
    /// is represented. It does not modify the credential or load a different
    /// credential source.
    ///
    /// # Example
    ///
    /// ```
    /// use reqsign_aws_v4::RequestSigner;
    ///
    /// let signer = RequestSigner::new("s3express", "us-west-2")
    ///     .with_standard_session_token();
    /// ```
    ///
    /// [`CopyObject`]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
    /// [`CreateSession`]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateSession.html
    /// [`HeadBucket`]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
    /// [`UploadPartCopy`]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html
    pub fn with_standard_session_token(mut self) -> Self {
        self.use_standard_session_token = true;
        self
    }

    /// Set the canonical URI percent-encoding mode for header and query signing.
    ///
    /// The default is [`PercentEncodingMode::Single`] for every signing service,
    /// preserving Reqsign's existing canonical URI and signature bytes. Select
    /// [`PercentEncodingMode::Double`] explicitly when the service expects one
    /// additional encoding pass over the wire path. This does not modify the
    /// outgoing URI, normalize paths, or change payload hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use reqsign_aws_v4::{PercentEncodingMode, RequestSigner};
    ///
    /// let signer = RequestSigner::new("execute-api", "us-east-1")
    ///     .with_percent_encoding_mode(PercentEncodingMode::Double);
    /// ```
    pub fn with_percent_encoding_mode(mut self, mode: PercentEncodingMode) -> Self {
        self.percent_encoding_mode = mode;
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

    fn uses_s3_express_session_token(&self) -> bool {
        self.service == "s3express" && !self.use_standard_session_token
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

        sign_request_parts(
            crypto,
            req,
            credential,
            expires_in,
            self.get_time(),
            SigV4SigningOptions {
                service: &self.service,
                region: &self.region,
                percent_encoding_mode: self.percent_encoding_mode,
                uses_s3_express_session_token: self.uses_s3_express_session_token(),
                excluded_headers: &self.excluded_headers,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PercentEncodingMode, StaticCredentialProvider};
    use anyhow::Result;
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::PayloadChecksumKind;
    use aws_sigv4::http_request::PercentEncodingMode as AwsPercentEncodingMode;
    use aws_sigv4::http_request::SessionTokenMode;
    use aws_sigv4::http_request::SignableBody;
    use aws_sigv4::http_request::SignableRequest;
    use aws_sigv4::http_request::SignatureLocation;
    use aws_sigv4::http_request::SigningSettings;
    use aws_sigv4::http_request::UriPathNormalizationMode;
    use aws_sigv4::sign::v4;
    use http::HeaderValue;
    use http::Request;
    use http::header;
    use reqsign_aws_core::constants::{
        X_AMZ_CONTENT_SHA_256, X_AMZ_S3_SESSION_TOKEN, X_AMZ_SECURITY_TOKEN,
    };
    use reqsign_aws_core::signing::{
        canonical_request_string, canonical_uri, canonicalize_query, canonicalize_signing_headers,
        signed_header_names, sigv4_authentication_query,
    };
    use reqsign_core::hash::hex_sha256;
    use reqsign_core::{ErrorKind, ProvideCredential, Signer, SigningRequest};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const RAW_QUERY: &str = "slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";
    const S3_EXPRESS_URI: &str =
        "https://bucket--use2-az1--x-s3.s3express-use2-az1.us-east-2.amazonaws.com/object";
    const CUSTOM_AUTHORITY_URI: &str = "https://objects.example.com/object";
    const S3_EXPRESS_REGION: &str = "us-east-2";
    const TEST_ACCESS_KEY: &str = "AKIDEXAMPLE";
    const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const TEST_SESSION_TOKEN: &str = "test-session-token";

    fn s3_express_credential(now: Timestamp) -> Credential {
        Credential {
            access_key_id: TEST_ACCESS_KEY.to_string(),
            secret_access_key: TEST_SECRET_KEY.to_string(),
            session_token: Some(TEST_SESSION_TOKEN.to_string()),
            expires_in: Some(now + Duration::from_secs(3600)),
        }
    }

    fn aws_signed_s3_express_request(
        mut request: Request<&'static str>,
        now: Timestamp,
        presigned: bool,
        session_token_name_override: Option<&'static str>,
    ) -> Result<Request<&'static str>> {
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = AwsPercentEncodingMode::Double;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.session_token_name_override = session_token_name_override;
        if presigned {
            settings.signature_location = SignatureLocation::QueryParams;
            settings.expires_in = Some(Duration::from_secs(60));
        }

        let identity = Credentials::new(
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
            Some(TEST_SESSION_TOKEN.to_string()),
            None,
            "hardcoded-credentials",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(S3_EXPRESS_REGION)
            .name("s3express")
            .time(now.as_system_time())
            .settings(settings)
            .build()
            .expect("signing params must be valid");
        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                request.method().as_str(),
                request.uri().to_string(),
                request
                    .headers()
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
                SignableBody::UnsignedPayload,
            )?,
            &params.into(),
        )?;
        let (instructions, _) = output.into_parts();
        instructions.apply_to_request_http1x(&mut request);
        Ok(request)
    }

    fn reqsign_s3_express_canonical_request(
        now: Timestamp,
        uri: &str,
        presigned: bool,
        use_standard_session_token: bool,
    ) -> Result<String> {
        let credential = s3_express_credential(now);
        let mut parts = Request::get(uri).body(())?.into_parts().0;
        let mut signing_request = SigningRequest::build(&mut parts)?;
        let expires_in = presigned.then_some(Duration::from_secs(60));
        canonicalize_signing_headers(
            &mut signing_request,
            &credential,
            expires_in,
            now,
            !use_standard_session_token,
        )?;
        let authentication_query = sigv4_authentication_query(
            &signed_header_names(&signing_request, &[]),
            &credential,
            expires_in,
            now,
            "s3express",
            S3_EXPRESS_REGION,
            !use_standard_session_token,
        );
        let canonical_query = canonicalize_query(&signing_request, &authentication_query);
        canonical_request_string(&signing_request, &canonical_query).map_err(Into::into)
    }

    #[derive(Debug)]
    struct SequenceProvider {
        credentials: Mutex<VecDeque<Credential>>,
        calls: Arc<AtomicUsize>,
    }

    impl ProvideCredential for SequenceProvider {
        type Credential = Credential;

        async fn provide_credential(
            &self,
            _ctx: &Context,
        ) -> reqsign_core::Result<Option<Self::Credential>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.credentials.lock().unwrap().pop_front())
        }
    }

    #[test]
    fn presign_deadline_uses_signing_time_and_requested_expiry() {
        let now: Timestamp = "2026-07-22T00:00:00Z"
            .parse()
            .expect("timestamp must parse");
        let signer = RequestSigner::new("s3", "test").with_time(now);
        let credential = Credential::default();

        assert_eq!(
            signer.required_valid_until(&credential, Some(Duration::from_secs(3600))),
            now + Duration::from_secs(3600)
        );
        assert_eq!(
            signer.required_valid_until(&credential, None),
            now + CREDENTIAL_OPERATION_HEADROOM
        );
    }

    fn presign_credential(expires_in: Option<Timestamp>) -> Credential {
        Credential {
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret-key".to_string(),
            session_token: None,
            expires_in,
        }
    }

    fn assert_parts_unchanged(actual: &http::request::Parts, expected: &http::request::Parts) {
        assert_eq!(actual.method, expected.method);
        assert_eq!(actual.uri, expected.uri);
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.headers, expected.headers);
    }

    #[test]
    fn presign_deadline_saturates_for_duration_max() {
        let now: Timestamp = "2026-07-22T00:00:00Z"
            .parse()
            .expect("timestamp must parse");
        let signer = RequestSigner::new("s3", "test").with_time(now);
        let max = now.saturating_add(Duration::MAX);

        assert_eq!(
            signer.required_valid_until(&presign_credential(None), Some(Duration::MAX)),
            max
        );
    }

    #[tokio::test]
    async fn presign_rejects_invalid_lifetimes_without_changing_the_request() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("s3", "test").with_time(now);
        let credential = presign_credential(None);

        for expires_in in [
            Duration::from_millis(500),
            Duration::from_secs(604_801),
            Duration::MAX,
        ] {
            let mut parts = Request::get("https://example.com/object")
                .body(())?
                .into_parts()
                .0;
            let original = parts.clone();

            let err = signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential),
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
    async fn presign_rejects_oversized_lifetime_after_credential_validation() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("s3", "test").with_time(now);
        let finite = presign_credential(Some(now + Duration::from_secs(3600)));
        let mut parts = Request::get("https://example.com/object")
            .body(())?
            .into_parts()
            .0;
        let original = parts.clone();

        let err = signer
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
    async fn presign_accepts_the_encoded_lifetime_boundaries() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("s3", "test").with_time(now);

        for (expires_in, encoded_seconds) in [
            (Duration::from_secs(1), "1"),
            (
                Duration::from_secs(604_800) + Duration::from_millis(500),
                "604800",
            ),
        ] {
            let mut parts = Request::get("https://example.com/object")
                .body(())?
                .into_parts()
                .0;

            signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&presign_credential(None)),
                    Some(expires_in),
                )
                .await?;

            let query = parts.uri.query().expect("presigned URL must have a query");
            assert!(query.contains(&format!("X-Amz-Expires={encoded_seconds}")));
            assert!(query.contains("X-Amz-Signature="));
        }
        Ok(())
    }

    #[tokio::test]
    async fn s3_express_header_token_modes_match_aws_sigv4() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = s3_express_credential(now);

        let expected_session = aws_signed_s3_express_request(
            Request::get(S3_EXPRESS_URI).body("")?,
            now,
            false,
            Some("x-amz-s3session-token"),
        )?;
        let (mut session_parts, body) = Request::get(S3_EXPRESS_URI).body("")?.into_parts();
        RequestSigner::new("s3express", S3_EXPRESS_REGION)
            .with_time(now)
            .sign_request(
                &crate::test_context(),
                &mut session_parts,
                Some(&credential),
                None,
            )
            .await?;
        let actual_session = Request::from_parts(session_parts, body);
        compare_request(
            "S3 Express CreateSession header mode",
            &expected_session,
            &actual_session,
        );
        assert_eq!(
            actual_session.headers()["x-amz-s3session-token"],
            TEST_SESSION_TOKEN
        );
        assert!(actual_session.headers()["x-amz-s3session-token"].is_sensitive());
        assert!(
            !actual_session
                .headers()
                .contains_key("x-amz-security-token")
        );

        let expected_iam = aws_signed_s3_express_request(
            Request::get(S3_EXPRESS_URI).body("")?,
            now,
            false,
            None,
        )?;
        let (mut iam_parts, body) = Request::get(S3_EXPRESS_URI).body("")?.into_parts();
        RequestSigner::new("s3express", S3_EXPRESS_REGION)
            .with_standard_session_token()
            .with_time(now)
            .sign_request(
                &crate::test_context(),
                &mut iam_parts,
                Some(&credential),
                None,
            )
            .await?;
        let actual_iam = Request::from_parts(iam_parts, body);
        compare_request("S3 Express IAM header mode", &expected_iam, &actual_iam);
        assert_eq!(
            actual_iam.headers()["x-amz-security-token"],
            TEST_SESSION_TOKEN
        );
        assert!(actual_iam.headers()["x-amz-security-token"].is_sensitive());
        assert!(!actual_iam.headers().contains_key("x-amz-s3session-token"));

        let session_authorization = actual_session.headers()[header::AUTHORIZATION].to_str()?;
        let iam_authorization = actual_iam.headers()[header::AUTHORIZATION].to_str()?;
        assert!(session_authorization.contains("x-amz-s3session-token"));
        assert!(iam_authorization.contains("x-amz-security-token"));
        assert_ne!(session_authorization, iam_authorization);
        let session_canonical =
            reqsign_s3_express_canonical_request(now, S3_EXPRESS_URI, false, false)?;
        let iam_canonical = reqsign_s3_express_canonical_request(now, S3_EXPRESS_URI, false, true)?;
        assert_eq!(
            session_canonical,
            format!(
                "GET\n/object\n\nhost:bucket--use2-az1--x-s3.s3express-use2-az1.us-east-2.amazonaws.com\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:20260722T000000Z\nx-amz-s3session-token:{TEST_SESSION_TOKEN}\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-s3session-token\nUNSIGNED-PAYLOAD"
            )
        );
        assert_eq!(
            iam_canonical,
            format!(
                "GET\n/object\n\nhost:bucket--use2-az1--x-s3.s3express-use2-az1.us-east-2.amazonaws.com\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:20260722T000000Z\nx-amz-security-token:{TEST_SESSION_TOKEN}\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-security-token\nUNSIGNED-PAYLOAD"
            )
        );
        assert_ne!(session_canonical, iam_canonical);
        assert_eq!(
            credential.session_token.as_deref(),
            Some(TEST_SESSION_TOKEN)
        );

        Ok(())
    }

    #[tokio::test]
    async fn s3_express_query_token_modes_match_aws_sigv4() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = s3_express_credential(now);
        let expires_in = Some(Duration::from_secs(60));

        let expected_session = aws_signed_s3_express_request(
            Request::get(S3_EXPRESS_URI).body("")?,
            now,
            true,
            Some("X-Amz-S3session-Token"),
        )?;
        let (mut session_parts, body) = Request::get(S3_EXPRESS_URI).body("")?.into_parts();
        RequestSigner::new("s3express", S3_EXPRESS_REGION)
            .with_time(now)
            .sign_request(
                &crate::test_context(),
                &mut session_parts,
                Some(&credential),
                expires_in,
            )
            .await?;
        let actual_session = Request::from_parts(session_parts, body);
        compare_request(
            "S3 Express CreateSession query mode",
            &expected_session,
            &actual_session,
        );

        let expected_iam =
            aws_signed_s3_express_request(Request::get(S3_EXPRESS_URI).body("")?, now, true, None)?;
        let (mut iam_parts, body) = Request::get(S3_EXPRESS_URI).body("")?.into_parts();
        RequestSigner::new("s3express", S3_EXPRESS_REGION)
            .with_standard_session_token()
            .with_time(now)
            .sign_request(
                &crate::test_context(),
                &mut iam_parts,
                Some(&credential),
                expires_in,
            )
            .await?;
        let actual_iam = Request::from_parts(iam_parts, body);
        compare_request("S3 Express IAM query mode", &expected_iam, &actual_iam);

        let session_query = actual_session.uri().query().expect("query must exist");
        let iam_query = actual_iam.uri().query().expect("query must exist");
        assert!(session_query.contains("X-Amz-S3session-Token="));
        assert!(!session_query.contains("X-Amz-Security-Token="));
        assert!(iam_query.contains("X-Amz-Security-Token="));
        assert!(!iam_query.contains("X-Amz-S3session-Token="));
        let session_signature = form_urlencoded::parse(session_query.as_bytes())
            .find(|(name, _)| name == "X-Amz-Signature")
            .expect("signature must exist")
            .1;
        let iam_signature = form_urlencoded::parse(iam_query.as_bytes())
            .find(|(name, _)| name == "X-Amz-Signature")
            .expect("signature must exist")
            .1;
        assert_ne!(session_signature, iam_signature);
        let session_canonical =
            reqsign_s3_express_canonical_request(now, S3_EXPRESS_URI, true, false)?;
        let iam_canonical = reqsign_s3_express_canonical_request(now, S3_EXPRESS_URI, true, true)?;
        assert_eq!(
            session_canonical,
            format!(
                "GET\n/object\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20260722%2Fus-east-2%2Fs3express%2Faws4_request&X-Amz-Date=20260722T000000Z&X-Amz-Expires=60&X-Amz-S3session-Token={TEST_SESSION_TOKEN}&X-Amz-SignedHeaders=host\nhost:bucket--use2-az1--x-s3.s3express-use2-az1.us-east-2.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"
            )
        );
        assert_eq!(
            iam_canonical,
            format!(
                "GET\n/object\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20260722%2Fus-east-2%2Fs3express%2Faws4_request&X-Amz-Date=20260722T000000Z&X-Amz-Expires=60&X-Amz-Security-Token={TEST_SESSION_TOKEN}&X-Amz-SignedHeaders=host\nhost:bucket--use2-az1--x-s3.s3express-use2-az1.us-east-2.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"
            )
        );
        assert_ne!(session_canonical, iam_canonical);
        assert_eq!(
            credential.session_token.as_deref(),
            Some(TEST_SESSION_TOKEN)
        );

        Ok(())
    }

    #[tokio::test]
    async fn s3_express_retry_replaces_create_session_token_with_standard_token() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = s3_express_credential(now);
        let iam_credential = Credential {
            session_token: Some("iam-session-token".to_string()),
            ..credential.clone()
        };
        let ctx = crate::test_context();
        let session_signer = RequestSigner::new("s3express", S3_EXPRESS_REGION).with_time(now);
        let iam_signer = RequestSigner::new("s3express", S3_EXPRESS_REGION)
            .with_time(now)
            .with_standard_session_token();
        let original = Request::get(S3_EXPRESS_URI).body(())?.into_parts().0;
        for expires_in in [None, Some(Duration::from_secs(60))] {
            let mut retried = original.clone();
            session_signer
                .sign_request(&ctx, &mut retried, Some(&credential), expires_in)
                .await?;
            iam_signer
                .sign_request(&ctx, &mut retried, Some(&iam_credential), expires_in)
                .await?;
            let mut fresh = original.clone();
            iam_signer
                .sign_request(&ctx, &mut fresh, Some(&iam_credential), expires_in)
                .await?;
            assert_eq!(retried.headers, fresh.headers);
            assert_eq!(retried.uri, fresh.uri);
        }
        Ok(())
    }

    #[tokio::test]
    async fn s3_express_custom_authority_selects_session_token_representation() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = s3_express_credential(now);

        for presigned in [false, true] {
            let expires_in = presigned.then_some(Duration::from_secs(60));

            let session_token_name = if presigned {
                "X-Amz-S3session-Token"
            } else {
                "x-amz-s3session-token"
            };
            let expected_session = aws_signed_s3_express_request(
                Request::get(CUSTOM_AUTHORITY_URI).body("")?,
                now,
                presigned,
                Some(session_token_name),
            )?;
            let (mut session_parts, body) =
                Request::get(CUSTOM_AUTHORITY_URI).body("")?.into_parts();
            RequestSigner::new("s3express", S3_EXPRESS_REGION)
                .with_time(now)
                .sign_request(
                    &crate::test_context(),
                    &mut session_parts,
                    Some(&credential),
                    expires_in,
                )
                .await?;
            let actual_session = Request::from_parts(session_parts, body);
            compare_request(
                &format!("custom authority CreateSession mode (presigned={presigned})"),
                &expected_session,
                &actual_session,
            );

            let expected_iam = aws_signed_s3_express_request(
                Request::get(CUSTOM_AUTHORITY_URI).body("")?,
                now,
                presigned,
                None,
            )?;
            let (mut iam_parts, body) = Request::get(CUSTOM_AUTHORITY_URI).body("")?.into_parts();
            RequestSigner::new("s3express", S3_EXPRESS_REGION)
                .with_standard_session_token()
                .with_time(now)
                .sign_request(
                    &crate::test_context(),
                    &mut iam_parts,
                    Some(&credential),
                    expires_in,
                )
                .await?;
            let actual_iam = Request::from_parts(iam_parts, body);
            compare_request(
                &format!("custom authority IAM mode (presigned={presigned})"),
                &expected_iam,
                &actual_iam,
            );

            if presigned {
                let session_query = actual_session.uri().query().expect("query must exist");
                let iam_query = actual_iam.uri().query().expect("query must exist");
                assert!(session_query.contains("X-Amz-S3session-Token="));
                assert!(!session_query.contains("X-Amz-Security-Token="));
                assert!(iam_query.contains("X-Amz-Security-Token="));
                assert!(!iam_query.contains("X-Amz-S3session-Token="));
            } else {
                assert_eq!(
                    actual_session.headers()[X_AMZ_S3_SESSION_TOKEN],
                    TEST_SESSION_TOKEN
                );
                assert!(actual_session.headers()[X_AMZ_S3_SESSION_TOKEN].is_sensitive());
                assert!(!actual_session.headers().contains_key(X_AMZ_SECURITY_TOKEN));

                assert_eq!(
                    actual_iam.headers()[X_AMZ_SECURITY_TOKEN],
                    TEST_SESSION_TOKEN
                );
                assert!(actual_iam.headers()[X_AMZ_SECURITY_TOKEN].is_sensitive());
                assert!(!actual_iam.headers().contains_key(X_AMZ_S3_SESSION_TOKEN));
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn other_services_keep_standard_session_token_on_express_authorities() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = s3_express_credential(now);

        for uri in [S3_EXPRESS_URI, CUSTOM_AUTHORITY_URI] {
            for presigned in [false, true] {
                let expires_in = presigned.then_some(Duration::from_secs(60));
                let (mut parts, _body) = Request::get(uri).body("")?.into_parts();
                RequestSigner::new("s3", S3_EXPRESS_REGION)
                    .with_time(now)
                    .sign_request(
                        &crate::test_context(),
                        &mut parts,
                        Some(&credential),
                        expires_in,
                    )
                    .await?;

                if presigned {
                    let query = parts.uri.query().expect("query must exist");
                    assert!(query.contains("X-Amz-Security-Token="));
                    assert!(!query.contains("X-Amz-S3session-Token="));
                } else {
                    assert_eq!(parts.headers[X_AMZ_SECURITY_TOKEN], TEST_SESSION_TOKEN);
                    assert!(parts.headers[X_AMZ_SECURITY_TOKEN].is_sensitive());
                    assert!(!parts.headers.contains_key(X_AMZ_S3_SESSION_TOKEN));
                }
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn session_token_is_redacted_from_debug_and_signing_errors() -> Result<()> {
        const TOKEN_MARKER: &str = "SENSITIVE_SESSION_TOKEN";

        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = Credential {
            session_token: Some(format!("{TOKEN_MARKER}\n")),
            ..s3_express_credential(now)
        };
        assert!(!format!("{credential:?}").contains(TOKEN_MARKER));

        for uri in [S3_EXPRESS_URI, CUSTOM_AUTHORITY_URI] {
            for use_standard_session_token in [false, true] {
                let signer = RequestSigner::new("s3express", S3_EXPRESS_REGION);
                let signer = if use_standard_session_token {
                    signer.with_standard_session_token()
                } else {
                    signer
                }
                .with_time(now);
                assert!(!format!("{signer:?}").contains(TOKEN_MARKER));

                let mut parts = Request::get(uri).body(())?.into_parts().0;
                let original = parts.clone();
                let error = signer
                    .sign_request(&crate::test_context(), &mut parts, Some(&credential), None)
                    .await
                    .expect_err("invalid session token must be rejected");

                assert!(!format!("{error}").contains(TOKEN_MARKER));
                assert!(!format!("{error:?}").contains(TOKEN_MARKER));
                assert_eq!(parts.uri, original.uri);
                assert_eq!(parts.headers, original.headers);
                assert_eq!(
                    credential.session_token.as_deref(),
                    Some("SENSITIVE_SESSION_TOKEN\n")
                );
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn presign_refreshes_credential_that_cannot_cover_url_lifetime() -> Result<()> {
        let now = Timestamp::now();
        let short_lived = Credential {
            access_key_id: "short-lived-ak".to_string(),
            secret_access_key: "short-lived-sk".to_string(),
            session_token: Some("short-lived-token".to_string()),
            expires_in: Some(now + Duration::from_secs(600)),
        };
        let long_lived = Credential {
            access_key_id: "long-lived-ak".to_string(),
            secret_access_key: "long-lived-sk".to_string(),
            session_token: Some("long-lived-token".to_string()),
            expires_in: Some(now + Duration::from_secs(7200)),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = SequenceProvider {
            credentials: Mutex::new(VecDeque::from([short_lived, long_lived])),
            calls: calls.clone(),
        };
        let signer = Signer::new(
            crate::test_context(),
            provider,
            RequestSigner::new("s3", "test").with_time(now),
        );

        let mut header_parts = Request::get("https://example.com/object")
            .body(())?
            .into_parts()
            .0;
        signer.sign(&mut header_parts, None).await?;

        let mut query_parts = Request::get("https://example.com/object")
            .body(())?
            .into_parts()
            .0;
        signer
            .sign(&mut query_parts, Some(Duration::from_secs(3600)))
            .await?;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            query_parts
                .uri
                .query()
                .expect("presigned query must exist")
                .contains("X-Amz-Credential=long-lived-ak%2F")
        );
        Ok(())
    }

    #[tokio::test]
    async fn presign_rejects_refreshed_credential_that_cannot_cover_url_lifetime() -> Result<()> {
        let now = Timestamp::now();
        let short_lived = Credential {
            access_key_id: "short-lived-ak".to_string(),
            secret_access_key: "short-lived-sk".to_string(),
            session_token: Some("short-lived-token".to_string()),
            expires_in: Some(now + Duration::from_secs(600)),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = SequenceProvider {
            credentials: Mutex::new(VecDeque::from([short_lived])),
            calls: calls.clone(),
        };
        let signer = Signer::new(
            crate::test_context(),
            provider,
            RequestSigner::new("s3", "test").with_time(now),
        );
        let mut parts = Request::get("https://example.com/object")
            .body(())?
            .into_parts()
            .0;
        let original = parts.clone();

        let err = signer
            .sign(&mut parts, Some(Duration::from_secs(3600)))
            .await
            .expect_err("credential must cover the entire presigned URL lifetime");

        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.headers, original.headers);

        let mut header_parts = Request::get("https://example.com/object")
            .body(())?
            .into_parts()
            .0;
        signer.sign(&mut header_parts, None).await?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            header_parts
                .headers
                .get(header::AUTHORIZATION)
                .expect("authorization header must exist")
                .to_str()?
                .contains("Credential=short-lived-ak/")
        );
        Ok(())
    }

    /// (name, request_builder)
    type TestCase = (&'static str, fn() -> Request<&'static str>);

    fn test_cases() -> Vec<TestCase> {
        vec![
            ("get_request", test_get_request),
            ("get_request_with_sse", test_get_request_with_sse),
            ("get_request_with_query", test_get_request_with_query),
            ("get_request_virtual_host", test_get_request_virtual_host),
            (
                "get_request_with_query_virtual_host",
                test_get_request_with_query_virtual_host,
            ),
            ("put_request", test_put_request),
            (
                "put_request_with_body_digest",
                test_put_request_with_body_digest,
            ),
            ("put_request_virtual_host", test_put_request_virtual_host),
        ]
    }

    fn test_get_request() -> Request<&'static str> {
        let mut req = Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_get_request_with_sse() -> Request<&'static str> {
        let mut req = Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");
        req.headers_mut().insert(
            "x-amz-server-side-encryption",
            "a".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-customer-algorithm",
            "b".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-customer-key",
            "c".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-customer-key-md5",
            "d".parse().expect("must be valid"),
        );
        req.headers_mut().insert(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "e".parse().expect("must be valid"),
        );

        req
    }

    fn test_get_request_with_query() -> Request<&'static str> {
        let mut req = Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://127.0.0.1:9000/hello?list-type=2&max-keys=3&prefix=CI/&start-after=ExampleGuide.pdf"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_get_request_virtual_host() -> Request<&'static str> {
        let mut req = Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://hello.s3.test.example.com"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_get_request_with_query_virtual_host() -> Request<&'static str> {
        let mut req = Request::new("");
        *req.method_mut() = http::Method::GET;
        *req.uri_mut() = "http://hello.s3.test.example.com?list-type=2&max-keys=3&prefix=CI/&start-after=ExampleGuide.pdf"
            .parse()
            .expect("url must be valid");

        req
    }

    fn test_put_request() -> Request<&'static str> {
        let content = "Hello,World!";
        let mut req = Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        req
    }

    fn test_put_request_with_body_digest() -> Request<&'static str> {
        let content = "Hello,World!";
        let mut req = Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://127.0.0.1:9000/hello"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        let body = hex_sha256(&provider, content.as_bytes()).expect("SHA-256 must succeed");
        req.headers_mut().insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(&body).expect("must be valid"),
        );

        req
    }

    fn test_put_request_virtual_host() -> Request<&'static str> {
        let content = "Hello,World!";
        let mut req = Request::new(content);
        *req.method_mut() = http::Method::PUT;
        *req.uri_mut() = "http://hello.s3.test.example.com"
            .parse()
            .expect("url must be valid");

        req.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&content.len().to_string()).expect("must be valid"),
        );

        req
    }

    #[track_caller]
    fn compare_request(name: &str, l: &Request<&str>, r: &Request<&str>) {
        fn format_headers(req: &Request<&str>) -> Vec<String> {
            let mut hs = req
                .headers()
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v.to_str().expect("must be valid")))
                .collect::<Vec<_>>();

            // Insert host if original request doesn't have it.
            if !hs.contains(&format!("host:{}", req.uri().authority().unwrap())) {
                hs.push(format!("host:{}", req.uri().authority().unwrap()))
            }

            hs.sort();
            hs
        }

        assert_eq!(
            format_headers(l),
            format_headers(r),
            "{name} header mismatch"
        );

        assert_eq!(
            sorted_query(l.uri()),
            sorted_query(r.uri()),
            "{name} query mismatch"
        );
    }

    fn sorted_query(uri: &http::Uri) -> Vec<(String, String)> {
        let query = uri.query().unwrap_or_default();
        let mut pairs = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<Vec<_>>();
        pairs.sort();
        pairs
    }

    fn encoding_request(uri: &str) -> Result<Request<&'static str>> {
        Ok(Request::get(uri)
            .header("x-custom", "encoding-test")
            .body("")?)
    }

    fn aws_signed_execute_api_request(
        mut request: Request<&'static str>,
        now: Timestamp,
        mode: PercentEncodingMode,
        presigned: bool,
        excluded_headers: &[&'static str],
    ) -> Result<Request<&'static str>> {
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = match mode {
            PercentEncodingMode::Single => AwsPercentEncodingMode::Single,
            PercentEncodingMode::Double => AwsPercentEncodingMode::Double,
        };
        // Match reqsign's signing settings for unsigned payloads and wire-ready paths.
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.session_token_mode = SessionTokenMode::Include;
        settings.session_token_name_override = None;
        settings.excluded_headers = Some(
            std::iter::once("authorization")
                .chain(excluded_headers.iter().copied())
                .map(Into::into)
                .collect(),
        );
        settings.signature_location = if presigned {
            SignatureLocation::QueryParams
        } else {
            SignatureLocation::Headers
        };
        settings.expires_in = presigned.then_some(Duration::from_secs(60));

        let identity = Credentials::new(
            TEST_ACCESS_KEY,
            TEST_SECRET_KEY,
            Some(TEST_SESSION_TOKEN.to_string()),
            None,
            "hardcoded-credentials",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region("us-east-1")
            .name("execute-api")
            .time(now.as_system_time())
            .settings(settings)
            .build()
            .expect("signing params must be valid");
        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                request.method().as_str(),
                request.uri().to_string(),
                request
                    .headers()
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
                SignableBody::UnsignedPayload,
            )?,
            &params.into(),
        )?;
        let (instructions, _) = output.into_parts();
        instructions.apply_to_request_http1x(&mut request);
        Ok(request)
    }

    async fn reqsign_signed_encoding_request(
        service: &str,
        uri: &str,
        now: Timestamp,
        mode: Option<PercentEncodingMode>,
        presigned: bool,
    ) -> Result<Request<&'static str>> {
        let credential = Credential {
            access_key_id: TEST_ACCESS_KEY.to_string(),
            secret_access_key: TEST_SECRET_KEY.to_string(),
            session_token: Some(TEST_SESSION_TOKEN.to_string()),
            expires_in: Some(now + Duration::from_secs(3600)),
        };
        let mut signer = RequestSigner::new(service, "us-east-1").with_time(now);
        if let Some(mode) = mode {
            signer = signer.with_percent_encoding_mode(mode);
        }
        let (mut parts, body) = encoding_request(uri)?.into_parts();
        signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                presigned.then_some(Duration::from_secs(60)),
            )
            .await?;
        Ok(Request::from_parts(parts, body))
    }

    async fn check_encoding_signatures_match_aws_sigv4(presigned: bool) -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        // Both implementations agree on Single for canonically encoded wire
        // paths. Noncanonical inputs are covered separately below.
        let encoded_paths = [
            "/",
            "/percent%25",
            "/encoded%2Fslash",
            "/space%20here",
            "/user%40example.com",
            "/key%3Dvalue",
            "/%E4%BD%A0%E5%A5%BD/%C3%A9",
            "/literal%252Fescape",
            "/unreserved-._~/a//b/./c/../d/",
        ];
        let double_only_paths = [
            "/user@example.com/key=value",
            "/lowercase%2fslash/%c3%a9",
            "/encoded%7Etilde",
            "/invalid-utf8%FF",
            "/a//b/./c/../d/",
        ];
        const QUERY: &str = "z=last&slash=%2f&dup=two&dup=one&empty=&flag&double=%252F";

        for mode in [PercentEncodingMode::Single, PercentEncodingMode::Double] {
            let mut paths = encoded_paths.to_vec();
            if mode == PercentEncodingMode::Double {
                paths.extend(double_only_paths);
            }
            for path in paths {
                let uri = format!("https://example.com{path}?{QUERY}");
                let expected = aws_signed_execute_api_request(
                    encoding_request(&uri)?,
                    now,
                    mode,
                    presigned,
                    &[],
                )?;
                let actual = reqsign_signed_encoding_request(
                    "execute-api",
                    &uri,
                    now,
                    Some(mode),
                    presigned,
                )
                .await?;
                let name = format!("{mode:?}, presigned={presigned}, path={path}");
                compare_request(&name, &expected, &actual);
                assert_eq!(actual.uri().path(), path, "{name} changed wire path");
                if presigned {
                    assert!(
                        actual.uri().to_string().starts_with(&format!("{uri}&")),
                        "{name} changed existing wire query"
                    );
                    assert!(actual.uri().query().unwrap().contains("X-Amz-Signature="));
                } else {
                    assert_eq!(actual.uri().to_string(), uri, "{name} changed wire URI");
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonical_uri_encoding_header_signatures_match_aws_sigv4() -> Result<()> {
        check_encoding_signatures_match_aws_sigv4(false).await
    }

    #[tokio::test]
    async fn canonical_uri_encoding_query_signatures_match_aws_sigv4() -> Result<()> {
        check_encoding_signatures_match_aws_sigv4(true).await
    }

    #[tokio::test]
    async fn default_encoding_mode_is_single_for_every_service() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let path = "/a//b/./c/../user@example.com/%2f/%7E/key=value/%25";
        let uri = format!("https://example.com{path}?{RAW_QUERY}");

        for service in ["s3", "s3express", "execute-api", "sts"] {
            for presigned in [false, true] {
                let default =
                    reqsign_signed_encoding_request(service, &uri, now, None, presigned).await?;
                let single = reqsign_signed_encoding_request(
                    service,
                    &uri,
                    now,
                    Some(PercentEncodingMode::Single),
                    presigned,
                )
                .await?;
                let double = reqsign_signed_encoding_request(
                    service,
                    &uri,
                    now,
                    Some(PercentEncodingMode::Double),
                    presigned,
                )
                .await?;

                assert_eq!(
                    default.headers(),
                    single.headers(),
                    "{service} should default to Single"
                );
                assert_eq!(
                    default.uri(),
                    single.uri(),
                    "{service} should default to Single"
                );
                if presigned {
                    assert_ne!(
                        default.uri(),
                        double.uri(),
                        "{service} should only use Double when requested"
                    );
                } else {
                    assert_ne!(
                        default.headers()[header::AUTHORIZATION],
                        double.headers()[header::AUTHORIZATION],
                        "{service} should only use Double when requested"
                    );
                }
                assert_eq!(default.uri().path(), path, "{service} changed wire path");
                if presigned {
                    assert!(
                        default.uri().to_string().starts_with(&uri),
                        "{service} changed existing wire query"
                    );
                } else {
                    assert_eq!(default.uri().to_string(), uri, "{service} changed wire URI");
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn default_encoding_mode_retains_legacy_canonicalization_differences() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        for (wire_path, legacy_path) in [
            (
                "/user@example.com/key=value",
                "/user%40example.com/key%3Dvalue",
            ),
            ("/lowercase%2fslash/%c3%a9", "/lowercase%2Fslash/%C3%A9"),
            ("/encoded%7Etilde", "/encoded~tilde"),
        ] {
            assert_eq!(canonical_uri(wire_path)?, legacy_path);
            let uri = format!("https://example.com{wire_path}");
            let legacy_uri = format!("https://example.com{legacy_path}");
            for presigned in [false, true] {
                let actual =
                    reqsign_signed_encoding_request("execute-api", &uri, now, None, presigned)
                        .await?;
                // SDK Single leaves the path verbatim. Legacy reqsign Single
                // decodes and re-encodes each segment, so compare the default
                // signature against the SDK signing the legacy canonical path.
                let expected = aws_signed_execute_api_request(
                    encoding_request(&legacy_uri)?,
                    now,
                    PercentEncodingMode::Single,
                    presigned,
                    &[],
                )?;
                compare_request(wire_path, &expected, &actual);
                assert_eq!(actual.uri().path(), wire_path);

                let sdk_wire = aws_signed_execute_api_request(
                    encoding_request(&uri)?,
                    now,
                    PercentEncodingMode::Single,
                    presigned,
                    &[],
                )?;
                if presigned {
                    let signature = |request: &Request<&str>| {
                        form_urlencoded::parse(request.uri().query().unwrap().as_bytes())
                            .find(|(name, _)| name == "X-Amz-Signature")
                            .expect("presigned signature must exist")
                            .1
                            .into_owned()
                    };
                    assert_ne!(signature(&actual), signature(&sdk_wire));
                } else {
                    assert_ne!(
                        actual.headers()[header::AUTHORIZATION],
                        sdk_wire.headers()[header::AUTHORIZATION]
                    );
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn excluded_headers_match_aws_sdk_signatures() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("execute-api", "us-east-1")
            .with_time(now)
            .with_excluded_headers(["UsEr-AgEnT", "X-AmZn-TrAcE-Id"]);
        let credential = s3_express_credential(now);
        let request = Request::get("https://example.com/object")
            .header(header::HOST, "example.com")
            .header(header::AUTHORIZATION, "Bearer fixture-token")
            .header(header::USER_AGENT, "  first    agent  ")
            .header(header::USER_AGENT, "second agent")
            .header("x-amzn-trace-id", "fixture-trace")
            .header("x-meta", "still signed")
            .body("")?;

        for presigned in [false, true] {
            let expected = aws_signed_execute_api_request(
                request.clone(),
                now,
                PercentEncodingMode::Single,
                presigned,
                &["user-agent", "x-amzn-trace-id"],
            )?;
            let (mut parts, body) = request.clone().into_parts();
            signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential),
                    presigned.then_some(Duration::from_secs(60)),
                )
                .await?;
            let actual = Request::from_parts(parts, body);
            assert_eq!(actual.headers(), expected.headers());
            assert_eq!(sorted_query(actual.uri()), sorted_query(expected.uri()));
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonical_headers_match_aws_sdk_signatures() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("execute-api", "us-east-1").with_time(now);
        let credential = s3_express_credential(now);
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
            let original = builder.body("")?;

            for presigned in [false, true] {
                let mut expected = aws_signed_execute_api_request(
                    original.clone(),
                    now,
                    PercentEncodingMode::Single,
                    presigned,
                    &[],
                )?;
                // The SDK synthesizes Host internally and only returns authentication fields.
                expected
                    .headers_mut()
                    .entry(header::HOST)
                    .or_insert(HeaderValue::from_static(expected_host));
                let mut parts = original.clone().into_parts().0;
                signer
                    .sign_request(
                        &ctx,
                        &mut parts,
                        Some(&credential),
                        presigned.then_some(Duration::from_secs(60)),
                    )
                    .await?;

                assert_eq!(
                    parts.headers,
                    *expected.headers(),
                    "{uri}, presigned={presigned}"
                );
                if presigned {
                    assert!(
                        parts
                            .uri
                            .to_string()
                            .starts_with(&format!("{uri}&X-Amz-Algorithm="))
                    );
                    assert_eq!(
                        sorted_query(&parts.uri),
                        sorted_query(expected.uri()),
                        "{uri}"
                    );
                } else {
                    assert_eq!(parts.uri.to_string(), uri);
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonical_headers_reject_opaque_repeated_values_atomically() -> Result<()> {
        let original = Request::get("https://example.com:443/object%2Fname?raw=%2f")
            .header("x-meta", "valid first value")
            .header("x-meta", HeaderValue::from_bytes(b"\xff")?)
            .extension("original extension")
            .body(())?
            .into_parts()
            .0;
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("execute-api", "us-east-1").with_time(now);
        let ctx = crate::test_context();
        let credential = presign_credential(None);

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
    async fn default_encoding_mode_retains_invalid_utf8_rejection() -> Result<()> {
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let credential = s3_express_credential(now);
        for presigned in [false, true] {
            let signer = RequestSigner::new("execute-api", "us-east-1").with_time(now);
            let mut parts = encoding_request("https://example.com/invalid%FF?raw=%2f")?
                .into_parts()
                .0;
            let original = parts.clone();
            let error = signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential),
                    presigned.then_some(Duration::from_secs(60)),
                )
                .await
                .expect_err("Single must retain its legacy UTF-8 validation");
            assert_eq!(error.kind(), ErrorKind::RequestInvalid);
            assert_eq!(parts.uri, original.uri);
            assert_eq!(parts.headers, original.headers);
        }
        Ok(())
    }

    #[tokio::test]
    async fn canonicalization_preserves_wire_uri() -> Result<()> {
        let credential = Credential {
            access_key_id: "access_key_id".to_string(),
            secret_access_key: "secret_access_key".to_string(),
            ..Default::default()
        };
        let now: Timestamp = "2026-07-22T00:00:00Z".parse()?;
        let signer = RequestSigner::new("s3", "test").with_time(now);
        let original_uri = format!("https://example.com/object%2Fname?{RAW_QUERY}");

        let mut canonical_parts = Request::get(&original_uri).body(())?.into_parts().0;
        let mut signing_req = SigningRequest::build(&mut canonical_parts)?;
        canonicalize_signing_headers(
            &mut signing_req,
            &credential,
            Some(Duration::from_secs(60)),
            now,
            false,
        )?;
        let auth_query = sigv4_authentication_query(
            &signed_header_names(&signing_req, &[]),
            &credential,
            Some(Duration::from_secs(60)),
            now,
            "s3",
            "test",
            false,
        );
        let canonical_query = canonicalize_query(&signing_req, &auth_query);

        assert_eq!(canonical_uri(&signing_req.path)?, "/object%2Fname");
        assert!(canonical_query.contains(&("literal-plus".to_string(), "%2B".to_string())));
        assert!(canonical_query.contains(&("double".to_string(), "%252F".to_string())));
        assert!(canonical_query.contains(&(String::new(), "empty-key".to_string())));
        assert!(canonical_query.contains(&("flag".to_string(), String::new())));

        let mut header_parts = Request::get(&original_uri)
            .header("x-custom", " value ")
            .body(())?
            .into_parts()
            .0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut header_parts,
                Some(&credential),
                None,
            )
            .await?;
        assert_eq!(header_parts.uri.to_string(), original_uri);
        assert_eq!(header_parts.headers["x-custom"], " value ");

        let mut query_parts = Request::get(&original_uri).body(())?.into_parts().0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut query_parts,
                Some(&credential),
                Some(Duration::from_secs(60)),
            )
            .await?;
        assert!(
            query_parts
                .uri
                .to_string()
                .starts_with(&format!("{original_uri}X-Amz-Algorithm="))
        );
        assert!(
            query_parts
                .uri
                .query()
                .unwrap()
                .contains("X-Amz-Signature=")
        );

        Ok(())
    }

    #[tokio::test]
    async fn test() -> Result<()> {
        for (name, req) in test_cases() {
            calculate(req)
                .await
                .unwrap_or_else(|err| panic!("calculate {name} should pass: {err:?}"));
            calculate_in_query(req)
                .await
                .unwrap_or_else(|err| panic!("calculate_in_query {name} should pass: {err:?}"));
            test_calculate_with_token(req).await.unwrap_or_else(|err| {
                panic!("test_calculate_with_token {name} should pass: {err:?}")
            });
            test_calculate_with_token_in_query(req)
                .await
                .unwrap_or_else(|err| {
                    panic!("test_calculate_with_token_in_query {name} should pass: {err:?}")
                });
        }
        Ok(())
    }

    async fn calculate(req_fn: fn() -> Request<&'static str>) -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = req_fn();
        let name = format!(
            "{} {} {:?}",
            req.method(),
            req.uri().path(),
            req.uri().query(),
        );
        let now = Timestamp::now();

        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = AwsPercentEncodingMode::Double;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let id = Credentials::new(
            "access_key_id",
            "secret_access_key",
            None,
            None,
            "hardcoded-credentials",
        )
        .into();
        let sp = v4::SigningParams::builder()
            .identity(&id)
            .region("test")
            .name("s3")
            .time(now.as_system_time())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        let mut body = SignableBody::UnsignedPayload;
        if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
            body = SignableBody::Bytes(req.body().as_bytes());
        }

        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                req.method().as_str(),
                req.uri().to_string(),
                req.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap())),
                body,
            )
            .unwrap(),
            &sp.into(),
        )?;
        let (aws_sig, _) = output.into_parts();
        aws_sig.apply_to_request_http1x(&mut req);
        let expected_req = req;

        let req = req_fn();
        let (mut parts, body) = req.into_parts();

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let loader = StaticCredentialProvider::new("access_key_id", "secret_access_key");
        let cred = loader.provide_credential(&ctx).await?.unwrap();

        let builder = RequestSigner::new("s3", "test").with_time(now);
        builder
            .sign_request(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("must apply success");

        let actual_req = Request::from_parts(parts, body);

        compare_request(&name, &expected_req, &actual_req);

        Ok(())
    }

    async fn calculate_in_query(req_fn: fn() -> Request<&'static str>) -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = req_fn();
        let name = format!(
            "{} {} {:?}",
            req.method(),
            req.uri().path(),
            req.uri().query(),
        );
        let now = Timestamp::now();

        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = AwsPercentEncodingMode::Double;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        ss.signature_location = SignatureLocation::QueryParams;
        ss.expires_in = Some(Duration::from_secs(3600));
        let id = Credentials::new(
            "access_key_id",
            "secret_access_key",
            None,
            None,
            "hardcoded-credentials",
        )
        .into();
        let sp = v4::SigningParams::builder()
            .identity(&id)
            .region("test")
            .name("s3")
            .time(now.as_system_time())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        let mut body = SignableBody::UnsignedPayload;
        if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
            body = SignableBody::Bytes(req.body().as_bytes());
        }

        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                req.method().as_str(),
                req.uri().to_string(),
                req.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap())),
                body,
            )
            .unwrap(),
            &sp.into(),
        )
        .expect("signing must succeed");
        let (aws_sig, _) = output.into_parts();
        aws_sig.apply_to_request_http1x(&mut req);
        let expected_req = req;

        let req = req_fn();
        let (mut parts, body) = req.into_parts();

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let loader = StaticCredentialProvider::new("access_key_id", "secret_access_key");
        let cred = loader.provide_credential(&ctx).await?.unwrap();

        let builder = RequestSigner::new("s3", "test").with_time(now);

        builder
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(3600)),
            )
            .await?;
        let actual_req = Request::from_parts(parts, body);

        compare_request(&name, &expected_req, &actual_req);

        Ok(())
    }

    async fn test_calculate_with_token(req_fn: fn() -> Request<&'static str>) -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = req_fn();
        let name = format!(
            "{} {} {:?}",
            req.method(),
            req.uri().path(),
            req.uri().query(),
        );
        let now = Timestamp::now();

        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = AwsPercentEncodingMode::Double;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let id = Credentials::new(
            "access_key_id",
            "secret_access_key",
            Some("security_token".to_string()),
            None,
            "hardcoded-credentials",
        )
        .into();
        let sp = v4::SigningParams::builder()
            .identity(&id)
            .region("test")
            .name("s3")
            .time(now.as_system_time())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        let mut body = SignableBody::UnsignedPayload;
        if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
            body = SignableBody::Bytes(req.body().as_bytes());
        }

        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                req.method().as_str(),
                req.uri().to_string(),
                req.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap())),
                body,
            )
            .unwrap(),
            &sp.into(),
        )
        .expect("signing must succeed");
        let (aws_sig, _) = output.into_parts();
        aws_sig.apply_to_request_http1x(&mut req);
        let expected_req = req;

        let req = req_fn();
        let (mut parts, body) = req.into_parts();

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let loader = StaticCredentialProvider::new("access_key_id", "secret_access_key")
            .with_session_token("security_token");
        let cred = loader.provide_credential(&ctx).await?.unwrap();

        let builder = RequestSigner::new("s3", "test").with_time(now);
        builder
            .sign_request(&ctx, &mut parts, Some(&cred), None)
            .await
            .expect("must apply success");
        let actual_req = Request::from_parts(parts, body);

        compare_request(&name, &expected_req, &actual_req);

        Ok(())
    }

    async fn test_calculate_with_token_in_query(
        req_fn: fn() -> Request<&'static str>,
    ) -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut req = req_fn();
        let name = format!(
            "{} {} {:?}",
            req.method(),
            req.uri().path(),
            req.uri().query(),
        );
        let now = Timestamp::now();

        let mut ss = SigningSettings::default();
        ss.percent_encoding_mode = AwsPercentEncodingMode::Double;
        ss.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        ss.signature_location = SignatureLocation::QueryParams;
        ss.expires_in = Some(Duration::from_secs(3600));
        let id = Credentials::new(
            "access_key_id",
            "secret_access_key",
            Some("security_token".to_string()),
            None,
            "hardcoded-credentials",
        )
        .into();
        let sp = v4::SigningParams::builder()
            .identity(&id)
            .region("test")
            // .security_token("security_token")
            .name("s3")
            .time(now.as_system_time())
            .settings(ss)
            .build()
            .expect("signing params must be valid");

        let mut body = SignableBody::UnsignedPayload;
        if req.headers().get(X_AMZ_CONTENT_SHA_256).is_some() {
            body = SignableBody::Bytes(req.body().as_bytes());
        }

        let output = aws_sigv4::http_request::sign(
            SignableRequest::new(
                req.method().as_str(),
                req.uri().to_string(),
                req.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap())),
                body,
            )
            .unwrap(),
            &sp.into(),
        )
        .expect("signing must succeed");
        let (aws_sig, _) = output.into_parts();
        aws_sig.apply_to_request_http1x(&mut req);
        let expected_req = req;

        let req = req_fn();
        let (mut parts, body) = req.into_parts();

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default());
        let loader = StaticCredentialProvider::new("access_key_id", "secret_access_key")
            .with_session_token("security_token");
        let cred = loader.provide_credential(&ctx).await?.unwrap();

        let builder = RequestSigner::new("s3", "test").with_time(now);
        builder
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(3600)),
            )
            .await
            .expect("must apply success");
        let actual_req = Request::from_parts(parts, body);

        compare_request(&name, &expected_req, &actual_req);

        Ok(())
    }
}
