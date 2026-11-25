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

//! Huawei Cloud Object Storage Service (OBS) builder
use std::collections::HashSet;
use std::fmt::Write;
use std::sync::LazyLock;
use std::time::Duration;

use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use http::{HeaderValue, Uri};
use jiff::ToSpan;
use jiff::tz::TimeZone;
use log::debug;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqsign_core::Result;

use super::constants::*;
use super::credential::Credential;
use reqsign_core::hash::base64_hmac_sha1;
use reqsign_core::time::Timestamp;
use reqsign_core::utils::Redact;
use reqsign_core::{SignRequest, SigningCredential, SigningRequest};

static OBS_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// RequestSigner that implement Huawei Cloud Object Storage Service Authorization.
///
/// - [User Signature Authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
///
/// Query signing embeds an absolute `Expires` second. Reqsign applies a local
/// signing rule: the instant represented by the encoded second must be later
/// than the full signing time and strictly earlier than the same UTC calendar
/// time 20 years later. February 29 clamps to February 28 when the target year
/// does not have it. Values outside that window or the representable timestamp
/// range return `RequestInvalid` before changing the request. This is Reqsign's
/// signing rule, not a claim about the OBS server's validation.
///
/// - [Query string authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0011.html)
#[derive(Debug)]
pub struct RequestSigner {
    bucket: String,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a builder.
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_string(),
            time: None,
        }
    }

    /// Specify the signing time.
    ///
    /// # Note
    ///
    /// We should always take current time to sign requests.
    /// Only use this function for testing.
    #[cfg(test)]
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
        signing_time.saturating_add(expires_in.unwrap_or_default())
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
        ctx: &reqsign_core::Context,
        parts: &mut http::request::Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return Ok(());
        };
        let provider = ctx.crypto_provider()?;

        let now = self.get_time();
        let required_until = self.required_valid_until_at(now, expires_in);
        if !cred.is_valid_at(required_until) {
            return Err(reqsign_core::Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }

        let original_uri = parts.uri.clone();
        let mut ctx = SigningRequest::build(parts)?;
        let query_expiration = expires_in
            .map(|expires| presign_expiration(now, expires))
            .transpose()?;

        let string_to_sign = string_to_sign(&mut ctx, cred, now, query_expiration, &self.bucket)?;
        let signature = base64_hmac_sha1(
            provider,
            cred.secret_access_key.as_bytes(),
            string_to_sign.as_bytes(),
        )?;

        let final_uri = if let Some(expiration) = query_expiration {
            ctx.headers.insert(DATE, now.format_http_date().parse()?);
            let mut authentication = Vec::new();
            if let Some(token) = &cred.security_token {
                authentication.push(format!(
                    "security-token={}",
                    utf8_percent_encode(token, &OBS_QUERY_ENCODE_SET)
                ));
            }
            authentication.push(format!(
                "AccessKeyId={}",
                utf8_percent_encode(&cred.access_key_id, &OBS_QUERY_ENCODE_SET)
            ));
            authentication.push(format!("Expires={}", expiration.as_second()));
            authentication.push(format!(
                "Signature={}",
                utf8_percent_encode(&signature, &OBS_QUERY_ENCODE_SET)
            ));
            Some(append_query_fragment(
                &original_uri,
                &authentication.join("&"),
            )?)
        } else {
            ctx.headers.insert(DATE, now.format_http_date().parse()?);
            ctx.headers.insert(AUTHORIZATION, {
                let mut value: HeaderValue =
                    format!("OBS {}:{}", cred.access_key_id, signature).parse()?;
                value.set_sensitive(true);

                value
            });
            None
        };

        ctx.apply(parts)?;
        if let Some(uri) = final_uri {
            parts.uri = uri;
        }
        Ok(())
    }
}

fn presign_expiration(now: Timestamp, expires: Duration) -> Result<Timestamp> {
    let expiration = now.checked_add(expires).ok_or_else(|| {
        reqsign_core::Error::request_invalid(
            "OBS signature expiration exceeds the representable time range",
        )
    })?;
    let signing_time = signing_time(now)?;
    let encoded_expiration =
        jiff::Timestamp::from_second(expiration.as_second()).map_err(|_| {
            reqsign_core::Error::request_invalid(
                "OBS signature expiration exceeds the representable time range",
            )
        })?;
    if encoded_expiration <= signing_time {
        return Err(reqsign_core::Error::request_invalid(
            "OBS signature expiration must represent an instant later than the signing time",
        ));
    }

    if let Some(bound) = twenty_year_bound(signing_time)? {
        if encoded_expiration >= bound {
            return Err(reqsign_core::Error::request_invalid(
                "OBS signature expiration must be less than 20 UTC calendar years after the signing time",
            ));
        }
    }

    Ok(expiration)
}

fn signing_time(now: Timestamp) -> Result<jiff::Timestamp> {
    now.to_string().parse().map_err(|e| {
        reqsign_core::Error::unexpected("failed to parse OBS signing time").with_source(e)
    })
}

fn twenty_year_bound(now: jiff::Timestamp) -> Result<Option<jiff::Timestamp>> {
    let datetime = now.to_zoned_datetime(TimeZone::UTC).datetime();
    let Ok(date) = datetime.date().checked_add(20.years()) else {
        return Ok(None);
    };
    let Ok(bound) = TimeZone::UTC.to_timestamp(date.to_datetime(datetime.time())) else {
        return Ok(None);
    };
    Ok(Some(bound))
}

/// Construct string to sign
///
/// ## Format
///
/// ```text
/// VERB + "\n" +
/// Content-MD5 + "\n" +
/// Content-Type + "\n" +
/// Date + "\n" +
/// CanonicalizedHeaders +
/// CanonicalizedResource;
/// ```
///
/// ## Reference
///
/// - [User Signature Authentication (OBS)](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0009.html)
fn string_to_sign(
    ctx: &mut SigningRequest,
    cred: &Credential,
    now: Timestamp,
    expires_at: Option<Timestamp>,
    bucket: &str,
) -> Result<String> {
    let mut s = String::new();
    s.write_str(ctx.method.as_str())?;
    s.write_str("\n")?;
    s.write_str(
        ctx.header_get_or_default(
            &CONTENT_MD5.parse().map_err(|e| {
                reqsign_core::Error::unexpected(format!("Invalid header name: {e}"))
            })?,
        )?,
    )?;
    s.write_str("\n")?;
    s.write_str(ctx.header_get_or_default(&CONTENT_TYPE)?)?;
    s.write_str("\n")?;
    match expires_at {
        Some(expiration) => {
            writeln!(&mut s, "{}", expiration.as_second())?;
        }
        None => {
            writeln!(&mut s, "{}", now.format_http_date())?;
        }
    }

    {
        let headers = canonicalize_header(ctx, expires_at.is_none(), cred)?;
        if !headers.is_empty() {
            writeln!(&mut s, "{headers}",)?;
        }
    }
    write!(&mut s, "{}", canonicalize_resource(ctx, bucket))?;

    if let Some(token) = cred
        .security_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        debug!(
            "string to sign: {}",
            s.replace(token, &format!("{:?}", Redact::from(token)))
        );
    } else {
        debug!("string to sign: {}", s);
    }
    Ok(s)
}

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_header(
    ctx: &mut SigningRequest,
    is_header: bool,
    cred: &Credential,
) -> Result<String> {
    if is_header {
        // Insert security token
        if let Some(token) = &cred.security_token {
            let mut value: HeaderValue = token.parse()?;
            value.set_sensitive(true);
            ctx.headers.insert("x-obs-security-token", value);
        }
    }

    Ok(SigningRequest::header_to_string(
        ctx.header_to_vec_with_prefix("x-obs-"),
        ":",
        "\n",
    ))
}

/// ## Reference
///
/// - [Authentication of Signature in a Header](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)
fn canonicalize_resource(ctx: &SigningRequest, bucket: &str) -> String {
    let params = ctx.query_to_vec_with_filter(is_sub_resource);

    let params_str = SigningRequest::query_to_string(params, "=", "&");

    if params_str.is_empty() {
        format!("/{bucket}{}", ctx.path)
    } else {
        format!("/{bucket}{}?{params_str}", ctx.path)
    }
}

fn append_query_fragment(uri: &Uri, fragment: &str) -> Result<Uri> {
    let mut value = uri.to_string();
    if uri.query().is_none() {
        value.push('?');
    } else if !value.ends_with('?') && !value.ends_with('&') {
        value.push('&');
    }
    value.push_str(fragment);

    value.parse().map_err(|e| {
        reqsign_core::Error::request_invalid("failed to append OBS signing query").with_source(e)
    })
}

fn is_sub_resource(param: &str) -> bool {
    SUBRESOURCES.contains(param)
}

// Please attention: the subresources are case-sensitive.
static SUBRESOURCES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "CDNNotifyConfiguration",
        "acl",
        "append",
        "attname",
        "backtosource",
        "cors",
        "customdomain",
        "delete",
        "deletebucket",
        "directcoldaccess",
        "encryption",
        "inventory",
        "length",
        "lifecycle",
        "location",
        "logging",
        "metadata",
        "modify",
        "name",
        "notification",
        "partNumber",
        "policy",
        "position",
        "quota",
        "rename",
        "replication",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "response-content-language",
        "response-content-type",
        "response-expires",
        "restore",
        "storageClass",
        "storagePolicy",
        "storageinfo",
        "tagging",
        "torrent",
        "truncate",
        "uploadId",
        "uploads",
        "versionId",
        "versioning",
        "versions",
        "website",
        "x-image-process",
        "x-image-save-bucket",
        "x-image-save-object",
        "x-obs-security-token",
    ])
});

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::{Mutex, OnceLock};

    use http::Uri;
    use http::header::HeaderName;
    use reqsign_core::{ErrorKind, OsEnv, Result, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;

    use super::super::provide_credential::StaticCredentialProvider;
    use super::*;

    static CAPTURED_LOGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

    struct CapturingLogger;

    impl log::Log for CapturingLogger {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            if let Some(logs) = CAPTURED_LOGS.get() {
                logs.lock()
                    .expect("captured logs lock poisoned")
                    .push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    fn start_log_capture() {
        CAPTURED_LOGS.get_or_init(|| {
            log::set_boxed_logger(Box::new(CapturingLogger))
                .expect("test logger must be installed once");
            log::set_max_level(log::LevelFilter::Debug);
            Mutex::new(Vec::new())
        });
        CAPTURED_LOGS
            .get()
            .expect("captured logs are initialized")
            .lock()
            .expect("captured logs lock poisoned")
            .clear();
    }

    fn captured_logs() -> String {
        CAPTURED_LOGS
            .get()
            .expect("captured logs are initialized")
            .lock()
            .expect("captured logs lock poisoned")
            .join("\n")
    }

    const RAW_QUERY: &str = "versionId=a%2Bb%3Dc%2525%26e&slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

    #[tokio::test]
    async fn security_token_is_redacted_from_signing_logs_and_request_debug() -> Result<()> {
        const TOKEN: &str = "synthetic-obs-security-token";

        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let credential = Credential::new(
            "access_key".to_string(),
            "123456".to_string(),
            Some(TOKEN.to_string()),
        );
        let signer = RequestSigner::new("bucket").with_time(now);
        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;

        let mut signing_request = SigningRequest::build(&mut parts)?;
        let string = string_to_sign(&mut signing_request, &credential, now, None, "bucket")?;
        assert!(string.contains(TOKEN));

        start_log_capture();
        signer
            .sign_request(&crate::test_context(), &mut parts, Some(&credential), None)
            .await?;

        assert!(!captured_logs().contains(TOKEN));
        assert!(parts.headers["x-obs-security-token"].is_sensitive());
        assert_eq!(parts.headers["x-obs-security-token"].to_str()?, TOKEN);
        assert!(!format!("{parts:?}").contains(TOKEN));

        Ok(())
    }

    #[tokio::test]
    async fn test_sign() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder = RequestSigner::new("bucket")
            .with_time(Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, builder);

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        assert_eq!(
            "OBS access_key:9gUZ4ol2W19LyYcc92Bu3U0V09E=",
            auth.to_str()?,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_with_subresource() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder = RequestSigner::new("bucket")
            .with_time(Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, builder);

        let get_req =
            "http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        // CanonicalizedResource: /bucket/object.txt?name=hello
        assert_eq!(
            "OBS access_key:EaTKiO1Qh5KFUvWAVvbCNGktJUY=",
            auth.to_str()?,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sign_list_objects() -> Result<()> {
        let loader = StaticCredentialProvider::new("access_key", "123456");
        let builder = RequestSigner::new("bucket")
            .with_time(Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?);

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let signer = Signer::new(ctx, loader, builder);

        let get_req = "http://bucket.obs.cn-north-4.myhuaweicloud.com?name=hello&abc=def";
        let mut req = http::Request::get(Uri::from_str(get_req)?).body(())?;
        req.headers_mut().insert(
            HeaderName::from_str("Content-MD5")?,
            HeaderValue::from_str("abc")?,
        );
        req.headers_mut().insert(
            HeaderName::from_str("Content-Type")?,
            HeaderValue::from_str("text/plain")?,
        );

        // Signing request with Signer
        let (mut parts, _) = req.into_parts();
        signer.sign(&mut parts, None).await?;
        let headers = parts.headers;
        let auth = headers.get("Authorization").unwrap();

        // calculated from Huaweicloud OBS Signature tool
        // https://obs-community.obs.cn-north-1.myhuaweicloud.com/sign/header_signature.html
        // CanonicalizedResource: /bucket/?name=hello
        assert_eq!(
            "OBS access_key:9OdOsf8PRdhGhpkp7IIbKE0kRvA=",
            auth.to_str()?,
        );

        Ok(())
    }

    fn assert_parts_unchanged(actual: &http::request::Parts, expected: &http::request::Parts) {
        assert_eq!(actual.method, expected.method);
        assert_eq!(actual.uri, expected.uri);
        assert_eq!(actual.version, expected.version);
        assert_eq!(actual.headers, expected.headers);
    }

    #[tokio::test]
    async fn presign_rejects_unrepresentable_expiration_without_changing_the_request() -> Result<()>
    {
        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;
        let original = parts.clone();

        let err = signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                Some(Duration::MAX),
            )
            .await
            .expect_err("unrepresentable expiration must be rejected");

        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_parts_unchanged(&parts, &original);
        Ok(())
    }

    #[tokio::test]
    async fn presign_rejects_unbounded_lifetime_for_a_finite_credential() -> Result<()> {
        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None)
            .with_expires_at(now + Duration::from_secs(3600));
        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;
        let original = parts.clone();

        let err = signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                Some(Duration::MAX),
            )
            .await
            .expect_err("a finite credential cannot cover an unbounded lifetime");

        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert_parts_unchanged(&parts, &original);
        Ok(())
    }

    #[tokio::test]
    async fn presign_keeps_the_ordinary_expiration() -> Result<()> {
        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;

        signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                Some(Duration::from_secs(60)),
            )
            .await?;

        let query = parts.uri.query().expect("presigned URL must have a query");
        assert!(query.contains("Expires=1660582272"));
        assert!(query.contains("Signature="));
        Ok(())
    }

    #[tokio::test]
    async fn presign_rejects_expiration_that_does_not_advance_a_second() -> Result<()> {
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);

        for (now, expires_in) in [
            ("2022-08-15T16:50:12Z", Duration::ZERO),
            ("2022-08-15T16:50:12.700Z", Duration::ZERO),
            ("2022-08-15T16:50:12.700Z", Duration::from_millis(200)),
            ("1969-12-31T23:59:59Z", Duration::ZERO),
        ] {
            let now: Timestamp = now.parse()?;
            let signer = RequestSigner::new("bucket").with_time(now);
            let mut parts =
                http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
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
                .expect_err("expiration must advance to a later second");

            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
            assert_parts_unchanged(&parts, &original);
        }
        Ok(())
    }

    #[tokio::test]
    async fn presign_accepts_subsecond_expiration_that_advances_a_second() -> Result<()> {
        let now: Timestamp = "2022-08-15T16:50:12.700Z".parse()?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;

        signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                Some(Duration::from_millis(300)),
            )
            .await?;

        let query = parts.uri.query().expect("presigned URL must have a query");
        assert!(query.contains("Expires=1660582213"));
        assert!(query.contains("Signature="));
        Ok(())
    }

    #[tokio::test]
    async fn presign_uses_the_represented_lower_bound_before_the_epoch() -> Result<()> {
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);

        for (now, expires_in) in [
            ("1969-12-31T23:59:59.400Z", Duration::from_millis(200)),
            ("1969-12-31T23:59:59Z", Duration::from_secs(1)),
        ] {
            let now: Timestamp = now.parse()?;
            let signer = RequestSigner::new("bucket").with_time(now);
            let mut parts =
                http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                    .body(())?
                    .into_parts()
                    .0;

            signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential),
                    Some(expires_in),
                )
                .await?;

            let query = parts.uri.query().expect("presigned URL must have a query");
            assert!(query.contains("Expires=0"));
            assert!(query.contains("Signature="));
        }
        Ok(())
    }

    #[tokio::test]
    async fn presign_enforces_the_twenty_year_calendar_bound() -> Result<()> {
        let now: Timestamp = "2080-02-29T00:00:00Z".parse()?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let twenty_years = Duration::from_secs(631_065_600);

        let mut accepted =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut accepted,
                Some(&credential),
                Some(twenty_years - Duration::from_secs(1)),
            )
            .await?;
        let query = accepted
            .uri
            .query()
            .expect("presigned URL must have a query");
        assert!(query.contains("Expires=4107455999"));

        for expires_in in [twenty_years, twenty_years + Duration::from_secs(1)] {
            let mut parts =
                http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
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
                .expect_err("expiration must be strictly earlier than the 20-year bound");

            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
            assert_parts_unchanged(&parts, &original);
        }
        Ok(())
    }

    #[tokio::test]
    async fn presign_compares_the_fractional_anniversary_boundary() -> Result<()> {
        let now: Timestamp = "2080-02-29T00:00:00.700Z".parse()?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let twenty_years = Duration::from_secs(631_065_600);

        for expires_in in [twenty_years, twenty_years + Duration::from_millis(299)] {
            let mut parts =
                http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                    .body(())?
                    .into_parts()
                    .0;

            signer
                .sign_request(
                    &crate::test_context(),
                    &mut parts,
                    Some(&credential),
                    Some(expires_in),
                )
                .await?;

            let query = parts.uri.query().expect("presigned URL must have a query");
            assert!(query.contains("Expires=4107456000"));
            assert!(query.contains("Signature="));
        }

        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;
        let original = parts.clone();

        let err = signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                Some(twenty_years + Duration::from_millis(300)),
            )
            .await
            .expect_err("the encoded expiry must stay below the fractional anniversary bound");

        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        assert_parts_unchanged(&parts, &original);
        Ok(())
    }

    #[tokio::test]
    async fn presign_accepts_a_representable_expiration_near_the_timestamp_maximum() -> Result<()> {
        let max: Timestamp = jiff::Timestamp::MAX.to_string().parse()?;
        let now = max - Duration::from_secs(1);
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let mut parts =
            http::Request::get("http://bucket.obs.cn-north-4.myhuaweicloud.com/object.txt")
                .body(())?
                .into_parts()
                .0;

        signer
            .sign_request(
                &crate::test_context(),
                &mut parts,
                Some(&credential),
                Some(Duration::from_secs(1)),
            )
            .await?;

        let query = parts.uri.query().expect("presigned URL must have a query");
        assert!(query.contains(&format!("Expires={}", max.as_second())));
        assert!(query.contains("Signature="));
        Ok(())
    }

    #[tokio::test]
    async fn canonicalization_and_signing_preserve_wire_uri() -> Result<()> {
        let now = Timestamp::parse_rfc2822("Mon, 15 Aug 2022 16:50:12 GMT")?;
        let signer = RequestSigner::new("bucket").with_time(now);
        let credential = Credential::new("access_key".to_string(), "123456".to_string(), None);
        let original_uri =
            format!("http://bucket.obs.cn-north-4.myhuaweicloud.com/object%2Fname?{RAW_QUERY}");

        let mut canonical_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        let mut signing_req = SigningRequest::build(&mut canonical_parts)?;
        let string = string_to_sign(&mut signing_req, &credential, now, None, "bucket")?;
        assert!(string.ends_with("/bucket/object%2Fname?versionId=a+b=c%25&e"));

        let mut header_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut header_parts,
                Some(&credential),
                None,
            )
            .await?;
        assert_eq!(header_parts.uri.to_string(), original_uri);

        let mut query_parts = http::Request::get(&original_uri).body(())?.into_parts().0;
        signer
            .sign_request(
                &crate::test_context(),
                &mut query_parts,
                Some(&credential),
                Some(Duration::from_secs(60)),
            )
            .await?;
        assert!(query_parts.uri.to_string().starts_with(&original_uri));
        assert!(query_parts.uri.query().unwrap().contains("Signature="));

        Ok(())
    }
}
