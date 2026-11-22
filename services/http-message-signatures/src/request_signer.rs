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

//! RFC 9421 request signature generation.

use crate::Component;
use crate::Credential;
use crate::structured_field;
use http::HeaderMap;
use http::HeaderName;
use http::HeaderValue;
use http::header::HOST;
use http::request::Parts;
use http::uri::Authority;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, Result, SignRequest, SigningCredential};
use std::time::Duration;

const SIGNATURE_INPUT: HeaderName = HeaderName::from_static("signature-input");
const SIGNATURE: HeaderName = HeaderName::from_static("signature");

// These are the bounds accepted by jiff's `Timestamp::from_second`. The signer
// saturates its credential deadline here so a caller-supplied `Duration` cannot
// make `required_valid_until` panic. The signature itself still rejects an
// expiration outside the Structured Fields integer range.
const MIN_SAFE_UNIX_SECOND: i64 = -377_705_023_201;
const MAX_SAFE_UNIX_SECOND: i64 = 253_402_207_200;

/// Sign request heads with an RFC 9421 HTTP message signature.
///
/// The signer covers the caller-selected list of [`Component`] values in order.
/// It emits `created` and `keyid` parameters, the credential-derived `alg`
/// parameter by default, and `expires` when a duration is supplied.
///
/// The request URI must be an absolute HTTP or HTTPS URI. Its wire path, query
/// order, query repeats, and percent escapes are used unchanged. `@target-uri`
/// is reconstructed as `<scheme>://<authority><origin-form>`, using the
/// authority exactly as represented in the URI and an empty path as `/`.
///
/// A `Host` header, when present, must be unique and byte-identical to the URI
/// authority after trimming optional whitespace. This keeps the reconstructed
/// target URI equal to the URI an HTTP/1.1 origin-form receiver would build
/// from its request-target and `Host` field. A case-only or explicit/default
/// port difference is rejected as ambiguous instead of being silently
/// normalized into a different target URI. Origin-form request targets without
/// a URI authority are not accepted; callers must provide the absolute target
/// URI and the matching `Host` representation.
///
/// ## Body coverage
///
/// This crate does not read or hash the request body. A caller that wants body
/// coverage must compute a `Content-Digest` header before signing and include
/// it in the component list.
///
/// ## Backend availability
///
/// HMAC-SHA256 needs [`CryptoProvider::hmac_sha256`](reqsign_core::crypto::CryptoProvider::hmac_sha256).
/// RSA needs
/// [`CryptoProvider::rsa_pkcs1v15_sha256_sign`](reqsign_core::crypto::CryptoProvider::rsa_pkcs1v15_sha256_sign).
/// The RustCrypto provider supports RSA on native targets; on
/// `wasm32-unknown-unknown` the RSA operation returns `ConfigInvalid`.
#[derive(Debug)]
pub struct RequestSigner {
    label: String,
    components: Vec<Component>,
    include_algorithm: bool,
    time: Option<Timestamp>,
}

impl RequestSigner {
    /// Create a policy with a signature label and an ordered, nonempty,
    /// duplicate-free component list.
    ///
    /// The label is used as the `Signature-Input` and `Signature` dictionary
    /// key and must satisfy the RFC 8941 key syntax. The component order is
    /// preserved exactly in the signature base and signature parameters.
    pub fn new(
        label: impl Into<String>,
        components: impl IntoIterator<Item = Component>,
    ) -> Result<Self> {
        let label = label.into();
        if !structured_field::is_key(&label) {
            return Err(Error::config_invalid(
                "signature label is not a valid RFC 8941 dictionary key",
            ));
        }

        let components = components.into_iter().collect::<Vec<_>>();
        if components.is_empty() {
            return Err(Error::config_invalid(
                "signature coverage list must not be empty",
            ));
        }
        for (index, component) in components.iter().enumerate() {
            if components[..index].contains(component) {
                return Err(Error::config_invalid(
                    "signature coverage list contains a duplicate component",
                ));
            }
        }

        Ok(Self {
            label,
            components,
            include_algorithm: true,
            time: None,
        })
    }

    /// Set whether the credential-derived `alg` parameter is included.
    ///
    /// It is included by default. Some verifiers select the algorithm from the
    /// key identifier instead and expect it to be omitted.
    pub fn with_algorithm(mut self, include: bool) -> Self {
        self.include_algorithm = include;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    fn signing_time(&self) -> Timestamp {
        self.time.unwrap_or_else(crate::clock::now)
    }
}

impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        safe_deadline(self.signing_time(), expires_in)
    }

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let credential = credential.ok_or_else(|| {
            Error::credential_invalid("RFC 9421 request signing requires a credential")
        })?;
        let provider = ctx.crypto_provider()?;

        if req.headers.contains_key(SIGNATURE) || req.headers.contains_key(SIGNATURE_INPUT) {
            return Err(Error::request_invalid(
                "request already contains RFC 9421 signature headers",
            ));
        }

        let signing_time = self.signing_time();
        let required_until = safe_deadline(signing_time, expires_in);
        if !credential.is_valid_at(required_until) {
            return Err(Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }

        let created = signing_time.as_second();
        if !(structured_field::MIN_INTEGER..=structured_field::MAX_INTEGER).contains(&created) {
            return Err(Error::request_invalid(
                "signature creation time is outside the RFC 8941 integer range",
            ));
        }
        let expires = expiration(created, expires_in)?;

        let target = TargetContext::from_parts(req)?;
        let signature_parameters = signature_parameters(
            credential,
            &self.components,
            created,
            expires,
            self.include_algorithm,
        )?;
        let signature_base = signature_base(req, &target, &self.components, &signature_parameters)?;
        let signature_bytes = credential.sign(provider, signature_base.as_bytes())?;

        let signature_input_value = format!("{}={signature_parameters}", self.label);
        let signature_value = format!(
            "{}={}",
            self.label,
            structured_field::serialize_byte_sequence(&signature_bytes)
        );

        // Validate both header values before changing the request. If either
        // conversion fails, direct `SignRequest` callers keep the entire head.
        let mut signature_input_header = HeaderValue::from_str(&signature_input_value)
            .map_err(|_| Error::request_invalid("failed to encode Signature-Input header value"))?;
        let mut signature_header = HeaderValue::from_str(&signature_value)
            .map_err(|_| Error::request_invalid("failed to encode Signature header value"))?;
        signature_input_header.set_sensitive(true);
        signature_header.set_sensitive(true);

        req.headers.insert(SIGNATURE_INPUT, signature_input_header);
        req.headers.insert(SIGNATURE, signature_header);
        Ok(())
    }
}

pub(crate) struct TargetContext {
    method: String,
    target_uri: String,
    authority: String,
    scheme: String,
    path: String,
    query: String,
}

impl TargetContext {
    pub(crate) fn from_parts(parts: &Parts) -> Result<Self> {
        let uri = &parts.uri;
        let scheme = uri.scheme().ok_or_else(|| {
            Error::request_invalid("request URI must be absolute with an HTTP or HTTPS scheme")
        })?;
        let scheme_name = scheme.as_str();
        if !scheme_name.eq_ignore_ascii_case("http") && !scheme_name.eq_ignore_ascii_case("https") {
            return Err(Error::request_invalid(
                "request URI scheme must be HTTP or HTTPS",
            ));
        }

        let authority = uri
            .authority()
            .ok_or_else(|| Error::request_invalid("request URI must contain an authority"))?;
        let authority_raw = authority.as_str().to_string();
        let authority = normalize_authority(authority, scheme_name)?;
        validate_host_header(&parts.headers, &authority_raw)?;

        let path = uri.path();
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        let raw_query = uri.path_and_query().and_then(|target| target.query());
        let query = match raw_query {
            Some(query) => format!("?{query}"),
            None => "?".to_string(),
        };
        let target_uri = reconstruct_target_uri(
            &scheme_name.to_ascii_lowercase(),
            &authority_raw,
            &path,
            raw_query,
        )?;

        Ok(Self {
            method: parts.method.as_str().to_string(),
            target_uri,
            authority,
            scheme: scheme_name.to_ascii_lowercase(),
            path,
            query,
        })
    }

    fn value(&self, parts: &Parts, component: &Component) -> Result<String> {
        match component {
            Component::Header(name) => canonical_header_value(&parts.headers, name),
            Component::Method => {
                validate_derived_value("method", &self.method)?;
                Ok(self.method.clone())
            }
            Component::TargetUri => {
                validate_derived_value("target URI", &self.target_uri)?;
                Ok(self.target_uri.clone())
            }
            Component::Authority => {
                validate_derived_value("authority", &self.authority)?;
                Ok(self.authority.clone())
            }
            Component::Scheme => {
                validate_derived_value("scheme", &self.scheme)?;
                Ok(self.scheme.clone())
            }
            Component::Path => {
                validate_derived_value("path", &self.path)?;
                Ok(self.path.clone())
            }
            Component::Query => {
                validate_derived_value("query", &self.query)?;
                Ok(self.query.clone())
            }
        }
    }
}

fn normalize_authority(authority: &Authority, scheme: &str) -> Result<String> {
    let raw = authority.as_str();
    if raw.is_empty() || raw.contains('@') {
        return Err(Error::request_invalid(
            "request authority must not contain userinfo or be empty",
        ));
    }

    let host = authority.host();
    if host.is_empty() || host.contains('%') {
        return Err(Error::request_invalid(
            "request authority contains an unsupported host",
        ));
    }
    let port = explicit_port(authority)?;

    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let mut normalized = host.to_ascii_lowercase();
    if let Some(port) = port {
        if port != default_port {
            normalized.push(':');
            normalized.push_str(&port.to_string());
        }
    }

    Ok(normalized)
}

fn explicit_port(authority: &Authority) -> Result<Option<u16>> {
    let raw = authority.as_str();
    if raw.is_empty() || raw.contains('@') {
        return Err(Error::request_invalid(
            "request authority must not contain userinfo or be empty",
        ));
    }

    let host = authority.host();
    if host.is_empty() || host.contains('%') {
        return Err(Error::request_invalid(
            "request authority contains an unsupported host",
        ));
    }

    let suffix = raw
        .strip_prefix(host)
        .ok_or_else(|| Error::request_invalid("request authority contains a malformed host"))?;
    if suffix.is_empty() {
        return Ok(None);
    }

    let port = suffix
        .strip_prefix(':')
        .ok_or_else(|| Error::request_invalid("request authority contains a malformed port"))?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::request_invalid(
            "request authority contains a malformed port",
        ));
    }
    port.parse::<u16>()
        .map(Some)
        .map_err(|_| Error::request_invalid("request authority contains an out-of-range port"))
}

fn validate_host_header(headers: &HeaderMap, expected: &str) -> Result<()> {
    let mut values = headers.get_all(HOST).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(Error::request_invalid(
            "request contains more than one Host header",
        ));
    }

    let value = std::str::from_utf8(value.as_bytes())
        .map_err(|_| Error::request_invalid("Host header is not ASCII"))?
        .trim_matches(|character| matches!(character, ' ' | '\t'));
    if value.is_empty() {
        return Err(Error::request_invalid("Host header is empty"));
    }

    let host = value
        .parse::<Authority>()
        .map_err(|_| Error::request_invalid("Host header is not a valid authority"))?;
    explicit_port(&host)?;
    if host.as_str() != expected {
        return Err(Error::request_invalid(
            "Host header representation is inconsistent with the request URI authority",
        ));
    }

    Ok(())
}

fn reconstruct_target_uri(
    scheme: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
) -> Result<String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err(Error::request_invalid(
            "request URI path must be empty or an absolute path",
        ));
    }

    let mut target_uri = String::new();
    target_uri.push_str(scheme);
    target_uri.push_str("://");
    target_uri.push_str(authority);
    target_uri.push_str(path);
    if let Some(query) = query {
        target_uri.push('?');
        target_uri.push_str(query);
    }
    if target_uri.contains('#') {
        return Err(Error::request_invalid(
            "request target URI must not contain a fragment",
        ));
    }
    validate_derived_value("target URI", &target_uri)?;

    Ok(target_uri)
}

fn canonical_header_value(headers: &HeaderMap, name: &HeaderName) -> Result<String> {
    let mut values = headers.get_all(name).iter().peekable();
    if values.peek().is_none() {
        return Err(Error::request_invalid(format!(
            "covered header `{name}` is missing"
        )));
    }

    let mut output = String::new();
    let mut first = true;
    for value in values {
        if !first {
            output.push_str(", ");
        }
        first = false;

        let value = trim_ows(value.as_bytes());
        for byte in value {
            if !(*byte == b'\t' || (0x20..=0x7e).contains(byte)) {
                return Err(Error::request_invalid(format!(
                    "covered header `{name}` contains unsupported bytes"
                )));
            }
        }

        let value = std::str::from_utf8(value)
            .map_err(|_| Error::request_invalid(format!("covered header `{name}` is not ASCII")))?;
        output.push_str(value);
    }

    Ok(output)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn validate_derived_value(name: &str, value: &str) -> Result<()> {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !(byte == b' ' || (0x21..=0x7e).contains(&byte)))
        || value.starts_with(' ')
        || value.ends_with(' ')
    {
        return Err(Error::request_invalid(format!(
            "{name} is not a valid RFC 9421 component value"
        )));
    }

    Ok(())
}

fn expiration(created: i64, expires_in: Option<Duration>) -> Result<Option<i64>> {
    let Some(expires_in) = expires_in else {
        return Ok(None);
    };
    if expires_in.subsec_nanos() != 0 {
        return Err(Error::request_invalid(
            "expires_in must be a whole number of seconds",
        ));
    }

    let expires = i128::from(created) + i128::from(expires_in.as_secs());
    if expires < i128::from(created)
        || !(i128::from(structured_field::MIN_INTEGER)..=i128::from(structured_field::MAX_INTEGER))
            .contains(&expires)
    {
        return Err(Error::request_invalid(
            "signature expiration is outside the RFC 8941 integer range",
        ));
    }

    Ok(Some(expires as i64))
}

fn safe_deadline(signing_time: Timestamp, expires_in: Option<Duration>) -> Timestamp {
    let Some(expires_in) = expires_in else {
        return signing_time;
    };

    // Round sub-second durations up so a credential deadline never understates
    // the requested lifetime. `expiration` still rejects sub-second durations
    // before signing because RFC 9421 cannot represent them.
    let extra_seconds =
        i128::from(expires_in.as_secs()) + i128::from(u8::from(expires_in.subsec_nanos() != 0));
    let seconds = i128::from(signing_time.as_second()).saturating_add(extra_seconds);
    let seconds = seconds.clamp(
        i128::from(MIN_SAFE_UNIX_SECOND),
        i128::from(MAX_SAFE_UNIX_SECOND),
    ) as i64;

    Timestamp::from_second(seconds).unwrap_or(signing_time)
}

pub(crate) fn signature_parameters(
    credential: &Credential,
    components: &[Component],
    created: i64,
    expires: Option<i64>,
    include_algorithm: bool,
) -> Result<String> {
    let mut output = String::from("(");
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            output.push(' ');
        }
        output.push_str(&structured_field::serialize_string(
            &component.identifier(),
        )?);
    }
    output.push(')');

    output.push_str(";created=");
    output.push_str(&structured_field::serialize_integer(created)?);
    output.push_str(";keyid=");
    output.push_str(&structured_field::serialize_string(credential.keyid())?);
    if include_algorithm {
        output.push_str(";alg=");
        output.push_str(&structured_field::serialize_string(credential.algorithm())?);
    }
    if let Some(expires) = expires {
        output.push_str(";expires=");
        output.push_str(&structured_field::serialize_integer(expires)?);
    }

    Ok(output)
}

pub(crate) fn signature_base(
    parts: &Parts,
    target: &TargetContext,
    components: &[Component],
    signature_parameters: &str,
) -> Result<String> {
    let mut output = String::new();
    for component in components {
        output.push_str(&structured_field::serialize_string(
            &component.identifier(),
        )?);
        output.push_str(": ");
        output.push_str(&target.value(parts, component)?);
        output.push('\n');
    }
    output.push_str("\"@signature-params\": ");
    output.push_str(signature_parameters);

    if !output.is_ascii() {
        return Err(Error::request_invalid(
            "signature base contains non-ASCII characters",
        ));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_deadline_saturates_instead_of_panicking() {
        let now = Timestamp::from_second(1_618_884_480).unwrap();
        assert!(safe_deadline(now, Some(Duration::MAX)) > now);
        assert!(safe_deadline(now, Some(Duration::from_nanos(1))) > now);
        assert_eq!(safe_deadline(now, None), now);
    }

    #[test]
    fn explicit_ports_are_parsed_strictly() {
        for raw in ["example.net:invalid", "example.net:65536", "example.net:"] {
            let authority: Authority = raw.parse().expect("authority parser accepts the shape");
            assert!(explicit_port(&authority).is_err(), "{raw}");
        }
        for raw in ["example.net", "example.net:0", "example.net:65535"] {
            let authority: Authority = raw.parse().expect("authority must parse");
            assert!(explicit_port(&authority).is_ok(), "{raw}");
        }
    }

    #[test]
    fn expiration_requires_whole_seconds_and_sf_bounds() {
        assert_eq!(
            expiration(100, Some(Duration::from_secs(5))).unwrap(),
            Some(105)
        );
        assert_eq!(
            expiration(100, Some(Duration::from_millis(1_500)))
                .unwrap_err()
                .kind(),
            reqsign_core::ErrorKind::RequestInvalid
        );
        assert!(expiration(structured_field::MAX_INTEGER, Some(Duration::from_secs(1))).is_err());
    }
}
