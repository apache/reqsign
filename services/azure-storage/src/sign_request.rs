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

use crate::Credential;
use crate::constants::*;
use crate::service_sas::ServiceSasResource;
use crate::user_delegation::{
    MAX_USER_DELEGATION_KEY_LIFETIME, UserDelegationKeyCache, ceil_to_wire_second,
    floor_to_wire_second, user_delegation_key_covers,
};
use http::request::Parts;
use http::{HeaderValue, Uri, header};
use reqsign_core::hash::{base64_decode, base64_hmac_sha256};
use reqsign_core::time::Timestamp;
use reqsign_core::{
    Context, Error, Result, SignRequest, SigningCredential, SigningMethod, SigningRequest,
};
use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::sync::Mutex;
use std::time::Duration;

const BEARER_TOKEN_OPERATION_HEADROOM: Duration = Duration::from_secs(20);

/// Resource kind required by SAS generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SasResourceKind {
    /// Container SAS.
    Container,
    /// Blob SAS.
    Blob,
}

/// Sign Azure Storage requests, or explicitly use [Bearer header signing](Self::bearer).
///
/// - [Authorize with Shared Key](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
///
/// Shared Key query signing creates a Service SAS. Its encoded expiry second
/// must reach a future wire second and remain representable in the SAS
/// timestamp. A subsecond lifetime is accepted only when it advances the
/// encoded second.
///
/// - [Create a service SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas)
/// - [Format date/time values](https://learn.microsoft.com/en-us/rest/api/storageservices/formatting-datetime-values)
pub struct RequestSigner {
    bearer_only: bool,
    time: Option<Timestamp>,
    service_sas_permissions: Option<String>,
    service_sas_start: Option<Timestamp>,
    service_sas_ip: Option<String>,
    service_sas_protocol: Option<String>,
    service_sas_version: Option<String>,

    user_delegation_presign: Option<UserDelegationPresignConfig>,
    user_delegation_key_cache: Mutex<UserDelegationKeyCache<UserDelegationPresignCacheKey>>,
}

#[derive(Clone, Debug)]
struct UserDelegationPresignConfig {
    resource: SasResourceKind,
    permissions: String,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: Option<String>,
    version: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct UserDelegationPresignCacheKey {
    account: String,
    endpoint: String,
    source_authority: String,
    version: String,
}

impl Debug for RequestSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSigner").finish_non_exhaustive()
    }
}

impl RequestSigner {
    /// Create a signer for Azure Storage requests.
    pub fn new() -> Self {
        Self {
            bearer_only: false,
            time: None,
            service_sas_permissions: None,
            service_sas_start: None,
            service_sas_ip: None,
            service_sas_protocol: None,
            service_sas_version: None,

            user_delegation_presign: None,
            user_delegation_key_cache: Mutex::new(UserDelegationKeyCache::default()),
        }
    }

    /// Sign non-Storage Azure API requests with a sensitive `Authorization: Bearer` header.
    ///
    /// Supply a bearer credential for the API's resource and pass `None` for
    /// `expires_in`. This mode requires a bearer credential, preserves the URI
    /// and all other headers, and rejects presigning.
    pub fn bearer() -> Self {
        Self {
            bearer_only: true,
            ..Self::new()
        }
    }

    /// Configure Service SAS presign permissions for Shared Key query signing.
    ///
    /// This setting is required when `expires_in` is provided and credential is `SharedKey`.
    pub fn with_service_sas_permissions(mut self, permissions: &str) -> Self {
        self.service_sas_permissions = Some(permissions.to_string());
        self
    }

    /// Configure Service SAS presign start time for Shared Key query signing.
    ///
    /// The start keeps the signer's existing whole-second formatting. An
    /// explicit start at or after the encoded expiry returns `RequestInvalid`
    /// before the request changes.
    pub fn with_service_sas_start(mut self, start: Timestamp) -> Self {
        self.service_sas_start = Some(start);
        self
    }

    /// Configure Service SAS presign allowed IP range.
    pub fn with_service_sas_ip(mut self, ip: &str) -> Self {
        self.service_sas_ip = Some(ip.to_string());
        self
    }

    /// Configure Service SAS presign allowed protocol, e.g. `https` or `https,http`.
    pub fn with_service_sas_protocol(mut self, protocol: &str) -> Self {
        self.service_sas_protocol = Some(protocol.to_string());
        self
    }

    /// Configure Service SAS presign service version.
    pub fn with_service_sas_version(mut self, version: &str) -> Self {
        self.service_sas_version = Some(version.to_string());
        self
    }

    /// Enable User Delegation SAS presign for Bearer Token query signing.
    ///
    /// This is only used when `expires_in` is provided and credential is `BearerToken`.
    pub fn with_user_delegation_presign(
        mut self,
        resource: SasResourceKind,
        permissions: &str,
    ) -> Self {
        self.user_delegation_presign = Some(UserDelegationPresignConfig {
            resource,
            permissions: permissions.to_string(),
            start: None,
            ip: None,
            protocol: None,
            version: None,
        });
        self
    }

    /// Configure User Delegation SAS presign start time.
    pub fn with_user_delegation_start(mut self, start: Timestamp) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.start = Some(start);
        }
        self
    }

    /// Configure User Delegation SAS presign allowed IP range.
    pub fn with_user_delegation_ip(mut self, ip: &str) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.ip = Some(ip.to_string());
        }
        self
    }

    /// Configure User Delegation SAS presign allowed protocol, e.g. `https` or `https,http`.
    pub fn with_user_delegation_protocol(mut self, protocol: &str) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.protocol = Some(protocol.to_string());
        }
        self
    }

    /// Configure User Delegation SAS presign service version.
    pub fn with_user_delegation_version(mut self, version: &str) -> Self {
        if let Some(cfg) = self.user_delegation_presign.as_mut() {
            cfg.version = Some(version.to_string());
        }
        self
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
        credential: &Credential,
        signing_time: Timestamp,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        match credential {
            Credential::BearerToken { .. } => signing_time + BEARER_TOKEN_OPERATION_HEADROOM,
            Credential::SharedKey { .. } | Credential::SasToken { .. } => signing_time,
        }
    }
}

impl Default for RequestSigner {
    fn default() -> Self {
        Self::new()
    }
}
impl SignRequest for RequestSigner {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Timestamp {
        self.required_valid_until_at(credential, self.get_time(), expires_in)
    }

    async fn sign_request(
        &self,
        context: &Context,
        req: &mut Parts,
        credential: Option<&Self::Credential>,
        expires_in: Option<Duration>,
    ) -> Result<()> {
        let Some(cred) = credential else {
            return if self.bearer_only {
                Err(reqsign_core::Error::credential_invalid(
                    "Azure Bearer signing requires a bearer token",
                ))
            } else {
                Ok(())
            };
        };

        let signing_time = self.get_time();
        let required_until = self.required_valid_until_at(cred, signing_time, expires_in);
        if !cred.is_valid_at(required_until) {
            return Err(reqsign_core::Error::credential_invalid(
                "credential expires before the requested signing operation deadline",
            ));
        }
        if self.bearer_only {
            let Credential::BearerToken { token, .. } = cred else {
                return Err(reqsign_core::Error::credential_invalid(
                    "Azure Bearer signing requires a bearer token",
                ));
            };
            if expires_in.is_some() {
                return Err(reqsign_core::Error::request_invalid(
                    "Azure Bearer signing does not support presigning",
                ));
            }
            if req.uri.authority().is_none() {
                return Err(reqsign_core::Error::request_invalid(
                    "Azure Bearer signing requires a request URI with an authority",
                ));
            }
            req.headers
                .insert(header::AUTHORIZATION, bearer_authorization(token)?);
            return Ok(());
        }
        let method = if let Some(expires_in) = expires_in {
            SigningMethod::Query(expires_in)
        } else {
            SigningMethod::Header
        };

        let original_uri = req.uri.clone();
        let mut sctx = SigningRequest::build(req)?;
        let mut final_uri = None;

        // Handle different credential types
        match cred {
            Credential::SasToken { token, .. } => {
                // SAS token authentication
                final_uri = Some(append_query_fragment(&original_uri, token)?);
            }
            Credential::BearerToken { token, .. } => {
                // Bearer token authentication
                match method {
                    SigningMethod::Query(d) => {
                        let Some(cfg) = &self.user_delegation_presign else {
                            return Err(reqsign_core::Error::request_invalid(
                                "BearerToken can't be used in query string",
                            ));
                        };
                        if d.is_zero() || d > MAX_USER_DELEGATION_KEY_LIFETIME {
                            return Err(reqsign_core::Error::request_invalid(
                                "Azure user delegation SAS lifetime must be greater than zero and at most seven days",
                            ));
                        }
                        let expiry = floor_to_wire_second(signing_time + d)?;
                        if expiry <= signing_time {
                            return Err(reqsign_core::Error::request_invalid(
                                "Azure user delegation SAS lifetime does not reach a future wire timestamp",
                            ));
                        }
                        let start = cfg.start.map(ceil_to_wire_second).transpose()?;
                        if start.is_some_and(|start| start >= expiry) {
                            return Err(reqsign_core::Error::request_invalid(
                                "Azure user delegation SAS start time must be before its expiration",
                            ));
                        }
                        let key_start = floor_to_wire_second(
                            start.map_or(signing_time, |start| start.min(signing_time)),
                        )?;
                        if expiry > key_start + MAX_USER_DELEGATION_KEY_LIFETIME {
                            return Err(reqsign_core::Error::request_invalid(
                                "Azure user delegation SAS interval exceeds the seven-day user delegation key limit",
                            ));
                        }

                        let resource = ServiceSasResource::from_uri_path(&sctx.path)?;
                        match (cfg.resource, &resource) {
                            (SasResourceKind::Container, ServiceSasResource::Container { .. }) => {}
                            (SasResourceKind::Blob, ServiceSasResource::Blob { .. }) => {}
                            _ => {
                                return Err(reqsign_core::Error::request_invalid(
                                    "request resource doesn't match configured SAS resource kind",
                                ));
                            }
                        }

                        let provider = context.crypto_provider()?;
                        let account = infer_account_name(sctx.authority.as_str())?;
                        let version = cfg.version.as_deref().unwrap_or("2020-12-06");
                        let cache_key = UserDelegationPresignCacheKey {
                            account: account.clone(),
                            endpoint: format!("{}://{}", sctx.scheme, sctx.authority),
                            source_authority: reqsign_core::hash::hex_sha256(
                                provider,
                                token.as_bytes(),
                            )?,
                            version: version.to_string(),
                        };

                        let effective_start = start.unwrap_or(signing_time);
                        let key = {
                            let cached = self
                                .user_delegation_key_cache
                                .lock()
                                .expect("lock poisoned")
                                .find_cloned(&cache_key, |key| {
                                    user_delegation_key_covers(
                                        key,
                                        effective_start,
                                        expiry,
                                        signing_time,
                                        version,
                                    )
                                });
                            if let Some(cached) = cached {
                                cached
                            } else {
                                let required_until =
                                    self.get_time() + BEARER_TOKEN_OPERATION_HEADROOM;
                                if !cred.is_valid_at(required_until) {
                                    return Err(reqsign_core::Error::credential_invalid(
                                        "Azure bearer token expires before the user delegation key request can complete",
                                    ));
                                }
                                let fetched = crate::user_delegation::get_user_delegation_key(
                                    context,
                                    crate::user_delegation::UserDelegationKeyRequest {
                                        scheme: sctx.scheme.as_str(),
                                        authority: sctx.authority.as_str(),
                                        bearer_token: token,
                                        start: key_start,
                                        expiry,
                                        service_version: version,
                                        now: signing_time,
                                    },
                                )
                                .await?;
                                let after_io = self.get_time();
                                if !user_delegation_key_covers(
                                    &fetched,
                                    effective_start,
                                    expiry,
                                    after_io,
                                    version,
                                ) {
                                    return Err(reqsign_core::Error::credential_invalid(
                                        "Azure user delegation key does not cover the requested SAS interval",
                                    ));
                                }
                                let mut cache = self
                                    .user_delegation_key_cache
                                    .lock()
                                    .expect("lock poisoned");
                                cache.insert(cache_key, fetched.clone(), after_io);
                                fetched
                            }
                        };

                        let mut signer =
                            crate::user_delegation::UserDelegationSharedAccessSignature::new(
                                account,
                                key,
                                resource.into(),
                                cfg.permissions.to_string(),
                                expiry,
                            );
                        if let Some(start) = start {
                            signer = signer.with_start(start);
                        }
                        if let Some(ip) = &cfg.ip {
                            signer = signer.with_ip(ip);
                        }
                        if let Some(protocol) = &cfg.protocol {
                            signer = signer.with_protocol(protocol);
                        }
                        if let Some(version) = &cfg.version {
                            signer = signer.with_version(version);
                        }

                        let signer_token = signer.token(provider).map_err(|e| {
                            reqsign_core::Error::new(
                                e.kind(),
                                "failed to generate user delegation SAS token",
                            )
                            .with_source(e)
                        })?;
                        final_uri = Some(append_query_pairs(&original_uri, &signer_token)?);
                    }
                    SigningMethod::Header => {
                        sctx.headers.insert(
                            X_MS_DATE,
                            signing_time.format_http_date().parse().map_err(|e| {
                                reqsign_core::Error::unexpected("failed to parse date header")
                                    .with_source(e)
                            })?,
                        );
                        sctx.headers
                            .insert(header::AUTHORIZATION, bearer_authorization(token)?);
                    }
                }
            }
            Credential::SharedKey {
                account_name,
                account_key,
            } => {
                // Shared key authentication
                match method {
                    SigningMethod::Query(d) => {
                        let Some(permissions) = &self.service_sas_permissions else {
                            return Err(reqsign_core::Error::request_invalid(
                                "Service SAS permissions are required for presign",
                            ));
                        };

                        let resource = ServiceSasResource::from_uri_path(&sctx.path)?;
                        let provider = context.crypto_provider()?;
                        let expiry = crate::service_sas::expiry_at_wire_second(signing_time, d)?;
                        if expiry <= signing_time {
                            return Err(reqsign_core::Error::request_invalid(
                                "Azure Service SAS lifetime does not reach a future wire timestamp",
                            ));
                        }
                        let start = self.service_sas_start;
                        if start.is_some_and(|start| start >= expiry) {
                            return Err(reqsign_core::Error::request_invalid(
                                "Azure Service SAS start time must be before its expiration",
                            ));
                        }

                        let mut signer = crate::service_sas::ServiceSharedAccessSignature::new(
                            account_name.clone(),
                            account_key.clone(),
                            resource,
                            permissions.to_string(),
                            expiry,
                        );
                        if let Some(start) = start {
                            signer = signer.with_start(start);
                        }
                        if let Some(ip) = &self.service_sas_ip {
                            signer = signer.with_ip(ip);
                        }
                        if let Some(protocol) = &self.service_sas_protocol {
                            signer = signer.with_protocol(protocol);
                        }
                        if let Some(version) = &self.service_sas_version {
                            signer = signer.with_version(version);
                        }
                        // The working query view is decoded once. Azure requires the
                        // URL-decoded response override value in the string-to-sign.
                        if let Some((_, value)) = sctx.query.iter().find(|(name, _)| name == "rscd")
                        {
                            signer = signer.with_content_disposition(value.clone());
                        }

                        let signer_token = signer.token(provider).map_err(|e| {
                            reqsign_core::Error::new(
                                e.kind(),
                                "failed to generate service SAS token",
                            )
                            .with_source(e)
                        })?;
                        final_uri = Some(append_query_pairs(&original_uri, &signer_token)?);
                    }
                    SigningMethod::Header => {
                        let provider = context.crypto_provider()?;
                        sctx.headers.insert(
                            X_MS_DATE,
                            signing_time.format_http_date().parse().map_err(|e| {
                                Error::unexpected("failed to parse x-ms-date header").with_source(e)
                            })?,
                        );
                        let string_to_sign = string_to_sign(&sctx, account_name)?;
                        let decode_content = base64_decode(account_key).map_err(|e| {
                            reqsign_core::Error::unexpected("failed to decode account key")
                                .with_source(e)
                        })?;
                        let signature = base64_hmac_sha256(
                            provider,
                            &decode_content,
                            string_to_sign.as_bytes(),
                        )?;

                        sctx.headers.insert(header::AUTHORIZATION, {
                            let mut value: HeaderValue =
                                format!("SharedKey {account_name}:{signature}")
                                    .parse()
                                    .map_err(|e| {
                                        reqsign_core::Error::unexpected(
                                            "failed to parse authorization header",
                                        )
                                        .with_source(e)
                                    })?;
                            value.set_sensitive(true);
                            value
                        });
                    }
                }
            }
        }

        sctx.apply(req)?;
        if let Some(uri) = final_uri {
            req.uri = uri;
        }
        Ok(())
    }
}

fn bearer_authorization(token: &str) -> Result<HeaderValue> {
    let mut value: HeaderValue = format!("Bearer {token}").parse().map_err(|err| {
        reqsign_core::Error::unexpected("failed to parse authorization header").with_source(err)
    })?;
    value.set_sensitive(true);
    Ok(value)
}

fn append_query_pairs(uri: &Uri, pairs: &[(String, String)]) -> Result<Uri> {
    let fragment = crate::service_sas::encode_query_pairs(pairs);
    append_query_fragment(uri, &fragment)
}

fn append_query_fragment(uri: &Uri, fragment: &str) -> Result<Uri> {
    if fragment.is_empty() {
        return Ok(uri.clone());
    }

    let mut value = uri.to_string();
    if uri.query().is_none() {
        value.push('?');
    } else if !value.ends_with('?') && !value.ends_with('&') {
        value.push('&');
    }
    value.push_str(fragment);

    value.parse().map_err(|e| {
        reqsign_core::Error::request_invalid("failed to append SAS query fragment").with_source(e)
    })
}

fn infer_account_name(authority: &str) -> Result<String> {
    let host = authority.split('@').next_back().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    let Some((account, _)) = host.split_once('.') else {
        return Err(reqsign_core::Error::request_invalid(
            "failed to infer account name from authority",
        ));
    };
    Ok(account.to_string())
}

/// Construct string to sign
///
/// ## Format
///
/// ```text
/// VERB + "\n" +
/// Content-Encoding + "\n" +
/// Content-Language + "\n" +
/// Content-Length + "\n" +
/// Content-MD5 + "\n" +
/// Content-Type + "\n" +
/// Date + "\n" +
/// If-Modified-Since + "\n" +
/// If-Match + "\n" +
/// If-None-Match + "\n" +
/// If-Unmodified-Since + "\n" +
/// Range + "\n" +
/// CanonicalizedHeaders +
/// CanonicalizedResource;
/// ```
/// ## Note
///
/// Reqsign signs the Azure service headers already present on the request.
/// Callers should include `x-ms-version` for ordinary Azure Storage requests,
/// but omit it for batch API sub-requests, which Azure requires to be signed
/// without that header.
///
/// ## Reference
///
/// - [Blob, Queue, and File Services (Shared Key authorization)](https://docs.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key)
fn string_to_sign(ctx: &SigningRequest, account_name: &str) -> Result<String> {
    let mut signing = String::with_capacity(128);
    signing.push_str(ctx.method.as_str());
    signing.push('\n');

    for name in [
        header::CONTENT_ENCODING,
        header::CONTENT_LANGUAGE,
        header::CONTENT_LENGTH,
        header::HeaderName::from_static(CONTENT_MD5),
        header::CONTENT_TYPE,
        header::DATE,
        header::IF_MODIFIED_SINCE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
        header::IF_UNMODIFIED_SINCE,
        header::RANGE,
    ] {
        let value = if name == header::DATE {
            // Shared Key signing supplies x-ms-date in the canonicalized headers.
            ""
        } else {
            ctx.header_get_or_default(&name)
                .map_err(|error| error.with_context(&name))?
        };
        if name != header::CONTENT_LENGTH || value != "0" {
            signing.push_str(value);
        }
        signing.push('\n');
    }

    append_canonicalized_headers(ctx, &mut signing)?;
    append_canonicalized_resource(ctx, account_name, &mut signing);
    Ok(signing)
}

/// [Constructing the canonicalized headers string](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-headers-string)
fn append_canonicalized_headers(ctx: &SigningRequest, output: &mut String) -> Result<()> {
    let mut names: Vec<_> = ctx
        .headers
        .keys()
        .map(header::HeaderName::as_str)
        .filter(|name| name.starts_with("x-ms-"))
        .collect();
    names.sort_unstable_by(|left, right| header_name_weights(left).cmp(header_name_weights(right)));

    for name in names {
        output.push_str(name);
        output.push(':');
        // HeaderMap keeps values for a name in insertion order.
        for (index, value) in ctx.headers.get_all(name).iter().enumerate() {
            let value = value.to_str().map_err(|error| {
                Error::request_invalid("invalid Azure Shared Key header value")
                    .with_context(name)
                    .with_source(error)
            })?;
            if index > 0 {
                output.push(',');
            }
            append_normalized_header_value(output, value);
        }
        output.push('\n');
    }
    Ok(())
}

fn header_name_weights(name: &str) -> impl Iterator<Item = u8> + '_ {
    // Azure sorts '_' before digits in metadata names. These are the Azure SDK for
    // Python's character weights for lowercase ASCII header names.
    // https://github.com/Azure/azure-sdk-for-python/pull/26991
    const WEIGHTS: [u8; 128] = {
        let order = b"-!#$%&*.^_|~+\"'`0123456789abcdefghijklmnopqrstuvwxyz";
        let mut weights = [u8::MAX; 128];
        let mut rank = 0;
        while rank < order.len() {
            weights[order[rank] as usize] = rank as u8;
            rank += 1;
        }
        weights
    };
    name.bytes().map(|byte| WEIGHTS[usize::from(byte)])
}

fn append_normalized_header_value(output: &mut String, value: &str) {
    let mut in_quotes = false;
    let mut escaped = false;
    let mut pending_space = false;
    // HeaderValue excludes CR and LF, leaving only spaces and tabs to fold.
    for character in value.trim_start_matches([' ', '\t']).chars() {
        if !in_quotes && matches!(character, ' ' | '\t') {
            pending_space = true;
            continue;
        }
        if pending_space {
            output.push(' ');
            pending_space = false;
        }
        output.push(character);

        if escaped {
            escaped = false;
        } else {
            match character {
                '\\' if in_quotes => escaped = true,
                '"' => in_quotes = !in_quotes,
                _ => {}
            }
        }
    }
}

/// [Constructing the canonicalized resource string](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#constructing-the-canonicalized-resource-string)
fn append_canonicalized_resource(ctx: &SigningRequest, account_name: &str, output: &mut String) {
    output.push('/');
    output.push_str(account_name);
    output.push_str(&ctx.path);

    // The decoded query view preserves a raw '+' as data for Shared Key signing.
    // https://github.com/Azure/azure-sdk-for-js/blob/bc12ee66f4cb9a1e3fddf51279ba254fe8953994/sdk/storage/storage-common/test/node/sharedKeySigning.spec.ts#L226-L231
    let mut query: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (name, value) in &ctx.query {
        query.entry(name.to_lowercase()).or_default().push(value);
    }
    for (name, mut values) in query {
        values.sort_unstable();
        output.push('\n');
        output.push_str(&name);
        output.push(':');
        output.push_str(&values.join(","));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::Request;
    use reqsign_core::{ErrorKind, HttpSend, OsEnv, Signer};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const RAW_QUERY: &str = "slash=%2F&hash=%23&amp=%26&equals=%3D&space=%20&encoded-plus=%2B&literal-plus=+&double=%252F&dup=first&dup=second&=empty-key&empty=&flag&flag=&";

    #[test]
    fn bearer_deadline_covers_rpc_not_generated_sas_lifetime() {
        let now: Timestamp = "2026-07-22T00:00:00Z"
            .parse()
            .expect("timestamp must parse");
        let signer = RequestSigner::new().with_time(now);
        let bearer = Credential::with_bearer_token("token", None);
        let shared_key = Credential::with_shared_key("account", "key");

        assert_eq!(
            signer.required_valid_until(&bearer, Some(Duration::from_secs(3600))),
            now + BEARER_TOKEN_OPERATION_HEADROOM
        );
        assert_eq!(
            signer.required_valid_until(&shared_key, Some(Duration::from_secs(3600))),
            now
        );
    }

    const SHARED_KEY_ACCOUNT: &str = "azsignfixture";
    const SHARED_KEY_BYTES: &[u8] = b"reqsign-azure-shared-key-fixture";
    const SHARED_KEY_URI: &str = "https://azsignfixture.example/container/blob%2fname";
    const SHARED_KEY_DATE: &str = "Tue, 01 Mar 2022 08:12:34 GMT";

    fn shared_key_request_signer() -> RequestSigner {
        RequestSigner::new().with_time("2022-03-01T08:12:34Z".parse().unwrap())
    }

    #[tokio::test]
    async fn shared_key_header_signs_x_ms_headers_in_azure_order() {
        let key = reqsign_core::hash::base64_encode(SHARED_KEY_BYTES);
        let signer = Signer::new(
            crate::test_context(),
            crate::StaticCredentialProvider::new_shared_key(SHARED_KEY_ACCOUNT, &key),
            shared_key_request_signer(),
        );
        let mut parts = Request::put(SHARED_KEY_URI)
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONTENT_LANGUAGE, "en")
            .header(header::CONTENT_LENGTH, "42")
            .header("content-md5", "bOWa0jy0OvR28Eh1kl5Cpg==")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::IF_MATCH, "\"fixture-etag\"")
            .header("x-ms-version", "2021-12-02")
            .header("x-ms-meta-i0", "zero")
            .header(
                "X-MS-Meta-I_",
                " \t zeta \t \"two\t  words \\\"stay  quoted\\\" ends\\\\\" \t tail \t",
            )
            .header("x-ms-meta-i9", "nine")
            .header("x-ms-meta-ia", "letter")
            .header("x-ms-meta-i", "prefix")
            .header("x-ms-meta-blank", " \t ")
            .header("x-ms-meta-i_", "  alpha \t\t beta \t")
            .header("x-ms-meta-_leading", "leading underscore")
            .header("x-ms-meta-i__", "two underscores")
            .header("x-ms-blob-type", "BlockBlob")
            .header("x-original", HeaderValue::from_bytes(b" \xff\t ").unwrap())
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let original_headers = parts.headers.clone();

        signer.sign(&mut parts, None).await.unwrap();

        let authorization = parts.headers.remove(header::AUTHORIZATION).unwrap();
        // Python hmac over these lines in the Azure SDK for Python's order:
        // x-ms-meta-_leading:leading underscore
        // x-ms-meta-blank:
        // x-ms-meta-i:prefix
        // x-ms-meta-i_:zeta "two\t  words \"stay  quoted\" ends\\" tail,alpha beta
        // x-ms-meta-i__:two underscores
        // x-ms-meta-i0:zero
        // x-ms-meta-i9:nine
        // x-ms-meta-ia:letter
        assert_eq!(
            authorization,
            concat!(
                "SharedKey azsignfixture:",
                "mFfPFGISqmdN+D/zGtbJd+1aygNlsWcD7ahCPjskLuM="
            )
        );
        assert!(authorization.is_sensitive());
        assert_eq!(parts.headers.remove(X_MS_DATE).unwrap(), SHARED_KEY_DATE);
        assert_eq!(parts.headers, original_headers);
        assert_eq!(parts.uri.to_string(), SHARED_KEY_URI);
    }

    #[tokio::test]
    async fn shared_key_header_signs_grouped_decoded_query() {
        let uri = format!(
            "{SHARED_KEY_URI}?Zed=last&Dup=%7a&dUP=A&%44UP=%31&dup=A&dup=&flag&Empty=&raw=x+y&encoded-plus=x%2By&encoded-space=x%20y&escaped=%2B%3D%26%252F&comp=list&"
        );
        let mut parts = Request::get(&uri)
            .header(header::CONTENT_LENGTH, "0")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let original_headers = parts.headers.clone();
        let key = reqsign_core::hash::base64_encode(SHARED_KEY_BYTES);
        let credential = Credential::with_shared_key(SHARED_KEY_ACCOUNT, &key);

        shared_key_request_signer()
            .sign_request(&crate::test_context(), &mut parts, Some(&credential), None)
            .await
            .unwrap();

        // HMAC over the output from Azure SDK for JavaScript storage-common 12.6.0-beta.1:
        // /azsignfixture/container/blob%2fname
        // comp:list
        // dup:,1,A,A,z
        // empty:
        // encoded-plus:x+y
        // encoded-space:x y
        // escaped:+=&%2F
        // flag:
        // raw:x+y
        // zed:last
        assert_eq!(
            parts.headers.remove(header::AUTHORIZATION).unwrap(),
            concat!(
                "SharedKey azsignfixture:",
                "bnvwitjYdYeL2Pcg91shnx859540aU8lAye64pb1FqA="
            )
        );
        assert_eq!(parts.headers.remove(X_MS_DATE).unwrap(), SHARED_KEY_DATE);
        assert_eq!(parts.headers, original_headers);
        assert_eq!(parts.uri.to_string(), uri);
    }

    #[tokio::test]
    async fn shared_key_header_rejects_invalid_signed_values_atomically() {
        let context = crate::test_context();
        let signer = shared_key_request_signer();
        let key = reqsign_core::hash::base64_encode(SHARED_KEY_BYTES);
        let credential = Credential::with_shared_key(SHARED_KEY_ACCOUNT, &key);
        let uri = format!("{SHARED_KEY_URI}?dup=%2f&dup=&flag");
        for name in ["x-ms-meta-note", "content-type"] {
            let mut parts = Request::get(&uri)
                .header(header::AUTHORIZATION, "previous authorization")
                .header(X_MS_DATE, "Mon, 28 Feb 2022 08:12:34 GMT")
                .header("x-ms-meta-note", "valid first value")
                .header(name, HeaderValue::from_bytes(b"opaque-\xff").unwrap())
                .extension(42u32)
                .body(())
                .unwrap()
                .into_parts()
                .0;
            let original = parts.clone();

            let error = signer
                .sign_request(&context, &mut parts, Some(&credential), None)
                .await
                .expect_err("malformed signed header must fail");

            assert_eq!(error.kind(), ErrorKind::RequestInvalid, "{name}");
            assert_eq!(error.context(), [name]);
            assert_eq!(parts.headers, original.headers);
            assert_eq!(parts.uri.to_string(), uri);
            assert_eq!(parts.method, original.method);
            assert_eq!(parts.version, original.version);
            assert_eq!(parts.extensions.get::<u32>(), Some(&42));
        }
    }

    #[tokio::test]
    async fn test_sas_token() {
        let _ = env_logger::builder().is_test(true).try_init();

        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let cred = Credential::with_sas_token(
            "sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D",
        );

        let builder = RequestSigner::new();
        let original_uri =
            format!("https://test.blob.core.windows.net/testbucket/testblob?{RAW_QUERY}");

        // Construct request
        let req = Request::builder().uri(&original_uri).body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        // A SAS credential selects query authentication even without expires_in.
        assert!(
            builder
                .sign_request(&ctx, &mut parts, Some(&cred), None)
                .await
                .is_ok()
        );
        assert_eq!(
            parts.uri.to_string(),
            format!(
                "{original_uri}sv=2021-01-01&ss=b&srt=c&sp=rwdlaciytfx&se=2022-01-01T11:00:14Z&st=2022-01-02T03:00:14Z&spr=https&sig=KEllk4N8f7rJfLjQCmikL2fRVt%2B%2Bl73UBkbgH%2FK3VGE%3D"
            )
        )
    }

    #[tokio::test]
    async fn test_bearer_token() {
        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::default())
            .with_env(OsEnv);
        let cred = Credential::with_bearer_token(
            "token",
            Some(Timestamp::now() + Duration::from_secs(3600)),
        );
        let builder = RequestSigner::new();

        let original_uri =
            format!("https://test.blob.core.windows.net/testbucket/testblob?{RAW_QUERY}");
        let req = Request::builder().uri(&original_uri).body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        // Can effectively sign request with header method
        assert!(
            builder
                .sign_request(&ctx, &mut parts, Some(&cred), None)
                .await
                .is_ok()
        );
        let authorization = parts
            .headers
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!("Bearer token", authorization);
        assert_eq!(parts.uri.to_string(), original_uri);

        // Will not sign request with query method
        let req = Request::builder().uri(&original_uri).body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        assert!(
            builder
                .sign_request(&ctx, &mut parts, Some(&cred), Some(Duration::from_secs(1)))
                .await
                .is_err()
        );
        assert_eq!(parts.uri.to_string(), original_uri);
    }

    #[tokio::test]
    async fn shared_key_presign_signs_the_exact_resource() {
        let signer = reqsign_core::Signer::new(
            crate::test_context(),
            crate::StaticCredentialProvider::new_shared_key("account", "a2V5"),
            RequestSigner::new()
                .with_time(Timestamp::from_str("2022-03-01T08:12:34Z").unwrap())
                .with_service_sas_permissions("r"),
        );

        // These signatures were calculated independently with the key `key`
        // using Azure's Service SAS string-to-sign for version 2020-12-06.
        for (path, resource_kind, signature) in [
            (
                "/container/path/to/blob.txt",
                "b",
                "CP9a2LIrR9zeG4I4jZjqPetJSXWJ77QeUA7c3GMypyM%3D",
            ),
            (
                "/container/marker",
                "b",
                "5lVNRgqySZLMGMrADVCeGN6uluyZGn0tm%2BtPiKQR/Io%3D",
            ),
            (
                "/container/marker/",
                "b",
                "YDl6JKSJGFlDkdxLBYNy%2B4Bfi86gZeT51iU8SDwNR%2BY%3D",
            ),
            (
                "/container//dir//marker/",
                "b",
                "8QJW8Kn5uGuitYi1Y3ShWliraB3AZlLy/KVRjZFvkNQ%3D",
            ),
            (
                "/container/path%2Fto/blob%252F+caf%C3%A9/",
                "b",
                "uhcZTYC738i6iyTaISFPv%2BC0tlD%2BeFfRbr2T3KxcdhY%3D",
            ),
            (
                "/container",
                "c",
                "UnJTepxgfsXOLb5pyWhw/j4SUOLoD%2B4K/jYYD8Eb994%3D",
            ),
            (
                "/container/",
                "c",
                "UnJTepxgfsXOLb5pyWhw/j4SUOLoD%2B4K/jYYD8Eb994%3D",
            ),
            (
                "/container%2Fname",
                "c",
                "BlwumN/S/0vX5qLFUsOcjs2%2B26G2kxQ0q9kYQxXhGEo%3D",
            ),
        ] {
            let original_uri = format!("https://storage.example:8443{path}?{RAW_QUERY}");
            let mut parts = Request::head(&original_uri)
                .body(())
                .unwrap()
                .into_parts()
                .0;

            signer
                .sign(&mut parts, Some(Duration::from_secs(300)))
                .await
                .unwrap();

            let expected = format!(
                "{original_uri}sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr={resource_kind}&sig={signature}"
            );
            assert!(
                parts.uri.to_string() == expected,
                "unexpected signed URI for {path} with SAS resource kind {resource_kind}"
            );
        }
    }

    #[tokio::test]
    async fn shared_key_presign_rejects_explicit_start_at_or_after_wire_expiry() {
        let ctx = crate::test_context();
        let now = Timestamp::from_str("2022-03-01T08:12:34Z").unwrap();
        let key = reqsign_core::hash::base64_encode(b"key");
        let cred = Credential::with_shared_key("account", &key);

        for start in [
            "2022-03-01T08:17:34Z",
            "2022-03-01T08:17:34.700Z",
            "2022-03-01T08:17:35Z",
        ] {
            let signer = RequestSigner::new()
                .with_time(now)
                .with_service_sas_permissions("r")
                .with_service_sas_start(Timestamp::from_str(start).unwrap());
            let mut parts =
                Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0;
            let original = parts.clone();

            let err = signer
                .sign_request(
                    &ctx,
                    &mut parts,
                    Some(&cred),
                    Some(Duration::from_secs(300)),
                )
                .await
                .expect_err("an explicit start must encode before the expiry");

            assert_eq!(err.kind(), reqsign_core::ErrorKind::RequestInvalid);
            assert_eq!(parts.method, original.method);
            assert_eq!(parts.uri, original.uri);
            assert_eq!(parts.version, original.version);
            assert_eq!(parts.headers, original.headers);
        }
    }

    #[tokio::test]
    async fn shared_key_presign_keeps_existing_start_rounding_for_valid_windows() {
        let ctx = crate::test_context();
        let now = Timestamp::from_str("2022-03-01T08:12:34Z").unwrap();
        let key = reqsign_core::hash::base64_encode(b"key");
        let cred = Credential::with_shared_key("account", &key);
        let mut queries = Vec::new();

        for start in ["2022-03-01T08:17:33Z", "2022-03-01T08:17:33.700Z"] {
            let signer = RequestSigner::new()
                .with_time(now)
                .with_service_sas_permissions("r")
                .with_service_sas_start(Timestamp::from_str(start).unwrap());
            let mut parts =
                Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0;

            signer
                .sign_request(
                    &ctx,
                    &mut parts,
                    Some(&cred),
                    Some(Duration::from_secs(300)),
                )
                .await
                .unwrap();

            queries.push(
                parts
                    .uri
                    .query()
                    .expect("presigned URL must have a query")
                    .to_string(),
            );
        }

        for query in &queries {
            assert!(query.contains("st=2022-03-01T08%3A17%3A33Z"));
            assert!(query.contains("se=2022-03-01T08%3A17%3A34Z"));
            assert!(query.contains("sig="));
        }
        assert_eq!(
            queries[0], queries[1],
            "fractional start must keep the existing whole-second wire formatting"
        );
    }

    fn review_request_with_override() -> http::request::Parts {
        Request::get(
            "https://example.invalid/container/blob?rscd=attachment%3B%20filename%3Da.txt&x=%2f",
        )
        .header("x-test", "unchanged")
        .extension(19_u32)
        .body(())
        .unwrap()
        .into_parts()
        .0
    }

    #[tokio::test]
    async fn shared_key_presign_preserves_negative_year_start_bytes() {
        let ctx = crate::test_context();
        let cred =
            Credential::with_shared_key("account", &reqsign_core::hash::base64_encode(b"key"));
        let signer = RequestSigner::new()
            .with_time("-000001-12-31T23:59:57Z".parse().unwrap())
            .with_service_sas_permissions("r")
            .with_service_sas_start("-000001-12-31T23:59:58.700Z".parse().unwrap());
        let mut parts = review_request_with_override();

        signer
            .sign_request(&ctx, &mut parts, Some(&cred), Some(Duration::from_secs(2)))
            .await
            .unwrap();

        let query = parts.uri.query().expect("presigned URL must have a query");
        assert!(query.starts_with("rscd=attachment%3B%20filename%3Da.txt&x=%2f&"));
        let pairs =
            form_urlencoded::parse(query.as_bytes()).collect::<std::collections::HashMap<_, _>>();
        assert_eq!(pairs["st"], "-0001-12-31T23:59:58Z");
        assert_eq!(pairs["se"], "-0001-12-31T23:59:59Z");

        let canonical = [
            "r",
            "-0001-12-31T23:59:58Z",
            "-0001-12-31T23:59:59Z",
            "/blob/account/container/blob",
            "",
            "",
            "",
            "2020-12-06",
            "b",
            "",
            "",
            "",
            "attachment; filename=a.txt",
            "",
            "",
            "",
        ]
        .join("\n");
        let expected_signature =
            base64_hmac_sha256(ctx.crypto_provider().unwrap(), b"key", canonical.as_bytes())
                .unwrap();
        assert_eq!(pairs["sig"], expected_signature);
    }

    #[tokio::test]
    async fn shared_key_presign_rejects_negative_year_same_wire_second() {
        let ctx = crate::test_context();
        let cred =
            Credential::with_shared_key("account", &reqsign_core::hash::base64_encode(b"key"));

        for start in ["-000001-12-31T23:59:59Z", "-000001-12-31T23:59:59.700Z"] {
            let signer = RequestSigner::new()
                .with_time("-000001-12-31T23:59:57Z".parse().unwrap())
                .with_service_sas_permissions("r")
                .with_service_sas_start(start.parse().unwrap());
            let mut parts = review_request_with_override();
            let original = parts.clone();

            let err = signer
                .sign_request(&ctx, &mut parts, Some(&cred), Some(Duration::from_secs(2)))
                .await
                .expect_err("a negative-year start at the expiry must be rejected");

            assert_eq!(err.kind(), reqsign_core::ErrorKind::RequestInvalid);
            assert_eq!(parts.method, original.method);
            assert_eq!(parts.uri, original.uri);
            assert_eq!(parts.version, original.version);
            assert_eq!(parts.headers, original.headers);
            assert_eq!(parts.extensions.get::<u32>(), Some(&19));
        }
    }

    #[tokio::test]
    async fn shared_key_presign_keeps_future_start_before_expiry() {
        let ctx = crate::test_context();
        let cred =
            Credential::with_shared_key("account", &reqsign_core::hash::base64_encode(b"key"));
        let signer = RequestSigner::new()
            .with_time(Timestamp::from_str("2022-03-01T08:12:34Z").unwrap())
            .with_service_sas_permissions("r")
            .with_service_sas_start(Timestamp::from_str("2022-03-01T08:15:00Z").unwrap());
        let mut parts =
            Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                .body(())
                .unwrap()
                .into_parts()
                .0;

        signer
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(300)),
            )
            .await
            .unwrap();

        let query = parts.uri.query().expect("presigned URL must have a query");
        assert!(query.contains("st=2022-03-01T08%3A15%3A00Z"));
        assert!(query.contains("se=2022-03-01T08%3A17%3A34Z"));
        assert!(query.contains("sig="));
    }

    #[tokio::test]
    async fn shared_key_presign_rejects_invalid_lifetimes_without_changing_the_request() {
        let ctx = crate::test_context();
        let now = Timestamp::from_str("2022-03-01T08:12:34Z").unwrap();
        let key = reqsign_core::hash::base64_encode(b"key");
        let cred = Credential::with_shared_key("account", &key);
        let signer = RequestSigner::new()
            .with_time(now)
            .with_service_sas_permissions("r");

        for expires_in in [Duration::ZERO, Duration::from_millis(400), Duration::MAX] {
            let mut parts =
                Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0;
            let original = parts.clone();

            let err = signer
                .sign_request(&ctx, &mut parts, Some(&cred), Some(expires_in))
                .await
                .expect_err("invalid Service SAS lifetime must be rejected");

            assert_eq!(err.kind(), reqsign_core::ErrorKind::RequestInvalid);
            assert_eq!(parts.method, original.method);
            assert_eq!(parts.uri, original.uri);
            assert_eq!(parts.version, original.version);
            assert_eq!(parts.headers, original.headers);
        }
    }

    #[tokio::test]
    async fn shared_key_presign_rejects_subsecond_lifetime_that_stays_in_the_signing_second() {
        let ctx = crate::test_context();
        let now = Timestamp::from_str("2022-03-01T08:12:34.700Z").unwrap();
        let key = reqsign_core::hash::base64_encode(b"key");
        let cred = Credential::with_shared_key("account", &key);
        let signer = RequestSigner::new()
            .with_time(now)
            .with_service_sas_permissions("r");
        let mut parts =
            Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                .body(())
                .unwrap()
                .into_parts()
                .0;
        let original = parts.clone();

        let err = signer
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_millis(200)),
            )
            .await
            .expect_err("a lifetime that stays in the signing second must be rejected");

        assert_eq!(err.kind(), reqsign_core::ErrorKind::RequestInvalid);
        assert_eq!(parts.method, original.method);
        assert_eq!(parts.uri, original.uri);
        assert_eq!(parts.version, original.version);
        assert_eq!(parts.headers, original.headers);
    }

    #[tokio::test]
    async fn shared_key_presign_accepts_subsecond_lifetime_that_advances_the_sas_second() {
        let ctx = crate::test_context();
        let now = Timestamp::from_str("2022-03-01T08:12:34.700Z").unwrap();
        let key = reqsign_core::hash::base64_encode(b"key");
        let cred = Credential::with_shared_key("account", &key);
        let signer = RequestSigner::new()
            .with_time(now)
            .with_service_sas_permissions("r");
        let mut parts =
            Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                .body(())
                .unwrap()
                .into_parts()
                .0;

        signer
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_millis(300)),
            )
            .await
            .unwrap();

        let query = parts.uri.query().expect("presigned URL must have a query");
        assert!(query.contains("se=2022-03-01T08%3A12%3A35Z"));
        assert!(query.contains("sig="));
    }

    #[tokio::test]
    async fn test_shared_key_presign_signs_content_disposition() {
        let ctx = crate::test_context();
        let key = reqsign_core::hash::base64_encode(b"key");
        let cred = Credential::with_shared_key("account", &key);
        let signer = RequestSigner::new()
            .with_time(Timestamp::from_str("2022-03-01T08:12:34Z").unwrap())
            .with_service_sas_permissions("racwd");
        let encoded = "attachment%3B%20filename%3D%22foo%2Bbar%25.txt%22";
        let decoded = "attachment; filename=\"foo+bar%.txt\"";
        let request = Request::get(format!(
            "https://account.blob.core.windows.net/container/blob.txt?rscd={encoded}"
        ))
        .body(())
        .unwrap();
        let (mut parts, _) = request.into_parts();

        signer
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(300)),
            )
            .await
            .unwrap();

        assert!(
            parts
                .uri
                .query()
                .unwrap()
                .starts_with(&format!("rscd={encoded}&")),
            "the original encoded override must remain on the wire"
        );

        let string_to_sign = [
            "racwd",
            "", // Start time
            "2022-03-01T08:17:34Z",
            "/blob/account/container/blob.txt",
            "", // Signed identifier
            "", // IP range
            "", // Protocol
            "2020-12-06",
            "b",
            "", // Snapshot time
            "", // Encryption scope
            "", // rscc
            decoded,
            "", // rsce
            "", // rscl
            "", // rsct
        ]
        .join("\n");
        let expected_signature = base64_hmac_sha256(
            ctx.crypto_provider().unwrap(),
            b"key",
            string_to_sign.as_bytes(),
        )
        .unwrap();
        let request = SigningRequest::build(&mut parts).unwrap();
        assert!(
            request
                .query
                .iter()
                .any(|(name, value)| name == "sig" && value == &expected_signature),
            "Service SAS must authenticate the decoded response override"
        );
    }

    #[tokio::test]
    async fn test_shared_key_presign_empty_content_disposition_matches_omitted() {
        async fn sign(uri: &str) -> String {
            let ctx = crate::test_context();
            let key = reqsign_core::hash::base64_encode(b"key");
            let cred = Credential::with_shared_key("account", &key);
            let signer = RequestSigner::new()
                .with_time(Timestamp::from_str("2022-03-01T08:12:34Z").unwrap())
                .with_service_sas_permissions("r");
            let request = Request::get(uri).body(()).unwrap();
            let (mut parts, _) = request.into_parts();

            signer
                .sign_request(
                    &ctx,
                    &mut parts,
                    Some(&cred),
                    Some(Duration::from_secs(300)),
                )
                .await
                .unwrap();

            let request = SigningRequest::build(&mut parts).unwrap();
            request
                .query
                .iter()
                .find(|(name, _)| name == "sig")
                .map(|(_, value)| value.clone())
                .expect("presigned request must contain a signature")
        }

        let omitted = sign("https://account.blob.core.windows.net/container/blob.txt").await;
        let empty = sign("https://account.blob.core.windows.net/container/blob.txt?rscd=").await;
        assert!(
            empty == omitted,
            "an empty response override must not change the Service SAS signature"
        );
    }

    #[derive(Clone, Debug, Default)]
    struct MockUserDelegationHttpSend {
        calls: Arc<AtomicUsize>,
    }
    impl HttpSend for MockUserDelegationHttpSend {
        async fn http_send(
            &self,
            req: http::Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if req.method() != http::Method::POST {
                return Err(reqsign_core::Error::unexpected("unexpected request method")
                    .with_context(req.method().to_string()));
            }

            let uri = req.uri().to_string();
            if uri
                != "https://account.blob.core.windows.net/?restype=service&comp=userdelegationkey"
            {
                return Err(
                    reqsign_core::Error::unexpected("unexpected request uri").with_context(uri)
                );
            }

            let version = req
                .headers()
                .get("x-ms-version")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if version != "2020-12-06" {
                return Err(
                    reqsign_core::Error::unexpected("unexpected x-ms-version header")
                        .with_context(version),
                );
            }

            let date = req
                .headers()
                .get("x-ms-date")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if date != "Tue, 01 Mar 2022 08:12:34 GMT" {
                return Err(
                    reqsign_core::Error::unexpected("unexpected x-ms-date header")
                        .with_context(date),
                );
            }

            let content_type = req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if content_type != "application/xml" {
                return Err(
                    reqsign_core::Error::unexpected("unexpected content-type header")
                        .with_context(content_type),
                );
            }

            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if auth != "Bearer token" {
                return Err(
                    reqsign_core::Error::unexpected("unexpected authorization header")
                        .with_context(auth),
                );
            }

            let body = String::from_utf8_lossy(req.body()).to_string();
            if !body.contains("<KeyInfo>")
                || !body.contains("<Start>2022-03-01T08:12:34Z</Start>")
                || !body.contains("<Expiry>2022-03-01T08:17:34Z</Expiry>")
            {
                return Err(
                    reqsign_core::Error::unexpected("unexpected request body").with_context(body)
                );
            }

            let body = r#"
<UserDelegationKey>
  <SignedOid>oid</SignedOid>
  <SignedTid>tid</SignedTid>
  <SignedStart>2022-03-01T08:12:34Z</SignedStart>
  <SignedExpiry>2022-03-01T09:12:34Z</SignedExpiry>
  <SignedService>b</SignedService>
  <SignedVersion>2020-12-06</SignedVersion>
  <Value>a2V5</Value>
</UserDelegationKey>
"#;

            Ok(http::Response::builder()
                .status(200)
                .body(Bytes::from(body))
                .unwrap())
        }
    }

    #[tokio::test]
    async fn test_bearer_token_presign_user_delegation_sas() {
        let now = Timestamp::from_str("2022-03-01T08:12:34.500Z").unwrap();

        let http_send = MockUserDelegationHttpSend::default();
        let ctx = crate::test_context()
            .with_file_read(TokioFileRead)
            .with_http_send(http_send.clone())
            .with_env(OsEnv);

        let cred = Credential::with_bearer_token("token", None);
        let builder = RequestSigner::new()
            .with_time(now)
            .with_user_delegation_presign(SasResourceKind::Blob, "r");

        let original_uri =
            format!("https://account.blob.core.windows.net/container/path/to/blob.txt?{RAW_QUERY}");
        let req = Request::builder().uri(&original_uri).body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        builder
            .sign_request(
                &ctx,
                &mut parts,
                Some(&cred),
                Some(Duration::from_secs(300)),
            )
            .await
            .unwrap();

        assert_eq!(
            parts.uri.to_string(),
            format!(
                "{original_uri}sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&skoid=oid&sktid=tid&skt=2022-03-01T08%3A12%3A34Z&ske=2022-03-01T09%3A12%3A34Z&sks=b&skv=2020-12-06&sig=ZEuqL17Enw3SO6zeRjYDnedXYngQ8GrQMUBx82BGelY%3D"
            )
        );

        let near_expiry_cred =
            Credential::with_bearer_token("token", Some(now + Duration::from_secs(5)));
        assert_eq!(
            builder.required_valid_until(&near_expiry_cred, Some(Duration::from_secs(300))),
            now + BEARER_TOKEN_OPERATION_HEADROOM
        );

        let req = Request::builder().uri(&original_uri).body(()).unwrap();
        let (mut cached_parts, _) = req.into_parts();
        let err = builder
            .sign_request(
                &ctx,
                &mut cached_parts,
                Some(&near_expiry_cred),
                Some(Duration::from_secs(300)),
            )
            .await
            .expect_err("request-blind preflight must retain Bearer I/O headroom");
        assert_eq!(err.kind(), reqsign_core::ErrorKind::CredentialInvalid);
        assert_eq!(http_send.calls.load(Ordering::SeqCst), 1);
    }
}
