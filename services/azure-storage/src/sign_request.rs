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
use crate::sas_response_overrides::{SasResponseOverrides, sas_query_value};
use crate::service_sas::{ServiceSasMode, ServiceSasResource, ServiceSasTarget, validate_account};
use crate::user_delegation::{
    DEFAULT_USER_DELEGATION_KEY_API_VERSION, DEFAULT_USER_DELEGATION_SAS_VERSION,
    MAX_USER_DELEGATION_KEY_LIFETIME, UserDelegationKeyCache, ceil_to_wire_second,
    floor_to_wire_second, user_delegation_key_covers, validate_user_delegation_sas_version,
};
use http::request::Parts;
use http::{HeaderValue, Uri, header};
use percent_encoding::percent_decode_str;
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

/// Location of the Azure Storage account in a request URI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AddressingStyle {
    /// The URI path starts at the resource. This is the default for Azure
    /// service hosts and custom domains that map directly to an account.
    #[default]
    HostStyle,
    /// The first path segment names the account, as in Azurite's IP-based URLs.
    /// It must match the selected account after one percent-decoding pass.
    PathStyle,
}

struct AccountPath<'a> {
    prefix: &'a str,
    resource: &'a str,
}

impl AddressingStyle {
    fn split_path<'a>(self, wire_path: &'a str, account: &str) -> Result<AccountPath<'a>> {
        match self {
            Self::HostStyle => Ok(AccountPath {
                prefix: "",
                resource: wire_path.trim_start_matches('/'),
            }),
            Self::PathStyle => {
                let path = wire_path.strip_prefix('/').unwrap_or_default();
                let (segment, resource) = path.split_once('/').unwrap_or((path, ""));
                if segment.is_empty() || !percent_decode_str(segment).eq(account.bytes()) {
                    return Err(Error::request_invalid(
                        "Azure path-style request must start with the storage account name",
                    ));
                }
                Ok(AccountPath {
                    prefix: &wire_path[..1 + segment.len()],
                    resource,
                })
            }
        }
    }
}

/// Azure Storage service contract for Shared Key header signing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SharedKeyMode {
    /// Blob, Queue, and File services (the default).
    #[default]
    BlobQueueFile,
    /// Table service, using the five-line Shared Key format.
    Table,
}

/// Resource kind required by User Delegation SAS generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SasResourceKind {
    /// Container SAS.
    Container,
    /// Blob SAS.
    Blob,
}

/// Sign Azure Storage requests with Shared Key, SAS, or a bearer token.
///
/// Use [`Self::bearer`] for bearer header signing on other Azure APIs.
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
    account_name: Option<String>,
    addressing_style: AddressingStyle,
    shared_key_mode: SharedKeyMode,
    service_sas_mode: ServiceSasMode,
    service_sas_identifier: Option<String>,
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
    account_endpoint: String,
    source_authority: String,
    key_api_version: String,
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
            account_name: None,
            addressing_style: AddressingStyle::default(),
            shared_key_mode: SharedKeyMode::default(),
            service_sas_mode: ServiceSasMode::default(),
            service_sas_identifier: None,
            service_sas_permissions: None,
            service_sas_start: None,
            service_sas_ip: None,
            service_sas_protocol: None,
            service_sas_version: None,

            user_delegation_presign: None,
            user_delegation_key_cache: Mutex::new(UserDelegationKeyCache::default()),
        }
    }

    /// Set the storage account name explicitly for Shared Key signing and SAS generation.
    ///
    /// A Shared Key credential must name the same account. For User Delegation
    /// SAS, set this for custom domains and for [`AddressingStyle::PathStyle`].
    /// With host-style URLs and no explicit name, User Delegation SAS uses the
    /// first DNS label. The name must contain 3–24 lowercase ASCII letters or digits.
    pub fn with_account_name(mut self, account_name: impl Into<String>) -> Self {
        self.account_name = Some(account_name.into());
        self
    }

    /// Select how request URIs are addressed for Shared Key signing and SAS generation.
    ///
    /// Path-style URLs retain the account segment in the Shared Key signature,
    /// exclude it from the SAS resource name, and use it as the User Delegation
    /// key request root. The caller supplies the final URI in both styles.
    pub fn with_addressing_style(mut self, style: AddressingStyle) -> Self {
        self.addressing_style = style;
        self
    }

    /// Select the Shared Key header format.
    ///
    /// [`SharedKeyMode::Table`] returns `RequestInvalid` for requests to
    /// generate a new SAS. It supports applying an existing SAS credential.
    pub fn with_shared_key_mode(mut self, mode: SharedKeyMode) -> Self {
        self.shared_key_mode = mode;
        self
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

    /// Select the resource interpretation for Shared Key Service SAS presigning.
    ///
    /// The default is Blob Storage. Select a different mode explicitly for
    /// directory, Azure Files, or Queue Storage requests. Use
    /// [`ServiceSasMode::FileShare`] to grant share-wide permissions on an
    /// Azure Files request to a directory or file.
    pub fn with_service_sas_mode(mut self, mode: ServiceSasMode) -> Self {
        self.service_sas_mode = mode;
        self
    }

    /// Associate the Service SAS with an existing stored access policy (`si`).
    ///
    /// A request can also carry `si` in its query. When both are present they
    /// must match. The policy must leave expiry unspecified because presigning
    /// signs an explicit expiry from `expires_in`. Set a start time or
    /// permissions on only one side.
    pub fn with_service_sas_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.service_sas_identifier = Some(identifier.into());
        self
    }

    /// Configure Service SAS presign permissions for Shared Key query signing.
    ///
    /// The permissions must use Azure's order for the selected resource. Omit
    /// them or pass an empty string when the stored access policy supplies them.
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

    /// Configure the User Delegation SAS signature format (`sv`).
    ///
    /// This also sets the requested `x-ms-version` for Get User Delegation Key.
    /// The key service's returned `SignedVersion` supplies `skv` and can be newer.
    /// SAS versions from `2025-07-05` onward return `RequestInvalid`.
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

    fn user_delegation_account<'a>(
        &'a self,
        authority: &'a http::uri::Authority,
    ) -> Result<&'a str> {
        if let Some(account) = &self.account_name {
            validate_account(account)?;
            return Ok(account);
        }
        if self.addressing_style == AddressingStyle::PathStyle {
            return Err(Error::config_invalid(
                "Azure path-style User Delegation SAS requires an explicit account name",
            ));
        }
        let Some((account, _)) = authority.host().split_once('.') else {
            return Err(Error::request_invalid(
                "failed to infer account name from authority",
            ));
        };
        Ok(account)
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

        if !self.bearer_only
            && self.shared_key_mode == SharedKeyMode::Table
            && expires_in.is_some()
            && !matches!(cred, Credential::SasToken { .. })
        {
            return Err(Error::request_invalid(
                "Azure Table mode does not support generating a SAS",
            ));
        }

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

                        let account = self.user_delegation_account(&sctx.authority)?;
                        let path = self.addressing_style.split_path(&sctx.path, account)?;
                        let resource = ServiceSasResource::from_uri_resource_path(path.resource)?;
                        match (cfg.resource, &resource) {
                            (SasResourceKind::Container, ServiceSasResource::Container { .. }) => {}
                            (SasResourceKind::Blob, ServiceSasResource::Blob { .. }) => {}
                            _ => {
                                return Err(reqsign_core::Error::request_invalid(
                                    "request resource doesn't match configured SAS resource kind",
                                ));
                            }
                        }

                        let (sas_version, key_api_version) = match cfg.version.as_deref() {
                            Some(version) => {
                                validate_user_delegation_sas_version(version)?;
                                (version, version)
                            }
                            None => (
                                DEFAULT_USER_DELEGATION_SAS_VERSION,
                                DEFAULT_USER_DELEGATION_KEY_API_VERSION,
                            ),
                        };
                        validate_presign_query(&sctx.query)?;
                        if sas_query_value(&sctx.query, "si")?.is_some() {
                            return Err(Error::request_invalid(
                                "Azure User Delegation SAS does not support stored access policies",
                            ));
                        }
                        let overrides = SasResponseOverrides::from_query(&sctx.query)?;
                        overrides.validate()?;
                        let provider = context.crypto_provider()?;
                        let cache_key = UserDelegationPresignCacheKey {
                            account: account.to_owned(),
                            account_endpoint: format!(
                                "{}://{}{}",
                                sctx.scheme, sctx.authority, path.prefix
                            ),
                            source_authority: reqsign_core::hash::hex_sha256(
                                provider,
                                token.as_bytes(),
                            )?,
                            key_api_version: key_api_version.to_string(),
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
                                        account_endpoint: &cache_key.account_endpoint,
                                        bearer_token: token,
                                        start: key_start,
                                        expiry,
                                        api_version: &cache_key.key_api_version,
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
                                account.to_owned(),
                                key,
                                resource.into(),
                                cfg.permissions.to_string(),
                                expiry,
                                sas_version,
                            )
                            .with_response_overrides(overrides);
                        if let Some(start) = start {
                            signer = signer.with_start(start);
                        }
                        if let Some(ip) = &cfg.ip {
                            signer = signer.with_ip(ip);
                        }
                        if let Some(protocol) = &cfg.protocol {
                            signer = signer.with_protocol(protocol);
                        }
                        let signer_token = signer.token(provider).map_err(|e| {
                            reqsign_core::Error::new(
                                e.kind(),
                                "failed to generate user delegation SAS token",
                            )
                            .with_source(e)
                        })?;
                        final_uri = Some(append_query_pairs(
                            &original_uri,
                            &sctx.query,
                            signer_token,
                        )?);
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
                if let Some(configured_account) = &self.account_name {
                    validate_account(configured_account)?;
                    if configured_account != account_name {
                        return Err(Error::credential_invalid(
                            "Azure Shared Key credential does not match the configured storage account",
                        ));
                    }
                }
                let path = self.addressing_style.split_path(&sctx.path, account_name)?;
                match method {
                    SigningMethod::Query(d) => {
                        validate_presign_query(&sctx.query)?;
                        let query_identifier = sas_query_value(&sctx.query, "si")?;
                        let configured_identifier = self.service_sas_identifier.as_deref();
                        if query_identifier
                            .zip(configured_identifier)
                            .is_some_and(|(query, configured)| query != configured)
                        {
                            return Err(Error::request_invalid(
                                "request stored access policy identifier does not match the configured identifier",
                            ));
                        }
                        let identifier = configured_identifier.or(query_identifier);
                        let permissions =
                            self.service_sas_permissions.as_deref().unwrap_or_default();
                        let target = ServiceSasTarget::from_request(
                            self.service_sas_mode,
                            path.resource,
                            &sctx.query,
                        )?;
                        let overrides = SasResponseOverrides::from_query(&sctx.query)?;
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

                        let mut signer =
                            crate::service_sas::ServiceSharedAccessSignature::for_target(
                                account_name.clone(),
                                account_key.clone(),
                                target,
                                permissions.to_string(),
                                Some(expiry),
                            )
                            .with_response_overrides(overrides);
                        if let Some(identifier) = identifier {
                            signer = signer.with_identifier(identifier);
                        }
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
                        let signer_token = signer.token(provider).map_err(|e| {
                            reqsign_core::Error::new(
                                e.kind(),
                                "failed to generate service SAS token",
                            )
                            .with_source(e)
                        })?;
                        final_uri = Some(append_query_pairs(
                            &original_uri,
                            &sctx.query,
                            signer_token,
                        )?);
                    }
                    SigningMethod::Header => {
                        let provider = context.crypto_provider()?;
                        let date = signing_time.format_http_date();
                        sctx.headers.insert(
                            X_MS_DATE,
                            date.parse().map_err(|e| {
                                Error::unexpected("failed to parse x-ms-date header").with_source(e)
                            })?,
                        );
                        let string_to_sign = match self.shared_key_mode {
                            SharedKeyMode::BlobQueueFile => string_to_sign(&sctx, account_name)?,
                            SharedKeyMode::Table => table_string_to_sign(
                                &sctx,
                                account_name,
                                &date,
                                original_uri.query(),
                            )?,
                        };
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

fn validate_presign_query(query: &[(String, String)]) -> Result<()> {
    // Existing SAS authorization fields would conflict with the new signature.
    // Response overrides, si and snapshot/version selectors are handled separately.
    const SAS_AUTH_FIELDS: &[&str] = &[
        "sv", "st", "se", "sp", "sr", "sip", "spr", "sig", "sdd", "ses", "ss", "srt", "skoid",
        "sktid", "skt", "ske", "sks", "skv", "saoid", "suoid", "scid", "sduoid", "skdutid", "srh",
        "srq", "srch", "srcq",
    ];
    if query.iter().any(|(name, _)| {
        SAS_AUTH_FIELDS
            .iter()
            .any(|field| name.eq_ignore_ascii_case(field))
    }) {
        return Err(Error::request_invalid(
            "cannot generate an Azure SAS on a URI with existing SAS authorization parameters",
        ));
    }
    Ok(())
}

fn append_query_pairs(
    uri: &Uri,
    original_query: &[(String, String)],
    mut pairs: Vec<(String, String)>,
) -> Result<Uri> {
    // Values already read for signing are present in the original URI. Keep
    // those bytes instead of re-encoding the value or adding another copy.
    pairs.retain(|(name, _)| {
        !original_query
            .iter()
            .any(|(original, _)| original.eq_ignore_ascii_case(name))
    });
    let fragment = crate::service_sas::encode_query_pairs(&pairs);
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

/// [Table service Shared Key](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key#table-service-shared-key-authorization)
fn table_string_to_sign(
    ctx: &SigningRequest,
    account_name: &str,
    date: &str,
    wire_query: Option<&str>,
) -> Result<String> {
    let md5_header = header::HeaderName::from_static(CONTENT_MD5);
    let md5 = ctx
        .header_get_or_default(&md5_header)
        .map_err(|error| error.with_context(&md5_header))?;
    let content_type = ctx
        .header_get_or_default(&header::CONTENT_TYPE)
        .map_err(|error| error.with_context(header::CONTENT_TYPE))?;
    let method = ctx.method.as_str().to_ascii_uppercase();
    let mut signing = format!(
        "{method}\n{md5}\n{content_type}\n{date}\n/{account_name}{}",
        ctx.path
    );

    // Table signs only the component selector, in its wire encoding.
    let comp = wire_query.unwrap_or_default().split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        name.eq_ignore_ascii_case("comp").then_some(value)
    });
    if let Some(comp) = comp {
        signing.push_str("?comp=");
        signing.push_str(comp);
    }
    Ok(signing)
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
    const AZURITE_ACCOUNT: &str = "devstoreaccount1";
    const AZURITE_KEY_URI: &str =
        "https://127.0.0.1:10000/devstoreaccount1/?restype=service&comp=userdelegationkey";
    const AZURITE_BLOB_URI: &str = "https://127.0.0.1:10000/devstoreaccount1/container/blob";
    const AZURITE_SIGNED_VERSION: &str = "2026-10-06";

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
    async fn shared_key_signing_and_service_sas_use_the_selected_addressing_style() {
        // HMACs calculated with Python's hmac module and the invented key `key`.
        // Shared Key includes the wire path. Service SAS signs the decoded Blob resource.
        for (style, target, header_signature, resource_kind, sas_signature) in [
            (
                AddressingStyle::PathStyle,
                "http://127.0.0.1:10000/devstoreaccount1/container/blob",
                "xFyDdbBeZU76KX7DYlEH0rWHOuEgH+wP2vnTCVO6/1w=",
                "b",
                "KRYc8SCBmB/Wh%2B%2BGjJOpMHyM8HBsnnwAVgDWszJJWow%3D",
            ),
            (
                AddressingStyle::PathStyle,
                "https://storage.example:8443/devstoreaccount1/devstoreaccount1//dir%2Fblob%252F+caf%C3%A9/",
                "X+nxEI1HvVmX/Ij/M4l6xPlmbpMEOhiJGTmlZEpdZIE=",
                "b",
                "obrcwccbpHE6SMZWVpY06R6pARTaCpaaA1IygeR0ypg%3D",
            ),
            (
                AddressingStyle::HostStyle,
                "https://storage.example:8443/devstoreaccount1/marker/",
                "A5P5emEqleluMN8UwiLh2PC5yRz2lgLtdHFpiAziutw=",
                "b",
                "Z6%2BDyxhh5Ptt8m3ptp7JLuLr3uDRGPHWY5oazi8Ucg4%3D",
            ),
            (
                AddressingStyle::PathStyle,
                "http://127.0.0.1:10000/devstoreaccount1/container/",
                "Swih36TcWJcU+y1dg6CsmtrKDq/yLGxbTGoJ4x9aL+k=",
                "c",
                "VebrEoKV24cme0RE2kH9VNUeo5JWW1vaumVEn2JstBo%3D",
            ),
        ] {
            let signer = Signer::new(
                crate::test_context(),
                crate::StaticCredentialProvider::new_shared_key(AZURITE_ACCOUNT, "a2V5"),
                shared_key_request_signer()
                    .with_account_name(AZURITE_ACCOUNT)
                    .with_addressing_style(style)
                    .with_service_sas_permissions("r"),
            );
            let uri = format!("{target}?comp=metadata&dupe=%252F&dupe=%20&flag&");
            let original = Request::head(&uri)
                .header("x-ms-version", "2020-12-06")
                .body(())
                .unwrap()
                .into_parts()
                .0;

            let mut header_signed = original.clone();
            signer.sign(&mut header_signed, None).await.unwrap();
            let authorization = header_signed.headers.remove(header::AUTHORIZATION).unwrap();
            assert!(authorization.is_sensitive());
            assert_eq!(
                authorization,
                format!("SharedKey {AZURITE_ACCOUNT}:{header_signature}")
            );
            assert_eq!(
                header_signed.headers.remove(X_MS_DATE).unwrap(),
                SHARED_KEY_DATE
            );
            assert_eq!(header_signed.headers, original.headers);
            assert_eq!(header_signed.uri, original.uri);

            let mut presigned = original.clone();
            signer
                .sign(&mut presigned, Some(Duration::from_secs(300)))
                .await
                .unwrap();
            let expected = format!(
                "{uri}sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr={resource_kind}&sig={sas_signature}"
            );
            assert!(
                presigned.uri.to_string() == expected,
                "unexpected Service SAS for {target}"
            );
            assert_eq!(presigned.headers, original.headers);
        }
    }

    #[tokio::test]
    async fn table_shared_key_signs_published_resource_cases() {
        // Microsoft's .NET SDK publishes the resource cases and the fixture key `Kg==`.
        // https://github.com/Azure/azure-sdk-for-net/blob/fd674af6cfb7ede9390d2687522245e38c4eb744/sdk/tables/Azure.Data.Tables/tests/TableSharedKeyPipelinePolicyTests.cs#L12-L23
        // The full five-line HMACs were calculated independently with Python's hmac module.
        let signer = Signer::new(
            crate::test_context(),
            crate::StaticCredentialProvider::new_shared_key("account", "Kg=="),
            shared_key_request_signer().with_shared_key_mode(SharedKeyMode::Table),
        );
        for (path, signature) in [
            (
                "/foopath?restype=service&comp=properties&sv=2019-02-02&ss=t&srt=s&se=2040-01-01T01%3A01%3A00Z&sp=rwdlau&sig=Sanitized",
                "BAfGwlPLwMWwkDp6GzVRzSPD7U3qnIhza3OOMtLlEzw=",
            ),
            (
                "/?sv=2019-02-02&ss=t&srt=s&se=2040-01-01T01%3A01%3A00Z&sp=rwdlau&sig=Sanitized",
                "ymmnxogaCUadjG2umcetRTdCYp6Tsf+RvPOGuDLBXsc=",
            ),
            ("/test", "NDJbuFQCYZvEmkXWEyOxrazsOZGpcy3KpQzFOTqoY/s="),
        ] {
            let uri = format!("https://foo.table.core.windows.net{path}");
            let mut parts = Request::get(&uri).body(()).unwrap().into_parts().0;
            signer.sign(&mut parts, None).await.unwrap();
            assert_eq!(
                parts.headers[header::AUTHORIZATION],
                format!("SharedKey account:{signature}")
            );
            assert_eq!(parts.headers[X_MS_DATE], SHARED_KEY_DATE);
            assert_eq!(parts.uri.to_string(), uri);
        }
    }

    #[tokio::test]
    async fn table_shared_key_signs_date_content_headers_and_encoded_component() {
        let context = crate::test_context();
        let signer = shared_key_request_signer()
            .with_addressing_style(AddressingStyle::PathStyle)
            .with_shared_key_mode(SharedKeyMode::Table);
        let credential = Credential::with_shared_key(AZURITE_ACCOUNT, "a2V5");
        let uri = "http://127.0.0.1:10002/devstoreaccount1/Tables('left%20right')?xcomp=other&CoMp=pro%70erties&$top=1";
        let mut parts = Request::put(uri)
            .header(header::DATE, "Mon, 28 Feb 2022 08:12:34 GMT")
            .header("content-md5", "Zml4dHVyZQ==")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::IF_MATCH, "*")
            .header("x-ms-version", "2020-12-06")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let original_headers = parts.headers.clone();
        signer
            .sign_request(&context, &mut parts, Some(&credential), None)
            .await
            .unwrap();

        // Python HMAC over the five lines with the generated x-ms-date and
        // /devstoreaccount1/devstoreaccount1/Tables('left%20right')?comp=pro%70erties.
        assert_eq!(
            parts.headers.remove(header::AUTHORIZATION).unwrap(),
            "SharedKey devstoreaccount1:wrx7epCyC676o97Azodu1oJVKw9TycaOTKQWypoaND0="
        );
        assert_eq!(parts.headers.remove(X_MS_DATE).unwrap(), SHARED_KEY_DATE);
        assert_eq!(parts.headers, original_headers);
        assert_eq!(parts.uri.to_string(), uri);

        let error = signer
            .with_service_sas_permissions("r")
            .sign_request(
                &context,
                &mut parts,
                Some(&credential),
                Some(Duration::from_secs(300)),
            )
            .await
            .expect_err("Table mode does not generate SAS credentials");
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert_eq!(parts.headers, original_headers);
        assert_eq!(parts.uri.to_string(), uri);
    }

    #[tokio::test]
    async fn mismatched_accounts_and_invalid_path_style_resources_fail_atomically() {
        let signer = shared_key_request_signer()
            .with_account_name(AZURITE_ACCOUNT)
            .with_addressing_style(AddressingStyle::PathStyle)
            .with_service_sas_permissions("r")
            .with_user_delegation_presign(SasResourceKind::Blob, "r");
        let transport = MockUserDelegationHttpSend::new(&[], "2020-12-06");
        let context = crate::test_context().with_http_send(transport.clone());
        let shared_key = Credential::with_shared_key(AZURITE_ACCOUNT, "a2V5");
        let bearer = Credential::with_bearer_token("token", None);
        let other_key = Credential::with_shared_key("otheraccount", "a2V5");
        let expiry = Some(Duration::from_secs(300));
        for (path, credential, expires_in, kind) in [
            (
                "/devstoreaccount1/container/blob",
                &other_key,
                None,
                ErrorKind::CredentialInvalid,
            ),
            (
                "/devstoreaccount12/container/blob",
                &shared_key,
                None,
                ErrorKind::RequestInvalid,
            ),
            (
                "/devstoreaccount1%2Fcontainer/blob",
                &shared_key,
                expiry,
                ErrorKind::RequestInvalid,
            ),
            (
                "/devstoreaccount1//container/blob",
                &shared_key,
                expiry,
                ErrorKind::RequestInvalid,
            ),
            (
                "/devstoreaccount1/",
                &bearer,
                expiry,
                ErrorKind::RequestInvalid,
            ),
        ] {
            let mut parts = Request::get(format!("http://127.0.0.1:10000{path}"))
                .header(header::AUTHORIZATION, "previous authorization")
                .body(())
                .unwrap()
                .into_parts()
                .0;
            let original = parts.clone();
            let error = signer
                .sign_request(&context, &mut parts, Some(credential), expires_in)
                .await
                .expect_err("invalid account or resource must fail");
            assert_eq!(error.kind(), kind, "{path}");
            assert_eq!(parts.uri, original.uri);
            assert_eq!(parts.headers, original.headers);
        }
        let mut parts = Request::get("http://127.0.0.1:10000/devstoreaccount1/container/blob")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let error = shared_key_request_signer()
            .with_addressing_style(AddressingStyle::PathStyle)
            .with_user_delegation_presign(SasResourceKind::Blob, "r")
            .sign_request(&context, &mut parts, Some(&bearer), expiry)
            .await
            .expect_err("path-style User Delegation SAS requires an account name");
        assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
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

    #[derive(Clone, Debug)]
    struct MockUserDelegationHttpSend {
        expected_uris: &'static [&'static str],
        signed_version: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl MockUserDelegationHttpSend {
        fn new(expected_uris: &'static [&'static str], signed_version: &'static str) -> Self {
            Self {
                expected_uris,
                signed_version,
                calls: Arc::default(),
            }
        }
    }

    impl HttpSend for MockUserDelegationHttpSend {
        async fn http_send(
            &self,
            req: http::Request<Bytes>,
        ) -> reqsign_core::Result<http::Response<Bytes>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if req.method() != http::Method::POST {
                return Err(reqsign_core::Error::unexpected("unexpected request method")
                    .with_context(req.method().to_string()));
            }

            let uri = req.uri().to_string();
            if self.expected_uris.get(call).copied() != Some(uri.as_str()) {
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
            if auth != "Bearer token" || !req.headers()[header::AUTHORIZATION].is_sensitive() {
                return Err(reqsign_core::Error::unexpected(
                    "unexpected authorization header",
                ));
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

            let body = format!(
                r#"
<UserDelegationKey>
  <SignedOid>oid</SignedOid>
  <SignedTid>tid</SignedTid>
  <SignedStart>2022-03-01T08:12:34Z</SignedStart>
  <SignedExpiry>2022-03-01T08:17:34Z</SignedExpiry>
  <SignedService>b</SignedService>
  <SignedVersion>{}</SignedVersion>
  <Value>a2V5</Value>
</UserDelegationKey>
"#,
                self.signed_version
            );

            Ok(http::Response::builder()
                .status(200)
                .body(Bytes::from(body))
                .unwrap())
        }
    }

    #[tokio::test]
    async fn service_sas_presign_uses_service_scope_and_preserves_the_wire_uri() {
        use crate::sas_response_overrides::TEST_RESPONSE_OVERRIDE_QUERY;

        let context = crate::test_context();
        let credential = Credential::with_shared_key("account", "a2V5");
        let file = format!(
            "https://storage.example/share/nested/a%20b.txt?si=watch%2bpolicy/%25&{TEST_RESPONSE_OVERRIDE_QUERY}&x=%2f&x=+"
        );
        // Python HMAC-SHA256 over the REST string-to-sign for each presigned URI.
        for (uri, addressing, mode, version, permissions, suffix) in [
            (
                "https://storage.example/container/path%2fto/blob?x=%2f&x=+&snapshot=2019-12-15T00%3a05%3a33.1234567Z",
                AddressingStyle::HostStyle,
                ServiceSasMode::Blob,
                "2018-11-09",
                "r",
                "&sp=r&sr=bs&sig=GKSrQX2ajzp627%2BM/lOT12IXDrIyDM1tTDcfChVG0jU%3D",
            ),
            (
                "http://127.0.0.1:10000/%61ccount/container/item?versionid=2019-12-15T00%3a05%3a33.1234567Z",
                AddressingStyle::PathStyle,
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "&sp=r&sr=bv&sig=rOHDWq/yN07X%2BNLmXsatRHntXmMxTtvLxTJ50tWKz48%3D",
            ),
            (
                "https://storage.example/container/nested%2fdir/?x=%2f",
                AddressingStyle::HostStyle,
                ServiceSasMode::BlobDirectory,
                "2020-02-10",
                "r",
                "&sp=r&sr=d&sdd=2&sig=z4l6/2MGZ5EghmRktgUZO7p5RgLqHD5ojZJDdOI6uXQ%3D",
            ),
            (
                "https://storage.example/container/?restype=container",
                AddressingStyle::HostStyle,
                ServiceSasMode::BlobDirectory,
                "2020-02-10",
                "r",
                "&sp=r&sr=d&sdd=0&sig=ZHOF1WcVNM8pDpKhSI8FxKlbn%2B7Gu1bBhGJbbpZrKmc%3D",
            ),
            (
                file.as_str(),
                AddressingStyle::HostStyle,
                ServiceSasMode::File,
                "2020-12-06",
                "",
                "&sr=f&sig=sP4aH/ozXZyxz1EPT2eydbUQfa6QwvzOrC8MPvE7UWs%3D",
            ),
            (
                "https://storage.example/share/?restype=share",
                AddressingStyle::HostStyle,
                ServiceSasMode::File,
                "2020-12-06",
                "r",
                "&sp=r&sr=s&sig=BiP0cdOhjvMcahoU9of1DyH9/cGWG5sQ/rGcYsepTMs%3D",
            ),
            (
                "http://127.0.0.1:10001/account/jobs/messages/message-id?visibilitytimeout=30&x=%2f&x=+",
                AddressingStyle::PathStyle,
                ServiceSasMode::Queue,
                "2020-12-06",
                "raup",
                "&sp=raup&sig=6cN15L8wm7VMHND5dt0kLjh0QsbCX767bfyTbyObRp0%3D",
            ),
        ] {
            let mut signer = shared_key_request_signer()
                .with_account_name("account")
                .with_addressing_style(addressing)
                .with_service_sas_mode(mode)
                .with_service_sas_version(version);
            signer = if permissions.is_empty() {
                signer.with_service_sas_identifier("watch+policy/%")
            } else {
                signer.with_service_sas_permissions(permissions)
            };
            let mut parts = Request::get(uri).body(()).unwrap().into_parts().0;
            signer
                .sign_request(
                    &context,
                    &mut parts,
                    Some(&credential),
                    Some(Duration::from_secs(300)),
                )
                .await
                .unwrap();
            assert_eq!(
                parts.uri.to_string(),
                format!("{uri}&sv={version}&se=2022-03-01T08%3A17%3A34Z{suffix}")
            );
        }
    }

    #[tokio::test]
    async fn service_sas_presigns_files_directory_list_at_explicit_share_scope() {
        for (addressing, uri) in [
            (
                AddressingStyle::HostStyle,
                "https://storage.example/programs/clips?restype=directory&comp=list&marker=page%2b1",
            ),
            (
                AddressingStyle::PathStyle,
                "http://127.0.0.1:10002/%61ccount/programs/clips?restype=directory&comp=list&marker=page%2b1",
            ),
        ] {
            let signer = Signer::new(
                crate::test_context(),
                crate::StaticCredentialProvider::new_shared_key("account", "a2V5"),
                shared_key_request_signer()
                    .with_account_name("account")
                    .with_addressing_style(addressing)
                    .with_service_sas_mode(ServiceSasMode::FileShare)
                    .with_service_sas_permissions("l"),
            );
            let mut parts = Request::get(uri).body(()).unwrap().into_parts().0;
            signer
                .sign(&mut parts, Some(Duration::from_secs(300)))
                .await
                .unwrap();
            // Python HMAC-SHA256 over the Files layout for /file/account/programs.
            assert_eq!(
                parts.uri.to_string(),
                format!(
                    "{uri}&sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=l&sr=s&sig=pXMDhnNBXbY3avI9C0HYTuQLHwbLD7q2wYHB/E4PsuY%3D"
                )
            );
        }
    }

    #[tokio::test]
    async fn service_sas_presigns_explicit_and_implicit_root_blob_selectors() {
        let cases = [
            (
                AddressingStyle::HostStyle,
                "https://storage.example/intro%2emov",
                true,
            ),
            (
                AddressingStyle::HostStyle,
                "https://storage.example/%24root/intro.mov",
                true,
            ),
            (
                AddressingStyle::HostStyle,
                "https://storage.example/container/intro.mov",
                false,
            ),
            (
                AddressingStyle::PathStyle,
                "http://127.0.0.1:10000/%61ccount/intro%2emov",
                true,
            ),
            (
                AddressingStyle::PathStyle,
                "http://127.0.0.1:10000/%61ccount/%24root/intro.mov",
                true,
            ),
            (
                AddressingStyle::PathStyle,
                "http://127.0.0.1:10000/%61ccount/container/intro.mov",
                false,
            ),
        ];
        for (addressing, endpoint, root_container) in cases {
            let signer = Signer::new(
                crate::test_context(),
                crate::StaticCredentialProvider::new_shared_key("account", "a2V5"),
                shared_key_request_signer()
                    .with_account_name("account")
                    .with_addressing_style(addressing)
                    .with_service_sas_permissions("r"),
            );
            // Python HMAC-SHA256 over /blob/account/$root/intro.mov and
            // /blob/account/container/intro.mov with each full selector value.
            for (selector, sr, root_signature, container_signature) in [
                (
                    "snapshot=2022-01-02T03%3a04%3A05.8934123Z",
                    "bs",
                    "0N1/eHwlnzxN%2BGalnW6Kl3GLzey9w%2BTNBOvgAHfOUok%3D",
                    "0pQCK5eZYtVqrgoEt6FWbGT4yOVKYtfQgZI1Gsjyb30%3D",
                ),
                (
                    "versionid=2022-09-08T07%3a06%3A05.1234567Z",
                    "bv",
                    "p5lPqJJzvomY37/8TQHh23IgDJ7H4SbXpHnsUqG9r6k%3D",
                    "vU99tnV82%2B1rVr7G8gn7uJEW8DdcWXC0eoFx/1FVJgA%3D",
                ),
            ] {
                let uri = format!("{endpoint}?tag=%2f&{selector}&tag=+");
                let signature = if root_container {
                    root_signature
                } else {
                    container_signature
                };
                let mut parts = Request::get(&uri).body(()).unwrap().into_parts().0;
                signer
                    .sign(&mut parts, Some(Duration::from_secs(300)))
                    .await
                    .unwrap();
                assert_eq!(
                    parts.uri.to_string(),
                    format!(
                        "{uri}&sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr={sr}&sig={signature}"
                    )
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_service_sas_options_fail_before_changing_the_request() {
        let context = crate::test_context();
        let credential = Credential::with_shared_key("account", "a2V5");
        let too_deep = format!("/container/{}dir", "dir/".repeat(61));
        for (path, mode, version, permissions, expected_error) in [
            (
                "/container/a?snapshot=old",
                ServiceSasMode::Blob,
                "2018-03-28",
                "r",
                "snapshots and versions require version 2018-11-09",
            ),
            (
                "/container/a?versionid=v",
                ServiceSasMode::Blob,
                "2018-03-28",
                "r",
                "snapshots and versions require version 2018-11-09",
            ),
            (
                "/container/a?snapshot=old&versionid=v",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "cannot combine snapshot and version selectors",
            ),
            (
                "/container/a?versionid=",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "invalid Azure blob snapshot or version selector",
            ),
            (
                "/container?restype=container&snapshot=old",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "snapshot and version selectors require a blob path",
            ),
            (
                "/container/?snapshot=old",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "blob name must be a non-empty",
            ),
            (
                "/nested%2fblob?versionid=v",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "root container blob names must not contain slashes",
            ),
            (
                "/container/a",
                ServiceSasMode::BlobDirectory,
                "2019-12-12",
                "r",
                "directory scope requires version 2020-02-10",
            ),
            (
                too_deep.as_str(),
                ServiceSasMode::BlobDirectory,
                "2020-12-06",
                "r",
                "invalid Azure Service SAS directory path",
            ),
            (
                "/share/a//b",
                ServiceSasMode::File,
                "2020-12-06",
                "r",
                "invalid Azure Service SAS file path",
            ),
            (
                "/share/a?restype=directory&comp=list",
                ServiceSasMode::File,
                "2020-12-06",
                "l",
                "invalid permission or permission order",
            ),
            (
                "/jobs/messages",
                ServiceSasMode::Queue,
                "2020-12-06",
                "pa",
                "invalid permission or permission order",
            ),
            (
                "/jobs/not-messages",
                ServiceSasMode::Queue,
                "2020-12-06",
                "r",
                "requires a queue or queue message path",
            ),
            (
                "/jobs?rsct=text/plain",
                ServiceSasMode::Queue,
                "2020-12-06",
                "r",
                "does not support response header overrides",
            ),
            (
                "/container/a?rscc=one&%72scc=two",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "duplicate signed Azure SAS query parameter",
            ),
            (
                "/container/a?rsct=text/plain%0Aextra-line",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "must not contain control characters",
            ),
            (
                "/container/a?sig=stale",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "existing SAS authorization parameters",
            ),
            (
                "/container/a?si=wrong",
                ServiceSasMode::Blob,
                "2020-12-06",
                "r",
                "does not match the configured identifier",
            ),
        ] {
            let signer = shared_key_request_signer()
                .with_service_sas_mode(mode)
                .with_service_sas_version(version)
                .with_service_sas_identifier("policy")
                .with_service_sas_permissions(permissions);
            let uri = format!("https://storage.example{path}");
            let mut parts = Request::get(&uri)
                .header("x-test", "original")
                .body(())
                .unwrap()
                .into_parts()
                .0;
            let headers = parts.headers.clone();
            let error = signer
                .sign_request(
                    &context,
                    &mut parts,
                    Some(&credential),
                    Some(Duration::from_secs(300)),
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), reqsign_core::ErrorKind::RequestInvalid);
            assert!(format!("{error:?}").contains(expected_error), "{error:?}");
            assert_eq!(parts.uri.to_string(), uri);
            assert_eq!(parts.headers, headers);
        }
    }

    #[tokio::test]
    async fn user_delegation_presign_signs_response_overrides_at_the_selected_account_root() {
        use crate::sas_response_overrides::TEST_RESPONSE_OVERRIDE_QUERY;

        let transport = MockUserDelegationHttpSend::new(
            &["https://storage.example/%61ccount/?restype=service&comp=userdelegationkey"],
            "2026-10-06",
        );
        let context = crate::test_context().with_http_send(transport.clone());
        let signer = Signer::new(
            context,
            crate::StaticCredentialProvider::new_bearer_token("token"),
            shared_key_request_signer()
                .with_account_name("account")
                .with_addressing_style(AddressingStyle::PathStyle)
                .with_user_delegation_presign(SasResourceKind::Blob, "r"),
        );
        let uri = format!(
            "https://storage.example/%61ccount/container/blob+file.txt?x=%2f&{TEST_RESPONSE_OVERRIDE_QUERY}&x=+"
        );
        let mut parts = Request::get(&uri).body(()).unwrap().into_parts().0;
        signer
            .sign(&mut parts, Some(Duration::from_secs(300)))
            .await
            .unwrap();
        assert_eq!(
            parts.uri.to_string(),
            format!(
                "{uri}&sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&skoid=oid&sktid=tid&skt=2022-03-01T08%3A12%3A34Z&ske=2022-03-01T08%3A17%3A34Z&sks=b&skv=2026-10-06&sig=79e1Lzdff%2B8hUWF6206HvDwgZNVEctxYeCpNAV1UyY8%3D"
            ),
        );
        let uri = format!("{uri}&si=stored-policy");
        let mut parts = Request::get(&uri).body(()).unwrap().into_parts().0;
        let error = signer
            .sign(&mut parts, Some(Duration::from_secs(300)))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not support stored access policies")
        );
        assert_eq!(parts.uri.to_string(), uri);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn user_delegation_presign_keys_follow_the_account_root() {
        // Azurite v3.38.0 echoes the requested time bounds and uses its own
        // Blob API version in SignedVersion. The mock uses an invented key.
        // https://github.com/Azure/Azurite/blob/v3.38.0/src/blob/handlers/ServiceHandler.ts#L88-L119
        let transport = MockUserDelegationHttpSend::new(
            &[
                AZURITE_KEY_URI,
                "https://127.0.0.1:10000/%64evstoreaccount1/?restype=service&comp=userdelegationkey",
                "https://storage.example:8443/devstoreaccount1/?restype=service&comp=userdelegationkey",
                "https://storage.example:8443/?restype=service&comp=userdelegationkey",
            ],
            AZURITE_SIGNED_VERSION,
        );
        let context = crate::test_context().with_http_send(transport.clone());
        let credential_provider = crate::StaticCredentialProvider::new_bearer_token("token");
        let request_signer = shared_key_request_signer()
            .with_account_name(AZURITE_ACCOUNT)
            .with_user_delegation_presign(SasResourceKind::Blob, "r")
            .with_user_delegation_protocol("https");
        let path_style = Signer::new(
            context,
            credential_provider,
            request_signer.with_addressing_style(AddressingStyle::PathStyle),
        );

        // Python HMACs over the sv=2020-12-06 format with skv=2026-10-06.
        let blob = "/6cOO%2B8gTjIDm8969cIlLS/reGmvBVciEhTdr8f16gE%3D";
        let nested_blob = "AGl7wawMdqsz1eYb/V7HHLr4gZSjq9JQnTxmP87q/Ng%3D";
        for (target, signature) in [
            (AZURITE_BLOB_URI, blob),
            (
                "https://127.0.0.1:10000/%64evstoreaccount1/container/blob",
                blob,
            ),
            (AZURITE_BLOB_URI, blob),
            (
                "https://storage.example:8443/devstoreaccount1/devstoreaccount1//dir%2Fblob%252F+caf%C3%A9/",
                nested_blob,
            ),
        ] {
            let uri = format!("{target}?{RAW_QUERY}");
            let mut parts = Request::get(&uri).body(()).unwrap().into_parts().0;
            path_style
                .sign(&mut parts, Some(Duration::from_secs(300)))
                .await
                .unwrap();
            let expected = format!(
                "{uri}sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&skoid=oid&sktid=tid&skt=2022-03-01T08%3A12%3A34Z&ske=2022-03-01T08%3A17%3A34Z&sks=b&skv=2026-10-06&spr=https&sig={signature}"
            );
            assert!(
                parts.uri.to_string() == expected,
                "unexpected User Delegation SAS for {target}"
            );
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 3);

        let host_style = path_style.with_request_signer(
            shared_key_request_signer()
                .with_account_name(AZURITE_ACCOUNT)
                .with_user_delegation_presign(SasResourceKind::Blob, "r")
                .with_user_delegation_protocol("https"),
        );
        let uri = "https://storage.example:8443/devstoreaccount1/marker/";
        let mut parts = Request::get(uri).body(()).unwrap().into_parts().0;
        host_style
            .sign(&mut parts, Some(Duration::from_secs(300)))
            .await
            .unwrap();
        assert!(
            parts.uri.to_string()
                == format!(
                    "{uri}?sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&skoid=oid&sktid=tid&skt=2022-03-01T08%3A12%3A34Z&ske=2022-03-01T08%3A17%3A34Z&sks=b&skv=2026-10-06&spr=https&sig=ufV3b%2BnrLYDLFPcFrrKvg9tt/UzPEzmUbSHW3CshWlI%3D"
                )
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn user_delegation_presign_rejects_invalid_or_older_key_versions() {
        let builder = shared_key_request_signer()
            .with_account_name(AZURITE_ACCOUNT)
            .with_addressing_style(AddressingStyle::PathStyle)
            .with_user_delegation_presign(SasResourceKind::Blob, "r");
        let credential = Credential::with_bearer_token("token", None);
        for version in ["2019-12-12", "2026-02-30"] {
            let transport = MockUserDelegationHttpSend::new(&[AZURITE_KEY_URI; 2], version);
            let context = crate::test_context().with_http_send(transport.clone());
            let mut parts = Request::get(AZURITE_BLOB_URI)
                .body(())
                .unwrap()
                .into_parts()
                .0;
            for _ in 0..2 {
                let error = builder
                    .sign_request(
                        &context,
                        &mut parts,
                        Some(&credential),
                        Some(Duration::from_secs(300)),
                    )
                    .await
                    .expect_err("invalid delegation key versions must be rejected");
                assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
                assert_eq!(parts.uri, AZURITE_BLOB_URI);
                assert!(parts.headers.is_empty());
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn user_delegation_presign_rejects_unsupported_sas_version_before_key_request() {
        let transport = MockUserDelegationHttpSend::new(&[], AZURITE_SIGNED_VERSION);
        let context = crate::test_context().with_http_send(transport.clone());
        let signer = Signer::new(
            context,
            crate::StaticCredentialProvider::new_bearer_token("token"),
            shared_key_request_signer()
                .with_account_name(AZURITE_ACCOUNT)
                .with_addressing_style(AddressingStyle::PathStyle)
                .with_user_delegation_presign(SasResourceKind::Blob, "r")
                .with_user_delegation_version("2025-07-05"),
        );
        let mut parts = Request::get(AZURITE_BLOB_URI)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let error = signer
            .sign(&mut parts, Some(Duration::from_secs(300)))
            .await
            .expect_err("unsupported SAS formats must remain rejected");
        assert_eq!(error.kind(), ErrorKind::RequestInvalid);
        assert_eq!(parts.uri, AZURITE_BLOB_URI);
        assert!(parts.headers.is_empty());
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_bearer_token_presign_user_delegation_sas() {
        let now = Timestamp::from_str("2022-03-01T08:12:34.500Z").unwrap();

        let http_send = MockUserDelegationHttpSend::new(
            &["https://account.blob.core.windows.net/?restype=service&comp=userdelegationkey"],
            "2020-12-06",
        );
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
                "{original_uri}sv=2020-12-06&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=b&skoid=oid&sktid=tid&skt=2022-03-01T08%3A12%3A34Z&ske=2022-03-01T08%3A17%3A34Z&sks=b&skv=2020-12-06&sig=FUYkhOx8h7evd0Q3v7obQK6q/zBEMG/oWzyCeUFQlt8%3D"
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
