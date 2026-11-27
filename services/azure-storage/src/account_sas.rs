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

use crate::constants::{
    SAS_ENCRYPTION_SCOPE_VERSION, SAS_VERSIONS_WITH_ENCRYPTION_SCOPE, STORAGE_ACCOUNT_KEY_LENGTH,
};
use crate::service_sas::{
    ceil_to_wire_second, encode_query_pairs, expiry_at_wire_second, validate_account,
};
use crate::{Credential, SasIpRange, SasProtocol};
use reqsign_core::hash;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result};
use std::fmt::{Debug, Formatter};
use std::ops::{BitOr, BitOrAssign};
use std::time::Duration;

const LEGACY_ACCOUNT_SAS_VERSIONS: &[&str] = &[
    "2015-04-05",
    "2015-07-08",
    "2015-12-11",
    "2016-05-31",
    "2017-04-17",
    "2017-07-29",
    "2017-11-09",
    "2018-03-28",
    "2018-11-09",
    "2019-02-02",
    "2019-07-07",
    "2019-12-12",
    "2020-02-10",
    "2020-04-08",
    "2020-06-12",
    "2020-08-04",
    "2020-10-02",
];

macro_rules! account_sas_flags {
    (
        $(#[$type_doc:meta])*
        $name:ident($bits:ty) {
            $($(#[$flag_doc:meta])* $flag:ident = $index:literal => $wire:literal,)+
        }
    ) => {
        $(#[$type_doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name($bits);

        impl $name {
            $($(#[$flag_doc])* pub const $flag: Self = Self(1 << $index);)+

            /// Return whether the set has no flags.
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            /// Return whether the set contains every flag in `other`.
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            fn to_wire(self) -> String {
                [$((Self::$flag, $wire)),+]
                    .into_iter()
                    .filter_map(|(flag, letter)| self.contains(flag).then_some(letter))
                    .collect()
            }
        }

        impl BitOr for $name {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }
    };
}

account_sas_flags! {
    /// Azure Storage services covered by an Account SAS (`ss`). Combine with `|`.
    AccountSasServices(u8) {
        /// Azure Blob Storage, including Data Lake Storage endpoints.
        BLOB = 0 => 'b',
        /// Azure Table Storage.
        TABLE = 1 => 't',
        /// Azure Queue Storage.
        QUEUE = 2 => 'q',
        /// Azure Files.
        FILE = 3 => 'f',
    }
}

account_sas_flags! {
    /// Azure Storage resource types covered by an Account SAS (`srt`). Combine with `|`.
    AccountSasResourceTypes(u8) {
        /// Service operations, such as listing containers or shares.
        SERVICE = 0 => 's',
        /// Container, queue, table, or share operations.
        CONTAINER = 1 => 'c',
        /// Blob, message, entity, or file operations.
        OBJECT = 2 => 'o',
    }
}

account_sas_flags! {
    /// Azure Storage Account SAS permissions (`sp`). Combine with `|`.
    ///
    /// Azure determines which permissions apply to each service, resource type,
    /// and operation.
    AccountSasPermissions(u16) {
        /// Read resources.
        READ = 0 => 'r',
        /// Create and update resources.
        WRITE = 1 => 'w',
        /// Delete resources.
        DELETE = 2 => 'd',
        /// Delete a blob version.
        DELETE_VERSION = 3 => 'x',
        /// Permanently delete a blob snapshot or version.
        PERMANENT_DELETE = 4 => 'y',
        /// List resources.
        LIST = 5 => 'l',
        /// Add queue messages, table entities, or blocks to append blobs.
        ADD = 6 => 'a',
        /// Create resources without overwriting them.
        CREATE = 7 => 'c',
        /// Update queue messages or table entities.
        UPDATE = 8 => 'u',
        /// Process queue messages.
        PROCESS = 9 => 'p',
        /// Read or write blob index tags.
        TAGS = 10 => 't',
        /// Filter blobs by tags.
        FILTER_BY_TAGS = 11 => 'f',
        /// Set or delete an immutability policy or legal hold on a blob.
        SET_IMMUTABILITY_POLICY = 12 => 'i',
    }
}

/// Azure Storage service version used to authorize an Account SAS (`sv`).
///
/// Accepts documented versions from `2015-04-05` through `2026-10-06`.
/// Defaults to `2020-12-06`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountSasVersion(&'static str);

impl AccountSasVersion {
    /// Validate and create a supported Azure Storage service version.
    pub fn new(version: impl AsRef<str>) -> Result<Self> {
        let version = version.as_ref();
        LEGACY_ACCOUNT_SAS_VERSIONS
            .iter()
            .chain(SAS_VERSIONS_WITH_ENCRYPTION_SCOPE)
            .copied()
            .find(|candidate| *candidate == version)
            .map(Self)
            .ok_or_else(|| Error::config_invalid("Azure Account SAS version is not supported"))
    }

    /// Return the service version in Azure wire format.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    fn supports_encryption_scope(self) -> bool {
        self.0 >= SAS_ENCRYPTION_SCOPE_VERSION
    }
}

impl Default for AccountSasVersion {
    fn default() -> Self {
        Self(SAS_ENCRYPTION_SCOPE_VERSION)
    }
}

/// Services, resource types, and permissions selected for an Account SAS.
///
/// The selected permissions apply across eligible resources of these types
/// within the configured account.
#[derive(Clone, Copy, Debug)]
pub struct AccountSasGrant {
    services: AccountSasServices,
    resource_types: AccountSasResourceTypes,
    permissions: AccountSasPermissions,
}

impl AccountSasGrant {
    /// Bind the authorization scope. Each set must be nonempty when granting.
    pub const fn new(
        services: AccountSasServices,
        resource_types: AccountSasResourceTypes,
        permissions: AccountSasPermissions,
    ) -> Self {
        Self {
            services,
            resource_types,
            permissions,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.services.is_empty() {
            return Err(Error::request_invalid(
                "Azure Account SAS requires services",
            ));
        }
        if self.resource_types.is_empty() {
            return Err(Error::request_invalid(
                "Azure Account SAS requires resource types",
            ));
        }
        if self.permissions.is_empty() {
            return Err(Error::request_invalid(
                "Azure Account SAS requires permissions",
            ));
        }
        Ok(())
    }
}

/// Account and optional restrictions for locally issuing an Account SAS.
#[derive(Clone)]
pub struct AccountSasConfig {
    account: String,
    start: Option<Timestamp>,
    ip: Option<SasIpRange>,
    protocol: SasProtocol,
    version: AccountSasVersion,
    encryption_scope: Option<String>,
}

impl Debug for AccountSasConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSasConfig").finish_non_exhaustive()
    }
}

impl AccountSasConfig {
    /// Bind an Azure storage account. The SAS requires HTTPS by default.
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            start: None,
            ip: None,
            protocol: SasProtocol::Https,
            version: AccountSasVersion::default(),
            encryption_scope: None,
        }
    }

    /// Set an optional start time (`st`). The rounded value must be at or
    /// before the issuing time so the SAS is immediately usable.
    pub fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    /// Restrict requests to an IPv4 address or inclusive range (`sip`).
    pub fn with_ip(mut self, ip: SasIpRange) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the permitted request protocols (`spr`).
    pub fn with_protocol(mut self, protocol: SasProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Select the Azure Storage service version (`sv`).
    pub fn with_version(mut self, version: AccountSasVersion) -> Self {
        self.version = version;
        self
    }

    /// Set the server-side encryption scope for blob uploads (`ses`).
    ///
    /// Requires Blob Storage in the grant and version `2020-12-06` or later.
    pub fn with_encryption_scope(mut self, scope: impl Into<String>) -> Self {
        self.encryption_scope = Some(scope.into());
        self
    }

    fn validate(&self, services: AccountSasServices) -> Result<()> {
        validate_account(&self.account)?;
        let Some(scope) = &self.encryption_scope else {
            return Ok(());
        };
        if !self.version.supports_encryption_scope() {
            return Err(Error::config_invalid(
                "Azure Account SAS encryption scope requires version 2020-12-06 or later",
            ));
        }
        if !services.contains(AccountSasServices::BLOB) {
            return Err(Error::request_invalid(
                "Azure Account SAS encryption scope requires the Blob Storage service",
            ));
        }
        // Each dash in an Azure encryption scope name must separate alphanumerics.
        if !(3..=63).contains(&scope.len())
            || !scope
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || scope.starts_with('-')
            || scope.ends_with('-')
            || scope.contains("--")
        {
            return Err(Error::config_invalid("invalid Azure encryption scope name"));
        }
        Ok(())
    }
}

/// Issues an expiring [Azure Storage Account SAS] locally.
///
/// The source must be a [`Credential::SharedKey`] for the configured account,
/// with a Base64-encoded 512-bit storage account key. The caller selects the
/// account, allowed services, resource types, permissions, and restrictions.
/// The operation signs these choices locally using the [`Context`] crypto provider.
///
/// Pass an explicit positive `expires_in` to [`reqsign_core::Granter::grant`].
/// Start is rounded up and expiration is rounded down to whole UTC seconds.
/// The returned [`Credential::SasToken`] carries the exact signed `se` and can
/// be used with [`crate::RequestSigner`].
///
/// [Azure Storage Account SAS]: https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas
///
/// ```no_run
/// use reqsign_azure_storage::{
///     AccountSasConfig, AccountSasGrant, AccountSasGranter, AccountSasPermissions,
///     AccountSasResourceTypes, AccountSasServices, StaticCredentialProvider,
/// };
/// use reqsign_core::{Context, Granter};
/// use reqsign_crypto_rustcrypto::RustCryptoProvider;
/// use std::time::Duration;
///
/// # async fn example(account_key: &str) -> reqsign_core::Result<()> {
/// let account = "mystorageaccount";
/// let grant = AccountSasGrant::new(
///     AccountSasServices::BLOB | AccountSasServices::FILE,
///     AccountSasResourceTypes::SERVICE,
///     AccountSasPermissions::LIST,
/// );
/// let context = Context::new().with_crypto(RustCryptoProvider::new());
/// let source = StaticCredentialProvider::new_shared_key(account, account_key);
/// let operation = AccountSasGranter::new(AccountSasConfig::new(account), grant);
/// let sas = Granter::new(context, source, operation)
///     .grant(Some(Duration::from_secs(900)))
///     .await?;
/// # let _ = sas;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AccountSasGranter {
    config: AccountSasConfig,
    grant: AccountSasGrant,
    #[cfg(test)]
    time: Option<Timestamp>,
}

impl Debug for AccountSasGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountSasGranter").finish_non_exhaustive()
    }
}

impl AccountSasGranter {
    /// Create an issuing operation with a bound account and grant.
    pub fn new(config: AccountSasConfig, grant: AccountSasGrant) -> Self {
        Self {
            config,
            grant,
            #[cfg(test)]
            time: None,
        }
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn validity_window(
        &self,
        lifetime: Option<Duration>,
    ) -> Result<(Option<Timestamp>, Timestamp)> {
        let lifetime = lifetime.filter(|value| !value.is_zero()).ok_or_else(|| {
            Error::request_invalid("Azure Account SAS requires an explicit positive lifetime")
        })?;
        let now = self.now();
        let expiry = expiry_at_wire_second(now, lifetime).map_err(|_| {
            Error::request_invalid("Azure Account SAS lifetime exceeds the wire time range")
        })?;
        if expiry <= now {
            return Err(Error::request_invalid(
                "Azure Account SAS lifetime does not reach a future wire timestamp",
            ));
        }
        let start = self
            .config
            .start
            .map(ceil_to_wire_second)
            .transpose()
            .map_err(|_| {
                Error::request_invalid("Azure Account SAS start time exceeds the wire time range")
            })?;
        if start.is_some_and(|start| start >= expiry) {
            return Err(Error::request_invalid(
                "Azure Account SAS start time must be before its expiration",
            ));
        }
        if start.is_some_and(|start| start > now) {
            return Err(Error::request_invalid(
                "Azure Account SAS start time must not be in the future",
            ));
        }
        Ok((start, expiry))
    }
}

impl GrantCredential for AccountSasGranter {
    type Credential = Credential;

    fn required_valid_until(
        &self,
        _credential: &Self::Credential,
        _expires_in: Option<Duration>,
    ) -> Timestamp {
        self.now()
    }

    async fn grant_credential(
        &self,
        ctx: &Context,
        credential: &Self::Credential,
        expires_in: Option<Duration>,
    ) -> Result<Self::Credential> {
        let Credential::SharedKey {
            account_name,
            account_key,
        } = credential
        else {
            return Err(Error::credential_invalid(
                "Azure Account SAS requires a Shared Key source credential",
            ));
        };
        self.grant.validate()?;
        self.config.validate(self.grant.services)?;
        if account_name != &self.config.account {
            return Err(Error::credential_invalid(
                "Azure Shared Key source account does not match the Account SAS account",
            ));
        }
        let decoded_key = hash::base64_decode(account_key)
            .ok()
            .filter(|key| key.len() == STORAGE_ACCOUNT_KEY_LENGTH)
            .ok_or_else(|| Error::credential_invalid("Azure Account SAS source key is invalid"))?;
        let (start, expiry) = self.validity_window(expires_in)?;
        let start = start.map(Timestamp::format_rfc3339_zulu);
        let expiry_wire = expiry.format_rfc3339_zulu();
        let ip = self.config.ip.map(SasIpRange::as_string);
        let protocol = self.config.protocol.as_str();
        let version = self.config.version.as_str();
        let scope = self.config.encryption_scope.as_deref();
        let services = self.grant.services.to_wire();
        let resource_types = self.grant.resource_types.to_wire();
        let permissions = self.grant.permissions.to_wire();

        let mut string_to_sign = [
            &self.config.account,
            &permissions,
            &services,
            &resource_types,
            start.as_deref().unwrap_or_default(),
            &expiry_wire,
            ip.as_deref().unwrap_or_default(),
            protocol,
            version,
        ]
        .join("\n");
        string_to_sign.push('\n');
        if self.config.version.supports_encryption_scope() {
            // Azure requires an empty line when this version supports an omitted scope.
            string_to_sign.push_str(scope.unwrap_or_default());
            string_to_sign.push('\n');
        }
        let signature = hash::base64_hmac_sha256(
            ctx.crypto_provider()?,
            &decoded_key,
            string_to_sign.as_bytes(),
        )?;

        let mut query = vec![
            ("sv".to_string(), version.to_string()),
            ("ss".to_string(), services),
            ("srt".to_string(), resource_types),
            ("sp".to_string(), permissions),
            ("se".to_string(), expiry_wire),
            ("spr".to_string(), protocol.to_string()),
        ];
        if let Some(start) = start {
            query.push(("st".to_string(), start));
        }
        if let Some(ip) = ip {
            query.push(("sip".to_string(), ip));
        }
        if let Some(scope) = scope {
            query.push(("ses".to_string(), scope.to_string()));
        }
        query.push(("sig".to_string(), signature));
        let token = encode_query_pairs(&query);
        if expiry <= self.now() {
            return Err(Error::request_invalid(
                "Azure Account SAS expired before granting completed",
            ));
        }
        Ok(Credential::SasToken {
            token,
            expires_at: Some(expiry),
        })
    }
}

#[cfg(test)]
mod tests;
