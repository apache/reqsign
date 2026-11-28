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
use crate::constants::{
    AZURE_QUERY_ENCODE_SET, LEGACY_SAS_VERSIONS_WITH_IP_AND_PROTOCOL, SAS_ENCRYPTION_SCOPE_VERSION,
    SAS_VERSIONS_WITH_ENCRYPTION_SCOPE, STORAGE_ACCOUNT_KEY_LENGTH,
};
use crate::sas_response_overrides::SasResponseOverrides;
use crate::user_delegation_sas::SasProtocol;
use percent_encoding::{percent_decode_str, percent_encode};
use reqsign_core::crypto::CryptoProvider;
use reqsign_core::hash;
use reqsign_core::time::Timestamp;
use reqsign_core::{Context, Error, GrantCredential, Result, SigningCredential};
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use std::ops::{BitOr, BitOrAssign};
use std::time::Duration;

mod target;

use target::BLOB_SNAPSHOT_SAS_VERSION;
pub use target::{ServiceSasMode, ServiceSasTarget};

const FIRST_SERVICE_SAS_VERSION: &str = "2015-02-21";
const SAS_IP_AND_PROTOCOL_VERSION: &str = "2015-04-05";

/// Blob Storage resource for the original Service SAS constructor.
/// For additional resource types, use [`ServiceSasTarget`].
#[derive(Clone, PartialEq, Eq)]
pub enum ServiceSasResource {
    /// A container resource.
    Container { container: String },
    /// A blob resource.
    Blob { container: String, blob: String },
}

impl Debug for ServiceSasResource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServiceSasResource(REDACTED)")
    }
}

impl ServiceSasResource {
    /// Build a resource from a request path.
    ///
    /// The input path must be percent-decoded. Slashes within a blob name,
    /// including a trailing slash, are part of the name.
    pub fn from_path_percent_decoded(path: &str) -> Result<Self> {
        Self::from_path(path.trim_start_matches('/'), str::to_owned)
    }

    pub(crate) fn from_uri_resource_path(path: &str) -> Result<Self> {
        // The account prefix and its delimiter have already been separated.
        // Split at the wire separator before decoding either component.
        Self::from_path(path, |component| {
            percent_decode_str(component)
                .decode_utf8_lossy()
                .into_owned()
        })
    }

    fn from_path(path: &str, decode: impl Fn(&str) -> String) -> Result<Self> {
        let (container, blob) = path.split_once('/').unwrap_or((path, ""));
        if container.is_empty() {
            return Err(Error::request_invalid("missing container in path"));
        }

        let container = decode(container);
        if blob.is_empty() {
            Ok(Self::Container { container })
        } else {
            Ok(Self::Blob {
                container,
                blob: decode(blob),
            })
        }
    }
}

macro_rules! service_sas_permissions {
    ($(#[$type_doc:meta])* $name:ident($bits:ty) {
        $($(#[$doc:meta])* $flag:ident = $bit:literal => $letter:literal,)+
    }) => {
        $(#[$type_doc])*
        #[derive(Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name($bits);

        impl $name {
            $($(#[$doc])* pub const $flag: Self = Self(1 << $bit);)+

            /// Return whether no permission is selected.
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            /// Return whether all permissions in `other` are selected.
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            fn as_canonical_string(self) -> String {
                [$((Self::$flag, $letter)),+]
                    .into_iter()
                    .filter_map(|(flag, letter)| self.contains(flag).then_some(letter))
                    .collect()
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(REDACTED)"))
            }
        }

        impl BitOr for $name {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self::Output {
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

service_sas_permissions! {
    /// Permissions for a container-scoped Blob Storage Service SAS.
    ///
    /// Combining values with `|` produces Azure's canonical permission order.
    ServiceSasContainerPermissions(u16) {
        /// Read blobs in the container.
        READ = 0 => 'r',
        /// Add blocks to append blobs.
        ADD = 1 => 'a',
        /// Create blobs.
        CREATE = 2 => 'c',
        /// Write blob data and metadata.
        WRITE = 3 => 'w',
        /// Delete blobs.
        DELETE = 4 => 'd',
        /// Delete blob versions.
        DELETE_VERSION = 5 => 'x',
        /// Permanently delete blob snapshots or versions.
        PERMANENT_DELETE = 6 => 'y',
        /// List blobs.
        LIST = 7 => 'l',
        /// Read or write blob index tags.
        TAGS = 8 => 't',
        /// Find blobs by index tags.
        FILTER_BY_TAGS = 9 => 'f',
        /// Move blobs in hierarchical-namespace accounts.
        MOVE = 10 => 'm',
        /// Read system properties or POSIX ACLs.
        EXECUTE = 11 => 'e',
        /// Set the owner or owning group for hierarchical namespace resources.
        OWNERSHIP = 12 => 'o',
        /// Set POSIX permissions or ACLs for hierarchical namespace resources.
        PERMISSIONS = 13 => 'p',
        /// Set an immutability policy or legal hold.
        SET_IMMUTABILITY_POLICY = 14 => 'i',
    }
}

service_sas_permissions! {
    /// Permissions for a blob-scoped Blob Storage Service SAS.
    ///
    /// Combining values with `|` produces Azure's canonical permission order.
    ServiceSasBlobPermissions(u16) {
        /// Read the blob.
        READ = 0 => 'r',
        /// Add blocks to an append blob.
        ADD = 1 => 'a',
        /// Create the blob.
        CREATE = 2 => 'c',
        /// Write blob data and metadata.
        WRITE = 3 => 'w',
        /// Delete the blob.
        DELETE = 4 => 'd',
        /// Delete a blob version.
        DELETE_VERSION = 5 => 'x',
        /// Permanently delete a blob snapshot or version.
        PERMANENT_DELETE = 6 => 'y',
        /// Read or write blob index tags.
        TAGS = 7 => 't',
        /// Move the blob in hierarchical-namespace accounts.
        MOVE = 8 => 'm',
        /// Read system properties or POSIX ACLs.
        EXECUTE = 9 => 'e',
        /// Set the owner or owning group for hierarchical namespace resources.
        OWNERSHIP = 10 => 'o',
        /// Set POSIX permissions or ACLs for hierarchical namespace resources.
        PERMISSIONS = 11 => 'p',
        /// Set an immutability policy or legal hold.
        SET_IMMUTABILITY_POLICY = 12 => 'i',
    }
}

service_sas_permissions! {
    /// Permissions for an Azure Files share or file Service SAS. Combine with `|`.
    ServiceSasFilePermissions(u8) {
        /// Read files and their properties and metadata.
        READ = 0 => 'r',
        /// Create or copy a file.
        CREATE = 1 => 'c',
        /// Write file data, properties, or metadata.
        WRITE = 2 => 'w',
        /// Delete a file.
        DELETE = 3 => 'd',
        /// List directories and files. Valid only for a share grant.
        LIST = 4 => 'l',
    }
}

service_sas_permissions! {
    /// Permissions for an Azure Queue Service SAS. Combine with `|`.
    ServiceSasQueuePermissions(u8) {
        /// Read properties and metadata or peek at messages.
        READ = 0 => 'r',
        /// Add messages.
        ADD = 1 => 'a',
        /// Update messages.
        UPDATE = 2 => 'u',
        /// Retrieve and delete messages.
        PROCESS = 3 => 'p',
    }
}

/// One complete, typed Azure Storage Service SAS grant.
#[derive(Clone)]
pub struct ServiceSasGrant {
    target: ServiceSasTarget,
    permissions: String,
    identifier: Option<String>,
    response_overrides: SasResponseOverrides,
}

impl Debug for ServiceSasGrant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasGrant").finish_non_exhaustive()
    }
}

impl ServiceSasGrant {
    fn new(target: ServiceSasTarget, permissions: String) -> Self {
        Self {
            target,
            permissions,
            identifier: None,
            response_overrides: SasResponseOverrides::default(),
        }
    }

    /// Grant permissions over one container and its blobs.
    pub fn for_container(
        container: impl Into<String>,
        permissions: ServiceSasContainerPermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::Container {
                container: container.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over one exact blob.
    pub fn for_blob(
        container: impl Into<String>,
        blob: impl Into<String>,
        permissions: ServiceSasBlobPermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::Blob {
                container: container.into(),
                blob: blob.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over one blob snapshot. The request must carry the
    /// matching `snapshot` query parameter.
    pub fn for_blob_snapshot(
        container: impl Into<String>,
        blob: impl Into<String>,
        snapshot: impl Into<String>,
        permissions: ServiceSasBlobPermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::BlobSnapshot {
                container: container.into(),
                blob: blob.into(),
                snapshot: snapshot.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over one blob version. The request must carry the
    /// matching `versionid` query parameter.
    pub fn for_blob_version(
        container: impl Into<String>,
        blob: impl Into<String>,
        version_id: impl Into<String>,
        permissions: ServiceSasBlobPermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::BlobVersion {
                container: container.into(),
                blob: blob.into(),
                version_id: version_id.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over a hierarchical-namespace directory. An empty
    /// path selects the container's root directory.
    pub fn for_directory(
        container: impl Into<String>,
        path: impl Into<String>,
        permissions: ServiceSasContainerPermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::Directory {
                container: container.into(),
                path: path.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over one share and its files.
    pub fn for_file_share(
        share: impl Into<String>,
        permissions: ServiceSasFilePermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::FileShare {
                share: share.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over one file at a path relative to the share.
    pub fn for_file(
        share: impl Into<String>,
        path: impl Into<String>,
        permissions: ServiceSasFilePermissions,
    ) -> Self {
        Self::new(
            ServiceSasTarget::File {
                share: share.into(),
                path: path.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Grant permissions over one queue and its messages.
    pub fn for_queue(queue: impl Into<String>, permissions: ServiceSasQueuePermissions) -> Self {
        Self::new(
            ServiceSasTarget::Queue {
                queue: queue.into(),
            },
            permissions.as_canonical_string(),
        )
    }

    /// Associate the grant with an existing stored access policy (`si`).
    ///
    /// The policy must leave expiry unspecified because the granter signs an
    /// explicit expiry. Use an empty permission set to let the policy supply
    /// permissions. Set a start time or permissions on only one side.
    pub fn with_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Sign response header overrides for a Blob Storage or Azure Files grant.
    pub fn with_response_overrides(mut self, overrides: SasResponseOverrides) -> Self {
        self.response_overrides = overrides;
        self
    }

    fn validate(&self) -> Result<()> {
        match &self.target {
            ServiceSasTarget::Container { container } => validate_container(container)?,
            ServiceSasTarget::Blob { container, blob } => {
                validate_container(container)?;
                validate_blob(blob)?;
            }
            _ => {}
        }
        if self.identifier.is_none() && self.permissions.is_empty() {
            return Err(Error::request_invalid(
                "Azure Service SAS permissions must not be empty",
            ));
        }
        Ok(())
    }
}

/// One IPv4 address or inclusive IPv4 range for an Azure SAS.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SasIpRange {
    start: Ipv4Addr,
    end: Option<Ipv4Addr>,
}

impl SasIpRange {
    /// Restrict requests to one IPv4 address.
    pub const fn address(address: Ipv4Addr) -> Self {
        Self {
            start: address,
            end: None,
        }
    }

    /// Restrict requests to an inclusive IPv4 range.
    pub fn range(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self> {
        if u32::from(start) > u32::from(end) {
            return Err(Error::request_invalid(
                "SAS IPv4 range start must not exceed its end",
            ));
        }
        Ok(Self {
            start,
            end: Some(end),
        })
    }

    pub(crate) fn as_string(self) -> String {
        self.end.map_or_else(
            || self.start.to_string(),
            |end| format!("{}-{end}", self.start),
        )
    }
}

impl From<Ipv4Addr> for SasIpRange {
    fn from(value: Ipv4Addr) -> Self {
        Self::address(value)
    }
}

impl Debug for SasIpRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SasIpRange(REDACTED)")
    }
}

/// Azure Storage service version used to authorize a Service SAS.
///
/// This type accepts documented Azure Storage versions from `2015-04-05`
/// through `2026-10-06` and defaults to `2020-12-06`. Certain resources and
/// permissions require a newer version.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceSasVersion(String);

impl ServiceSasVersion {
    /// Validate and create a supported Azure Storage service version.
    pub fn new(version: impl Into<String>) -> Result<Self> {
        let version = version.into();
        if !LEGACY_SAS_VERSIONS_WITH_IP_AND_PROTOCOL.contains(&version.as_str())
            && !SAS_VERSIONS_WITH_ENCRYPTION_SCOPE.contains(&version.as_str())
        {
            return Err(Error::config_invalid(
                "Azure Service SAS version is not supported by this signer",
            ));
        }
        Ok(Self(version))
    }

    /// Return the service version in Azure wire format.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ServiceSasVersion {
    fn default() -> Self {
        Self(SAS_ENCRYPTION_SCOPE_VERSION.to_string())
    }
}

impl Debug for ServiceSasVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ServiceSasVersion").field(&self.0).finish()
    }
}

/// Stable configuration for locally generating one Azure Storage Service SAS.
#[derive(Clone)]
pub struct ServiceSasConfig {
    account: String,
    start: Option<Timestamp>,
    ip: Option<SasIpRange>,
    protocol: SasProtocol,
    version: ServiceSasVersion,
}

impl Debug for ServiceSasConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasConfig").finish_non_exhaustive()
    }
}

impl ServiceSasConfig {
    /// Create configuration bound to one Azure storage account.
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
            start: None,
            ip: None,
            protocol: SasProtocol::Https,
            version: ServiceSasVersion::default(),
        }
    }

    /// Set an optional SAS start time.
    ///
    /// The rounded wire value must not be later than the time of granting,
    /// because the returned credential must be immediately usable.
    pub fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    /// Restrict the SAS to an IPv4 address or inclusive range.
    pub fn with_ip(mut self, ip: SasIpRange) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the protocol restriction embedded in the SAS.
    pub fn with_protocol(mut self, protocol: SasProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the Azure Storage service version embedded in the SAS.
    pub fn with_version(mut self, version: ServiceSasVersion) -> Self {
        self.version = version;
        self
    }

    fn validate(&self) -> Result<ValidatedConfig> {
        validate_account(&self.account)?;
        Ok(ValidatedConfig {
            account: self.account.clone(),
            start: self.start,
            ip: self.ip.map(SasIpRange::as_string),
            protocol: self.protocol,
            version: self.version.clone(),
        })
    }
}

struct ValidatedConfig {
    account: String,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: SasProtocol,
    version: ServiceSasVersion,
}

pub(crate) fn validate_account(account: &str) -> Result<()> {
    if !(3..=24).contains(&account.len())
        || !account
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
    {
        return Err(Error::config_invalid(
            "Azure storage account name must be 3-24 lowercase ASCII letters or digits",
        ));
    }
    Ok(())
}

fn validate_container(container: &str) -> Result<()> {
    if matches!(container, "$root" | "$web" | "$logs") {
        return Ok(());
    }
    if !valid_dns_name(container) {
        return Err(Error::request_invalid(
            "invalid Azure Blob Storage container name",
        ));
    }
    Ok(())
}

fn valid_dns_name(name: &str) -> bool {
    (3..=63).contains(&name.len())
        && name
            .bytes()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-')
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !name.contains("--")
}

fn validate_blob(blob: &str) -> Result<()> {
    if blob.is_empty()
        || blob.chars().count() > 1024
        || blob
            .chars()
            .any(|value| value.is_control() || value == '\\')
    {
        return Err(Error::request_invalid(
            "blob name must be a non-empty percent-decoded name without control characters or backslashes",
        ));
    }
    Ok(())
}

/// Service SAS generator using Shared Key.
///
/// Reference: <https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas>
pub struct ServiceSharedAccessSignature {
    account: String,
    key: String,

    target: ServiceSasTarget,
    permissions: String,
    expiry: Option<Timestamp>,
    start: Option<Timestamp>,
    ip: Option<String>,
    protocol: Option<String>,
    version: String,
    identifier: Option<String>,
    response_overrides: SasResponseOverrides,
}

impl ServiceSharedAccessSignature {
    /// Create a Service SAS signer for a blob or container with an explicit expiry.
    pub fn new(
        account: String,
        key: String,
        resource: ServiceSasResource,
        permissions: String,
        expiry: Timestamp,
    ) -> Self {
        Self::for_target(account, key, resource, permissions, Some(expiry))
    }

    /// Create a Service SAS signer for an Azure Storage target.
    ///
    /// The permission string must use Azure's order for the target. An empty
    /// permission string or absent expiry delegates that field to a stored
    /// access policy set with [`Self::with_identifier`]. Set each of start,
    /// expiry, and permissions on only one side. This constructor signs raw
    /// query parameters and does not infer a policy's expiry.
    pub fn for_target(
        account: String,
        key: String,
        target: impl Into<ServiceSasTarget>,
        permissions: String,
        expiry: Option<Timestamp>,
    ) -> Self {
        Self {
            account,
            key,
            target: target.into(),
            permissions,
            expiry,
            start: None,
            ip: None,
            protocol: None,
            version: SAS_ENCRYPTION_SCOPE_VERSION.to_string(),
            identifier: None,
            response_overrides: SasResponseOverrides::default(),
        }
    }

    /// Set the start time.
    pub fn with_start(mut self, start: Timestamp) -> Self {
        self.start = Some(start);
        self
    }

    /// Set the IP restriction.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    /// Set the allowed protocol.
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Set the Azure Storage service version (`2015-02-21` or later).
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Associate the SAS with a stored access policy (`si`).
    pub fn with_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Sign response header overrides for a Blob Storage or Azure Files SAS.
    pub fn with_response_overrides(mut self, overrides: SasResponseOverrides) -> Self {
        self.response_overrides = overrides;
        self
    }

    fn validate(&self) -> Result<()> {
        let version = self.version.as_str();
        if version.len() != 10
            || version < FIRST_SERVICE_SAS_VERSION
            || format!("{version}T00:00:00Z").parse::<Timestamp>().is_err()
        {
            return Err(Error::request_invalid(
                "invalid or unsupported Azure Service SAS version",
            ));
        }
        if version < SAS_IP_AND_PROTOCOL_VERSION && (self.ip.is_some() || self.protocol.is_some()) {
            return Err(Error::request_invalid(
                "Azure Service SAS IP and protocol restrictions require version 2015-04-05 or later",
            ));
        }
        if let Some(identifier) = &self.identifier {
            if identifier.is_empty()
                || identifier.chars().count() > 64
                || identifier.chars().any(char::is_control)
            {
                return Err(Error::request_invalid(
                    "Azure stored access policy identifier must be 1-64 characters without control characters",
                ));
            }
        } else if self.expiry.is_none() || self.permissions.is_empty() {
            return Err(Error::request_invalid(
                "Azure Service SAS requires permissions and expiry without a stored access policy",
            ));
        }
        self.response_overrides.validate()?;
        if self.target.signed_resource().is_none()
            && self
                .response_overrides
                .fields()
                .iter()
                .any(|(_, value)| !value.is_empty())
        {
            return Err(Error::request_invalid(
                "Azure Queue Service SAS does not support response header overrides",
            ));
        }
        self.target.validate(version, &self.permissions)?;
        if self.target.is_blob_storage() {
            for (since, permissions) in [
                ("2019-12-12", ['x', 't', 'f'].as_slice()),
                ("2020-02-10", ['y', 'm', 'e', 'o', 'p'].as_slice()),
                ("2020-06-12", ['i'].as_slice()),
            ] {
                if version < since && self.permissions.contains(permissions) {
                    return Err(Error::request_invalid(
                        "Azure Service SAS permission is unavailable for the selected version",
                    ));
                }
            }
        }
        Ok(())
    }

    fn string_to_sign(&self) -> String {
        let start = self.start.map(Timestamp::format_rfc3339_zulu);
        let expiry = self.expiry.map(Timestamp::format_rfc3339_zulu);
        let resource = self.target.canonicalized_resource(&self.account);
        let mut fields = vec![
            self.permissions.as_str(),
            start.as_deref().unwrap_or_default(),
            expiry.as_deref().unwrap_or_default(),
            &resource,
            self.identifier.as_deref().unwrap_or_default(),
        ];
        let version = self.version.as_str();
        if version >= SAS_IP_AND_PROTOCOL_VERSION {
            fields.extend([
                self.ip.as_deref().unwrap_or_default(),
                self.protocol.as_deref().unwrap_or_default(),
            ]);
        }
        fields.push(version);
        if self.target.is_blob_storage() && version >= BLOB_SNAPSHOT_SAS_VERSION {
            fields.push(self.target.signed_resource().unwrap_or_default());
            fields.push(self.target.signed_timestamp());
            if version >= SAS_ENCRYPTION_SCOPE_VERSION {
                fields.push(""); // signed encryption scope
            }
        }
        // Files uses sr on the wire but does not include it in the string-to-sign.
        // Queue includes neither sr nor the response override fields.
        if self.target.signed_resource().is_some() {
            fields.extend(self.response_overrides.fields().map(|(_, value)| value));
        }
        fields.join("\n")
    }

    fn signature_with_decoded_key(
        &self,
        provider: &dyn CryptoProvider,
        decoded_key: &[u8],
    ) -> reqsign_core::Result<String> {
        hash::base64_hmac_sha256(provider, decoded_key, self.string_to_sign().as_bytes())
    }

    fn token_with_decoded_key(
        &self,
        provider: &dyn CryptoProvider,
        decoded_key: &[u8],
    ) -> reqsign_core::Result<Vec<(String, String)>> {
        self.validate()?;
        let mut elements = vec![("sv".to_string(), self.version.clone())];
        if let Some(expiry) = self.expiry {
            elements.push(("se".to_string(), expiry.format_rfc3339_zulu()));
        }
        if !self.permissions.is_empty() {
            elements.push(("sp".to_string(), self.permissions.clone()));
        }
        if let Some(resource) = self.target.signed_resource() {
            elements.push(("sr".to_string(), resource.to_string()));
        }
        if let Some(depth) = self.target.directory_depth() {
            elements.push(("sdd".to_string(), depth.to_string()));
        }
        if let Some(identifier) = &self.identifier {
            elements.push(("si".to_string(), identifier.clone()));
        }
        if let Some(start) = &self.start {
            elements.push(("st".to_string(), start.format_rfc3339_zulu()))
        }
        if let Some(ip) = &self.ip {
            elements.push(("sip".to_string(), ip.to_string()))
        }
        if let Some(protocol) = &self.protocol {
            elements.push(("spr".to_string(), protocol.to_string()))
        }

        self.response_overrides.append_to_query(&mut elements);
        elements.push((
            "sig".to_string(),
            self.signature_with_decoded_key(provider, decoded_key)?,
        ));

        Ok(elements)
    }

    /// Generate SAS query parameters.
    ///
    /// `provider` must be the provider selected for this operation. Callers with
    /// a [`Context`] resolve it with `context.crypto_provider()?`. Supply the
    /// matching `snapshot` or `versionid` request query parameter separately
    /// when using a snapshot or version SAS.
    pub fn token(&self, provider: &dyn CryptoProvider) -> Result<Vec<(String, String)>> {
        let decoded_key = hash::base64_decode(&self.key)?;
        self.token_with_decoded_key(provider, &decoded_key)
    }
}

pub(crate) fn encode_query_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode(key.as_bytes(), &AZURE_QUERY_ENCODE_SET),
                percent_encode(value.as_bytes(), &AZURE_QUERY_ENCODE_SET)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

struct OperationTimes {
    now: Timestamp,
    start: Option<Timestamp>,
    expiry: Timestamp,
}

/// Grants expiration-aware Azure Storage Service SAS credentials.
///
/// The source credential must be [`Credential::SharedKey`] for exactly the
/// account bound in [`ServiceSasConfig`], with a Base64-encoded 512-bit Azure
/// account key. Service SAS generation is local and performs no network I/O.
/// `expires_in` must be explicit and non-zero. Azure wire timestamps have
/// whole-second precision: explicit start times are rounded forward,
/// expirations are rounded backward, and the returned credential expiration
/// exactly matches the signed `se` value.
#[derive(Clone)]
pub struct ServiceSasGranter {
    config: ServiceSasConfig,
    grant: ServiceSasGrant,
    #[cfg(test)]
    time: Option<Timestamp>,
    #[cfg(test)]
    time_after_generation: Option<Timestamp>,
}

impl Debug for ServiceSasGranter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasGranter").finish_non_exhaustive()
    }
}

impl ServiceSasGranter {
    /// Create a granter for a bound account configuration and typed grant.
    pub fn new(config: ServiceSasConfig, grant: ServiceSasGrant) -> Self {
        Self {
            config,
            grant,
            #[cfg(test)]
            time: None,
            #[cfg(test)]
            time_after_generation: None,
        }
    }

    /// Replace the bound resource and permission grant.
    pub fn with_grant(mut self, grant: ServiceSasGrant) -> Self {
        self.grant = grant;
        self
    }

    #[cfg(test)]
    fn with_time(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    #[cfg(test)]
    fn with_time_after_generation(mut self, time: Timestamp) -> Self {
        self.time_after_generation = Some(time);
        self
    }

    fn now(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn now_after_generation(&self) -> Timestamp {
        #[cfg(test)]
        if let Some(time) = self.time_after_generation {
            return time;
        }
        #[cfg(test)]
        if let Some(time) = self.time {
            return time;
        }
        Timestamp::now()
    }

    fn operation_times(
        &self,
        start: Option<Timestamp>,
        expires_in: Option<Duration>,
    ) -> Result<OperationTimes> {
        let expires_in = expires_in.ok_or_else(|| {
            Error::request_invalid("Azure Service SAS requires an explicit lifetime")
        })?;
        if expires_in.is_zero() {
            return Err(Error::request_invalid(
                "Azure Service SAS lifetime must be greater than zero",
            ));
        }

        let now = self.now();
        let expiry = expiry_at_wire_second(now, expires_in)?;
        if expiry <= now {
            return Err(Error::request_invalid(
                "Azure Service SAS lifetime does not reach a future wire timestamp",
            ));
        }
        let start = start.map(ceil_to_wire_second).transpose()?;
        if start.is_some_and(|start| start > now) {
            return Err(Error::request_invalid(
                "Azure Service SAS start time must not be in the future",
            ));
        }
        if start.is_some_and(|start| start >= expiry) {
            return Err(Error::request_invalid(
                "Azure Service SAS start time must be before its expiration",
            ));
        }

        Ok(OperationTimes { now, start, expiry })
    }
}

impl GrantCredential for ServiceSasGranter {
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
        let provider = ctx.crypto_provider()?;
        let Credential::SharedKey {
            account_name,
            account_key,
        } = credential
        else {
            return Err(Error::credential_invalid(
                "Azure Service SAS requires a Shared Key source credential",
            ));
        };

        let config = self.config.validate()?;
        if account_name != &config.account {
            return Err(Error::credential_invalid(
                "Azure Shared Key source account does not match the Service SAS account",
            ));
        }
        if account_key.is_empty() {
            return Err(Error::credential_invalid(
                "Azure Service SAS source account key is missing",
            ));
        }
        let decoded_key = hash::base64_decode(account_key).map_err(|_| {
            Error::credential_invalid("Azure Service SAS source account key is invalid")
        })?;
        if decoded_key.len() != STORAGE_ACCOUNT_KEY_LENGTH {
            return Err(Error::credential_invalid(
                "Azure Service SAS source account key is invalid",
            ));
        }

        self.grant.validate()?;
        let times = self.operation_times(config.start, expires_in)?;
        if !credential.is_valid_at(times.now) {
            return Err(Error::credential_invalid(
                "Azure Service SAS source credential is not currently usable",
            ));
        }

        let mut signer = ServiceSharedAccessSignature::for_target(
            config.account,
            String::new(),
            self.grant.target.clone(),
            self.grant.permissions.clone(),
            Some(times.expiry),
        )
        .with_protocol(config.protocol.as_str())
        .with_version(config.version.as_str())
        .with_response_overrides(self.grant.response_overrides.clone());
        if let Some(identifier) = &self.grant.identifier {
            signer = signer.with_identifier(identifier);
        }
        if let Some(start) = times.start {
            signer = signer.with_start(start);
        }
        if let Some(ip) = config.ip {
            signer = signer.with_ip(ip);
        }

        let pairs = signer.token_with_decoded_key(provider, &decoded_key)?;
        let token = encode_query_pairs(&pairs);
        let after_generation = self.now_after_generation();
        if times.expiry <= after_generation {
            return Err(Error::request_invalid(
                "Azure Service SAS expired before granting completed",
            ));
        }

        let output = Credential::with_sas_token_expires_at(&token, times.expiry);
        if !output.is_valid_at(after_generation) {
            return Err(Error::credential_invalid(
                "granted Azure Service SAS is not currently usable",
            ));
        }
        Ok(output)
    }
}

pub(crate) fn expiry_at_wire_second(now: Timestamp, expires_in: Duration) -> Result<Timestamp> {
    let duration_seconds = i64::try_from(expires_in.as_secs()).map_err(|_| {
        Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
    })?;
    let fractional = i64::from(now.subsec_nanosecond())
        .checked_add(i64::from(expires_in.subsec_nanos()))
        .ok_or_else(|| {
            Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
        })?;
    let carry = fractional.div_euclid(1_000_000_000);
    let expiry_second = now
        .as_second()
        .checked_add(duration_seconds)
        .and_then(|value| value.checked_add(carry))
        .ok_or_else(|| {
            Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
        })?;
    Timestamp::from_second(expiry_second).map_err(|_| {
        Error::request_invalid("Azure Service SAS lifetime exceeds the wire time range")
    })
}

pub(crate) fn ceil_to_wire_second(timestamp: Timestamp) -> Result<Timestamp> {
    let mut second = timestamp.as_second();
    if timestamp.subsec_nanosecond() > 0 {
        second = second.checked_add(1).ok_or_else(|| {
            Error::request_invalid("Azure Service SAS timestamp exceeds the wire time range")
        })?;
    }
    Timestamp::from_second(second).map_err(|_| {
        Error::request_invalid("Azure Service SAS timestamp exceeds the wire time range")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sas_response_overrides::{TEST_RESPONSE_OVERRIDE_QUERY, test_response_overrides};
    use crate::{RequestSigner, StaticCredentialProvider};
    use reqsign_core::{ErrorKind, Granter, SignRequest, Signer};
    use std::str::FromStr;

    const VALID_ACCOUNT_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_time() -> Timestamp {
        Timestamp::from_str("2022-03-01T08:12:34Z").unwrap()
    }

    #[test]
    fn test_can_generate_service_sas_token_for_blob() {
        let key = hash::base64_encode("key".as_bytes());
        let expiry = test_time() + Duration::from_secs(300);

        let resource = ServiceSasResource::Blob {
            container: "container".to_string(),
            blob: "path/to/blob.txt".to_string(),
        };

        let sign = ServiceSharedAccessSignature::new(
            "account".to_string(),
            key,
            resource,
            "r".to_string(),
            expiry,
        );

        let token_content = sign
            .token(&reqsign_crypto_rustcrypto::RustCryptoProvider::new())
            .expect("token generation failed");
        let token = token_content
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<String>>()
            .join("&");

        assert_eq!(
            token,
            "sv=2020-12-06&se=2022-03-01T08:17:34Z&sp=r&sr=b&sig=CP9a2LIrR9zeG4I4jZjqPetJSXWJ77QeUA7c3GMypyM="
        );
    }

    #[test]
    fn test_service_sas_resource_from_path() {
        assert_eq!(
            ServiceSasResource::from_path_percent_decoded("/container").unwrap(),
            ServiceSasResource::Container {
                container: "container".to_string()
            }
        );

        assert_eq!(
            ServiceSasResource::from_path_percent_decoded("/container/dir//marker/").unwrap(),
            ServiceSasResource::Blob {
                container: "container".to_string(),
                blob: "dir//marker/".to_string()
            }
        );
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().expect("timestamp must parse")
    }

    fn shared_key(account: &str, decoded_key: &str) -> Credential {
        Credential::with_shared_key(account, &hash::base64_encode(decoded_key.as_bytes()))
    }

    fn output_parts(credential: &Credential) -> (&str, Timestamp) {
        match credential {
            Credential::SasToken {
                token,
                expires_at: Some(expires_at),
            } => (token, *expires_at),
            other => panic!("expected expiring SAS credential, got {other:?}"),
        }
    }

    fn query_value(token: &str, key: &str) -> Option<String> {
        form_urlencoded::parse(token.as_bytes())
            .find_map(|(candidate, value)| (candidate == key).then(|| value.into_owned()))
    }

    #[test]
    fn typed_permissions_use_resource_specific_canonical_order() {
        let container_permissions = ServiceSasContainerPermissions::READ
            | ServiceSasContainerPermissions::ADD
            | ServiceSasContainerPermissions::CREATE
            | ServiceSasContainerPermissions::WRITE
            | ServiceSasContainerPermissions::DELETE
            | ServiceSasContainerPermissions::DELETE_VERSION
            | ServiceSasContainerPermissions::PERMANENT_DELETE
            | ServiceSasContainerPermissions::LIST
            | ServiceSasContainerPermissions::TAGS
            | ServiceSasContainerPermissions::FILTER_BY_TAGS
            | ServiceSasContainerPermissions::MOVE
            | ServiceSasContainerPermissions::EXECUTE
            | ServiceSasContainerPermissions::OWNERSHIP
            | ServiceSasContainerPermissions::PERMISSIONS
            | ServiceSasContainerPermissions::SET_IMMUTABILITY_POLICY;
        let container = ServiceSasGrant::for_container("container", container_permissions);
        container.validate().expect("container grant must be valid");
        assert_eq!(container.permissions, "racwdxyltfmeopi");
        assert!(container_permissions.contains(ServiceSasContainerPermissions::LIST));
        assert!(container_permissions.contains(ServiceSasContainerPermissions::OWNERSHIP));
        assert!(container_permissions.contains(ServiceSasContainerPermissions::PERMISSIONS));

        let blob_permissions = ServiceSasBlobPermissions::READ
            | ServiceSasBlobPermissions::ADD
            | ServiceSasBlobPermissions::CREATE
            | ServiceSasBlobPermissions::WRITE
            | ServiceSasBlobPermissions::DELETE
            | ServiceSasBlobPermissions::DELETE_VERSION
            | ServiceSasBlobPermissions::PERMANENT_DELETE
            | ServiceSasBlobPermissions::TAGS
            | ServiceSasBlobPermissions::MOVE
            | ServiceSasBlobPermissions::EXECUTE
            | ServiceSasBlobPermissions::OWNERSHIP
            | ServiceSasBlobPermissions::PERMISSIONS
            | ServiceSasBlobPermissions::SET_IMMUTABILITY_POLICY;
        let blob = ServiceSasGrant::for_blob("container", "blob", blob_permissions);
        blob.validate().expect("blob grant must be valid");
        assert_eq!(blob.permissions, "racwdxytmeopi");
        assert!(blob_permissions.contains(ServiceSasBlobPermissions::TAGS));
        assert!(blob_permissions.contains(ServiceSasBlobPermissions::OWNERSHIP));
        assert!(blob_permissions.contains(ServiceSasBlobPermissions::PERMISSIONS));
    }

    #[test]
    fn validates_complete_grants_versions_and_ip_ranges() {
        for grant in [
            ServiceSasGrant::for_container("container", ServiceSasContainerPermissions::default()),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::default()),
            ServiceSasGrant::for_container("UPPER", ServiceSasContainerPermissions::READ),
            ServiceSasGrant::for_blob("container", "", ServiceSasBlobPermissions::READ),
        ] {
            assert_eq!(
                grant
                    .validate()
                    .expect_err("invalid grant must fail")
                    .kind(),
                ErrorKind::RequestInvalid
            );
        }

        for version in [
            "2020-12-05",
            "2022-10-02",
            "2022-13-40",
            "2022-1-01",
            "9999-01-01",
            "future",
        ] {
            assert_eq!(
                ServiceSasVersion::new(version)
                    .expect_err("unsupported version must fail")
                    .kind(),
                ErrorKind::ConfigInvalid
            );
        }
        for version in ["2020-12-06", "2022-11-02", "2026-04-06"] {
            assert_eq!(
                ServiceSasVersion::new(version)
                    .expect("documented version must be accepted")
                    .as_str(),
                version
            );
        }

        let start = Ipv4Addr::new(198, 51, 100, 20);
        let end = Ipv4Addr::new(198, 51, 100, 10);
        assert_eq!(
            SasIpRange::range(start, end)
                .expect_err("reversed range must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );
    }

    #[tokio::test]
    async fn grants_leading_slash_blob_with_hierarchical_namespace_permissions() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob(
                "container",
                "/a",
                ServiceSasBlobPermissions::OWNERSHIP | ServiceSasBlobPermissions::PERMISSIONS,
            ),
        )
        .with_time(now);

        let output = operation
            .grant_credential(
                &crate::test_context(),
                &shared_key("account", VALID_ACCOUNT_KEY),
                Some(Duration::from_secs(60)),
            )
            .await
            .expect("leading-slash blob grant must be valid");
        let (token, expires_at) = output_parts(&output);

        assert_eq!(expires_at, timestamp("2030-01-01T00:01:00Z"));
        assert_eq!(
            token,
            "sv=2020-12-06&se=2030-01-01T00%3A01%3A00Z&sp=op&sr=b&spr=https&sig=fp21tjpRyr%2BTLkc5wZgehHGIbXj04QeiXTppdexgr6I%3D"
        );

        let signer = Signer::new(
            crate::test_context(),
            StaticCredentialProvider::new_sas_token_expires_at(token, expires_at),
            RequestSigner::new(),
        );
        let mut parts = http::Request::get("https://account.blob.core.windows.net/container//a")
            .body(())
            .expect("request must build")
            .into_parts()
            .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume the leading-slash blob SAS");
        assert_eq!(
            parts.uri.to_string(),
            format!("https://account.blob.core.windows.net/container//a?{token}")
        );
    }

    #[tokio::test]
    async fn grants_independently_computed_wire_vector() {
        let now = timestamp("2030-01-01T00:00:01.500Z");
        let start = timestamp("2030-01-01T00:00:00.750Z");
        let expiry = timestamp("2030-01-01T00:00:03Z");
        let ip = SasIpRange::range(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 20),
        )
        .expect("range must be ordered");
        let version = ServiceSasVersion::new("2022-11-02").expect("service version must be valid");
        let config = ServiceSasConfig::new("account")
            .with_start(start)
            .with_ip(ip)
            .with_protocol(SasProtocol::HttpsAndHttp)
            .with_version(version);
        let grant = ServiceSasGrant::for_blob(
            "container",
            "path/to/blob name.txt",
            ServiceSasBlobPermissions::WRITE | ServiceSasBlobPermissions::READ,
        );
        let operation = ServiceSasGranter::new(config, grant).with_time(now);
        let source = shared_key("account", VALID_ACCOUNT_KEY);

        let output = operation
            .grant_credential(
                &crate::test_context(),
                &source,
                Some(Duration::from_millis(1_500)),
            )
            .await
            .expect("Service SAS grant must succeed");
        let (token, expires_at) = output_parts(&output);

        assert_eq!(expires_at, expiry);
        assert_eq!(
            token,
            "sv=2022-11-02&se=2030-01-01T00%3A00%3A03Z&sp=rw&sr=b&st=2030-01-01T00%3A00%3A01Z&sip=198.51.100.10-198.51.100.20&spr=https%2Chttp&sig=57MGNuddYiw/hojfFxQkcz1qgFd8klPpi31BmqTAb28%3D"
        );
        assert_eq!(
            query_value(token, "sig").as_deref(),
            Some("57MGNuddYiw/hojfFxQkcz1qgFd8klPpi31BmqTAb28=")
        );
        assert!(!token.contains(VALID_ACCOUNT_KEY));

        let direct = ServiceSharedAccessSignature::new(
            "account".to_string(),
            hash::base64_encode(VALID_ACCOUNT_KEY.as_bytes()),
            ServiceSasResource::Blob {
                container: "container".to_string(),
                blob: "path/to/blob name.txt".to_string(),
            },
            "rw".to_string(),
            expiry,
        )
        .with_start(timestamp("2030-01-01T00:00:01Z"))
        .with_ip("198.51.100.10-198.51.100.20")
        .with_protocol("https,http")
        .with_version("2022-11-02");
        assert_eq!(
            direct.string_to_sign(),
            "rw\n2030-01-01T00:00:01Z\n2030-01-01T00:00:03Z\n/blob/account/container/path/to/blob name.txt\n\n198.51.100.10-198.51.100.20\nhttps,http\n2022-11-02\nb\n\n\n\n\n\n\n"
        );
        assert_eq!(
            encode_query_pairs(
                &direct
                    .token(&reqsign_crypto_rustcrypto::RustCryptoProvider::new())
                    .expect("compatibility signer must succeed"),
            ),
            token
        );
    }

    #[test]
    fn signs_policy_owned_expiry_and_permissions_without_inventing_either() {
        let signer = ServiceSharedAccessSignature::for_target(
            "account".into(),
            "a2V5".into(),
            ServiceSasResource::Container {
                container: "container".into(),
            },
            String::new(),
            None,
        )
        .with_response_overrides(test_response_overrides());
        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        assert_eq!(
            signer.token(&provider).unwrap_err().kind(),
            ErrorKind::RequestInvalid
        );

        let signer = signer.with_identifier("watch+policy/%");
        assert_eq!(
            signer.string_to_sign(),
            concat!(
                "\n\n\n/blob/account/container\nwatch+policy/%\n\n\n2020-12-06\nc\n\n\n",
                "public, max-age=60\nattachment; filename=\"a+b.txt\"\ngzip\nen-US\ntext/plain; charset=utf-8",
            ),
        );
        assert_eq!(
            encode_query_pairs(&signer.token(&provider).unwrap()),
            format!(
                "sv=2020-12-06&sr=c&si=watch%2Bpolicy/%25&{TEST_RESPONSE_OVERRIDE_QUERY}&sig=kV3AFk3S3jacqX5X%2BOUWC2vSz%2BK/b4OzLIWRXPBnP8g%3D"
            ),
        );
    }

    #[test]
    fn signs_the_initial_file_service_version_without_ip_or_protocol_fields() {
        let signer = ServiceSharedAccessSignature::for_target(
            "account".into(),
            "a2V5".into(),
            ServiceSasTarget::File {
                share: "share".into(),
                path: "a b.txt".into(),
            },
            "r".into(),
            Some(timestamp("2022-03-01T08:17:34Z")),
        )
        .with_version("2015-02-21")
        .with_response_overrides(test_response_overrides());
        let provider = reqsign_crypto_rustcrypto::RustCryptoProvider::new();
        assert_eq!(
            signer.string_to_sign(),
            concat!(
                "r\n\n2022-03-01T08:17:34Z\n/file/account/share/a b.txt\n\n2015-02-21\n",
                "public, max-age=60\nattachment; filename=\"a+b.txt\"\ngzip\nen-US\ntext/plain; charset=utf-8",
            ),
        );
        assert_eq!(
            encode_query_pairs(&signer.token(&provider).unwrap()),
            format!(
                "sv=2015-02-21&se=2022-03-01T08%3A17%3A34Z&sp=r&sr=f&{TEST_RESPONSE_OVERRIDE_QUERY}&sig=SusgPhpt82QsC3Y%2BW9n1bEobHcl%2B9UZz/dk5ipRgYKM%3D"
            ),
        );
        assert!(signer.with_protocol("https").token(&provider).is_err());
    }

    #[tokio::test]
    async fn grants_service_specific_sas_vectors() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let selector = "2019-12-15T00:05:33.1234567Z";
        let blob_read = ServiceSasBlobPermissions::READ;
        let file = ServiceSasFilePermissions::READ
            | ServiceSasFilePermissions::CREATE
            | ServiceSasFilePermissions::WRITE
            | ServiceSasFilePermissions::DELETE
            | ServiceSasFilePermissions::LIST;
        let queue = ServiceSasQueuePermissions::READ
            | ServiceSasQueuePermissions::ADD
            | ServiceSasQueuePermissions::UPDATE
            | ServiceSasQueuePermissions::PROCESS;
        let file_suffix = format!(
            "&sr=f&si=watch%2Bpolicy/%25&spr=https&{TEST_RESPONSE_OVERRIDE_QUERY}&sig=Dal68G8cuXq9XasEIE7duUC8p3pfN%2BKbTFWLGPUwaPc%3D"
        );
        // Python HMAC-SHA256 over the Microsoft REST strings for each service.
        for (grant, version, suffix) in [
            (
                ServiceSasGrant::for_blob_snapshot("container", "path/blob", selector, blob_read),
                "2018-11-09",
                "&sp=r&sr=bs&spr=https&sig=i4RBo99HcwSrjp9psMVo3PSFUceOGwY3ZRQpSBqz5vU%3D",
            ),
            (
                ServiceSasGrant::for_blob_version(
                    "container",
                    "path/blob",
                    selector,
                    blob_read | ServiceSasBlobPermissions::DELETE_VERSION,
                ),
                "2019-12-12",
                "&sp=rx&sr=bv&spr=https&sig=j6ynhyKuubettPiH4kMWoT4JqEfKnkwY/rt7ilnr30E%3D",
            ),
            (
                ServiceSasGrant::for_directory(
                    "container",
                    "nested/dir",
                    ServiceSasContainerPermissions::LIST | ServiceSasContainerPermissions::READ,
                ),
                "2020-02-10",
                "&sp=rl&sr=d&sdd=2&spr=https&sig=yAjYRLDFORIGtyaDT9/GKN3fBQUz%2BCxq635gadmjmwY%3D",
            ),
            (
                ServiceSasGrant::for_file_share("share", file),
                "2015-04-05",
                "&sp=rcwdl&sr=s&spr=https&sig=co114dFgUyQYBTdnIuLEXcyQO/S4tLupCbWHmgrYD1o%3D",
            ),
            (
                ServiceSasGrant::for_file(
                    "share",
                    "nested/a b.txt",
                    ServiceSasFilePermissions::default(),
                )
                .with_identifier("watch+policy/%")
                .with_response_overrides(test_response_overrides()),
                "2020-12-06",
                &file_suffix,
            ),
            (
                ServiceSasGrant::for_queue("jobs", queue),
                "2020-12-06",
                "&sp=raup&spr=https&sig=RDSWTr9U3ujGA0DneJUTxU6wOoV3%2BcCIfiCC1foqsBY%3D",
            ),
        ] {
            let version = ServiceSasVersion::new(version).unwrap();
            let config = ServiceSasConfig::new("account").with_version(version.clone());
            let granter = Granter::new(
                crate::test_context(),
                StaticCredentialProvider::new_shared_key(
                    "account",
                    &hash::base64_encode(VALID_ACCOUNT_KEY.as_bytes()),
                ),
                ServiceSasGranter::new(config, grant).with_time(now),
            );
            let granted = granter.grant(Some(Duration::from_secs(300))).await.unwrap();
            let (token, expires_at) = output_parts(&granted);
            assert_eq!(expires_at, timestamp("2030-01-01T00:05:00Z"));
            assert_eq!(
                token,
                format!(
                    "sv={}&se=2030-01-01T00%3A05%3A00Z{suffix}",
                    version.as_str()
                )
            );
        }
    }

    #[tokio::test]
    async fn grants_typed_container_permissions_and_encodes_signature() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_container(
                "container",
                ServiceSasContainerPermissions::LIST | ServiceSasContainerPermissions::READ,
            ),
        )
        .with_time(now);

        let output = operation
            .grant_credential(
                &crate::test_context(),
                &shared_key("account", VALID_ACCOUNT_KEY),
                Some(Duration::from_secs(60)),
            )
            .await
            .expect("container Service SAS grant must succeed");
        let (token, expires_at) = output_parts(&output);

        assert_eq!(expires_at, timestamp("2030-01-01T00:01:00Z"));
        assert_eq!(
            token,
            "sv=2020-12-06&se=2030-01-01T00%3A01%3A00Z&sp=rl&sr=c&spr=https&sig=BInNJ1Os6PeLCwLFrQzDgvuM0ZGsYFuIzWyD/%2BzONkk%3D"
        );
    }

    #[tokio::test]
    async fn rejects_source_variants_account_mismatch_and_invalid_key() {
        let now = timestamp("2030-01-01T00:00:00Z");
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);

        let invalid_sources = [
            Credential::with_bearer_token("bearer-secret", None),
            Credential::with_sas_token("sv=secret&sig=sas-secret"),
            shared_key("differentaccount", VALID_ACCOUNT_KEY),
            Credential::with_shared_key("account", "invalid-key-secret%%%"),
            Credential::with_shared_key("account", &hash::base64_encode(b"short-key")),
            Credential::with_shared_key("account", ""),
        ];
        for source in invalid_sources {
            let err = operation
                .grant_credential(
                    &crate::test_context(),
                    &source,
                    Some(Duration::from_secs(60)),
                )
                .await
                .expect_err("invalid source must fail");
            assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
            let debug = format!("{err:?}");
            for secret in [
                "bearer-secret",
                "sas-secret",
                "differentaccount",
                VALID_ACCOUNT_KEY,
                "invalid-key-secret",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn validates_lifetime_deadline_and_post_generation_usability() {
        let now = timestamp("2030-01-01T00:00:00.500Z");
        let source = shared_key("account", VALID_ACCOUNT_KEY);
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);

        assert_eq!(operation.required_valid_until(&source, None), now);
        for lifetime in [
            None,
            Some(Duration::ZERO),
            Some(Duration::from_millis(400)),
            Some(Duration::from_secs(u64::MAX)),
        ] {
            let err = operation
                .grant_credential(&crate::test_context(), &source, lifetime)
                .await
                .expect_err("invalid lifetime must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        let start_after_expiry = ServiceSasGranter::new(
            ServiceSasConfig::new("account").with_start(timestamp("2030-01-01T00:01:01Z")),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);
        assert_eq!(
            start_after_expiry
                .grant_credential(
                    &crate::test_context(),
                    &source,
                    Some(Duration::from_secs(60)),
                )
                .await
                .expect_err("start at or after expiry must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );

        let future_start = ServiceSasGranter::new(
            ServiceSasConfig::new("account").with_start(timestamp("2030-01-01T00:00:01Z")),
            ServiceSasGrant::for_blob("container", "blob", ServiceSasBlobPermissions::READ),
        )
        .with_time(now);
        assert_eq!(
            future_start
                .grant_credential(
                    &crate::test_context(),
                    &source,
                    Some(Duration::from_secs(60)),
                )
                .await
                .expect_err("future start must fail the immediate usability contract")
                .kind(),
            ErrorKind::RequestInvalid
        );

        let expired_after_generation =
            operation.with_time_after_generation(timestamp("2030-01-01T00:05:00Z"));
        assert_eq!(
            expired_after_generation
                .grant_credential(
                    &crate::test_context(),
                    &source,
                    Some(Duration::from_secs(300)),
                )
                .await
                .expect_err("expired post-generation output must fail")
                .kind(),
            ErrorKind::RequestInvalid
        );
    }

    #[tokio::test]
    async fn core_granter_output_matches_presign_and_is_consumed_by_signer() {
        let now = Timestamp::now();
        let key = hash::base64_encode(VALID_ACCOUNT_KEY.as_bytes());
        let source = Credential::with_shared_key("account", &key);
        let operation = ServiceSasGranter::new(
            ServiceSasConfig::new("account"),
            ServiceSasGrant::for_blob(
                "container",
                "path/to/blob.txt",
                ServiceSasBlobPermissions::READ,
            ),
        )
        .with_time(now);
        let output = Granter::new(
            crate::test_context(),
            StaticCredentialProvider::new_shared_key("account", &key),
            operation,
        )
        .grant(Some(Duration::from_secs(300)))
        .await
        .expect("core granter must return a usable SAS credential");
        let (token, expires_at) = output_parts(&output);
        let token = token.to_string();

        let signer = Signer::new(
            crate::test_context(),
            StaticCredentialProvider::new_sas_token_expires_at(&token, expires_at),
            RequestSigner::new(),
        );
        let mut parts = http::Request::get(
            "https://account.blob.core.windows.net/container/path/to/blob.txt?existing=%2F",
        )
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
        signer
            .sign(&mut parts, None)
            .await
            .expect("existing signer must consume granted credential");
        assert_eq!(
            parts.uri.to_string(),
            format!(
                "https://account.blob.core.windows.net/container/path/to/blob.txt?existing=%2F&{token}"
            )
        );
        assert!(!parts.headers.contains_key(http::header::AUTHORIZATION));

        let mut presigned =
            http::Request::get("https://account.blob.core.windows.net/container/path/to/blob.txt")
                .body(())
                .expect("request must build")
                .into_parts()
                .0;
        RequestSigner::new()
            .with_time(now)
            .with_service_sas_permissions("r")
            .with_service_sas_protocol("https")
            .sign_request(
                &crate::test_context(),
                &mut presigned,
                Some(&source),
                Some(Duration::from_secs(300)),
            )
            .await
            .expect("compatibility presign must succeed");
        assert_eq!(
            presigned.uri.to_string(),
            format!("https://account.blob.core.windows.net/container/path/to/blob.txt?{token}")
        );
    }

    #[tokio::test]
    async fn debug_and_errors_redact_grant_and_credential_material() {
        let ip = SasIpRange::address(Ipv4Addr::new(198, 51, 100, 77));
        let config = ServiceSasConfig::new("sensitiveaccount").with_ip(ip);
        let grant = ServiceSasGrant::for_blob(
            "sensitive-container",
            "sensitive/path/blob.txt",
            ServiceSasBlobPermissions::READ | ServiceSasBlobPermissions::WRITE,
        );
        let operation = ServiceSasGranter::new(config.clone(), grant.clone());
        let resource = ServiceSasResource::Blob {
            container: "sensitive-container".to_string(),
            blob: "sensitive/path/blob.txt".to_string(),
        };
        let source = Credential::with_shared_key("sensitiveaccount", "raw-account-key-secret");
        let sas = Credential::with_sas_token("sv=2020-12-06&sig=raw-sas-token-secret");

        for (debug, secret) in [
            (format!("{config:?}"), "sensitiveaccount"),
            (format!("{grant:?}"), "sensitive-container"),
            (format!("{resource:?}"), "sensitive/path"),
            (format!("{ip:?}"), "198.51.100.77"),
            (format!("{operation:?}"), "sensitiveaccount"),
            (format!("{source:?}"), "raw-account-key-secret"),
            (format!("{sas:?}"), "raw-sas-token-secret"),
        ] {
            assert!(!debug.contains(secret));
        }
        let credential_debug = format!("{source:?}\n{sas:?}");
        for fragment in ["raw", "ret", "sv=", "sig="] {
            assert!(!credential_debug.contains(fragment));
        }

        let err = operation
            .grant_credential(
                &crate::test_context(),
                &source,
                Some(Duration::from_secs(60)),
            )
            .await
            .expect_err("invalid key must fail without disclosure");
        let debug = format!("{err:?}");
        assert!(!debug.contains("raw-account-key-secret"));
        assert!(!debug.contains("sensitiveaccount"));
        assert!(!debug.contains("sensitive-container"));
        assert!(!debug.contains("sensitive/path"));
    }
}
