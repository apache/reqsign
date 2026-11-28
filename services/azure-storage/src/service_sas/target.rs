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

use super::{ServiceSasResource, valid_dns_name, validate_blob, validate_container};
use crate::sas_response_overrides::sas_query_value;
use percent_encoding::percent_decode_str;
use reqsign_core::{Error, Result};
use std::fmt::{Debug, Formatter};

pub(super) const BLOB_SNAPSHOT_SAS_VERSION: &str = "2018-11-09";
const BLOB_DIRECTORY_SAS_VERSION: &str = "2020-02-10";

/// How [`crate::RequestSigner`] selects the Service SAS target from a request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceSasMode {
    /// Infer a container, blob, snapshot, or version from the path and query.
    /// A snapshot or version selector on a single resource segment addresses
    /// a blob in the implicit `$root` container.
    #[default]
    Blob,
    /// Use the entire resource path as a Blob Storage directory.
    BlobDirectory,
    /// Infer a share or file from the Azure Files resource path.
    File,
    /// Sign at share scope, including for requests to directories or files in
    /// the share. The SAS grants the selected permissions across the share.
    FileShare,
    /// Use the queue name, including when signing a message operation URI.
    Queue,
}

/// Target of an Azure Storage Service SAS.
///
/// Names, paths, and snapshot and version selectors are percent-decoded. A
/// snapshot or version SAS must be used with the matching `snapshot` or
/// `versionid` operation query parameter on the request URI.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceSasTarget {
    /// A container and its blobs.
    Container { container: String },
    /// One blob.
    Blob { container: String, blob: String },
    /// One blob snapshot, identified by the opaque timestamp returned by Azure.
    BlobSnapshot {
        container: String,
        blob: String,
        snapshot: String,
    },
    /// One blob version, identified by the opaque version ID returned by Azure.
    BlobVersion {
        container: String,
        blob: String,
        version_id: String,
    },
    /// A directory in a hierarchical-namespace account. An empty path denotes
    /// the root directory of the container.
    Directory { container: String, path: String },
    /// A file share and its files.
    FileShare { share: String },
    /// One file. The path is relative to the file share.
    File { share: String, path: String },
    /// A queue and its messages.
    Queue { queue: String },
}

impl Debug for ServiceSasTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSasTarget").finish_non_exhaustive()
    }
}

impl From<ServiceSasResource> for ServiceSasTarget {
    fn from(resource: ServiceSasResource) -> Self {
        match resource {
            ServiceSasResource::Container { container } => Self::Container { container },
            ServiceSasResource::Blob { container, blob } => Self::Blob { container, blob },
        }
    }
}

impl ServiceSasTarget {
    pub(crate) fn from_request(
        mode: ServiceSasMode,
        path: &str,
        query: &[(String, String)],
    ) -> Result<Self> {
        let snapshot = sas_query_value(query, "snapshot")?;
        let version_id = sas_query_value(query, "versionid")?;
        if snapshot.is_some() && version_id.is_some() {
            return Err(Error::request_invalid(
                "Azure Service SAS cannot combine snapshot and version selectors",
            ));
        }
        if let Some(selector) = snapshot.or(version_id) {
            if mode != ServiceSasMode::Blob
                || sas_query_value(query, "restype")?
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("container"))
            {
                return Err(Error::request_invalid(
                    "Azure Service SAS snapshot and version selectors require a blob path",
                ));
            }
            let (first, remainder) = decode_resource_path(path)?;
            // The selector identifies a blob. With one wire segment, Azure
            // resolves it in the implicit $root container.
            let (container, blob) = if !path.is_empty() && !path.contains('/') {
                ("$root".to_owned(), first)
            } else {
                (first, remainder)
            };
            return Ok(if snapshot.is_some() {
                Self::BlobSnapshot {
                    container,
                    blob,
                    snapshot: selector.to_owned(),
                }
            } else {
                Self::BlobVersion {
                    container,
                    blob,
                    version_id: selector.to_owned(),
                }
            });
        }

        Ok(match mode {
            ServiceSasMode::Blob => ServiceSasResource::from_uri_resource_path(path)?.into(),
            ServiceSasMode::BlobDirectory => {
                let (container, path) = decode_resource_path(path)?;
                Self::Directory { container, path }
            }
            ServiceSasMode::File | ServiceSasMode::FileShare => {
                let (share, path) = decode_resource_path(path)?;
                if mode == ServiceSasMode::FileShare || path.is_empty() {
                    Self::FileShare { share }
                } else {
                    Self::File { share, path }
                }
            }
            ServiceSasMode::Queue => {
                let (queue, path) = decode_resource_path(path)?;
                if !matches!(path.as_str(), "" | "messages")
                    && !path.strip_prefix("messages/").is_some_and(valid_segment)
                {
                    return Err(Error::request_invalid(
                        "Azure Queue Service SAS requires a queue or queue message path",
                    ));
                }
                Self::Queue { queue }
            }
        })
    }

    pub(super) fn canonicalized_resource(&self, account: &str) -> String {
        match self {
            Self::Container { container } => format!("/blob/{account}/{container}"),
            Self::Blob { container, blob }
            | Self::BlobSnapshot {
                container, blob, ..
            }
            | Self::BlobVersion {
                container, blob, ..
            } => format!("/blob/{account}/{container}/{blob}"),
            Self::Directory { container, path } => format!("/blob/{account}/{container}/{path}"),
            Self::FileShare { share } => format!("/file/{account}/{share}"),
            Self::File { share, path } => format!("/file/{account}/{share}/{path}"),
            Self::Queue { queue } => format!("/queue/{account}/{queue}"),
        }
    }

    pub(super) fn signed_resource(&self) -> Option<&'static str> {
        Some(match self {
            Self::Container { .. } => "c",
            Self::Blob { .. } => "b",
            Self::BlobSnapshot { .. } => "bs",
            Self::BlobVersion { .. } => "bv",
            Self::Directory { .. } => "d",
            Self::FileShare { .. } => "s",
            Self::File { .. } => "f",
            Self::Queue { .. } => return None,
        })
    }

    pub(super) fn is_blob_storage(&self) -> bool {
        !matches!(
            self,
            Self::FileShare { .. } | Self::File { .. } | Self::Queue { .. }
        )
    }

    pub(super) fn signed_timestamp(&self) -> &str {
        match self {
            Self::BlobSnapshot { snapshot, .. } => snapshot,
            Self::BlobVersion { version_id, .. } => version_id,
            _ => "",
        }
    }

    pub(super) fn directory_depth(&self) -> Option<usize> {
        match self {
            Self::Directory { path, .. } if path.is_empty() => Some(0),
            Self::Directory { path, .. } => {
                Some(path.strip_suffix('/').unwrap_or(path).split('/').count())
            }
            _ => None,
        }
    }

    pub(super) fn validate(&self, version: &str, permissions: &str) -> Result<()> {
        let permission_order = match self {
            Self::BlobSnapshot {
                container, blob, ..
            }
            | Self::BlobVersion {
                container, blob, ..
            } => {
                validate_container(container)?;
                validate_blob(blob)?;
                if container == "$root" && blob.contains('/') {
                    return Err(Error::request_invalid(
                        "Azure root container blob names must not contain slashes",
                    ));
                }
                if version < BLOB_SNAPSHOT_SAS_VERSION {
                    return Err(Error::request_invalid(
                        "Azure Service SAS snapshots and versions require version 2018-11-09 or later",
                    ));
                }
                if self.signed_timestamp().is_empty()
                    || self.signed_timestamp().chars().any(char::is_control)
                {
                    return Err(Error::request_invalid(
                        "invalid Azure blob snapshot or version selector",
                    ));
                }
                if matches!(self, Self::BlobSnapshot { .. }) {
                    "rwdyi"
                } else {
                    "rxyi"
                }
            }
            Self::Directory { container, path } => {
                validate_container(container)?;
                if version < BLOB_DIRECTORY_SAS_VERSION {
                    return Err(Error::request_invalid(
                        "Azure Service SAS directory scope requires version 2020-02-10 or later",
                    ));
                }
                let directory = path.strip_suffix('/').unwrap_or(path);
                if !path.is_empty()
                    && (directory.chars().count() > 1024
                        || !directory.split('/').all(valid_segment)
                        || self.directory_depth().is_some_and(|depth| depth > 61))
                {
                    return Err(Error::request_invalid(
                        "invalid Azure Service SAS directory path",
                    ));
                }
                "racwdlmeop"
            }
            Self::FileShare { share } | Self::File { share, .. } => {
                if !valid_dns_name(share) {
                    return Err(Error::request_invalid("invalid Azure file share name"));
                }
                if let Self::File { path, .. } = self {
                    if path.chars().count() > 2048
                        || !path
                            .split('/')
                            .all(|segment| valid_segment(segment) && segment.chars().count() <= 255)
                    {
                        return Err(Error::request_invalid(
                            "invalid Azure Service SAS file path",
                        ));
                    }
                    "rcwd"
                } else {
                    "rcwdl"
                }
            }
            Self::Queue { queue } => {
                if !valid_dns_name(queue) {
                    return Err(Error::request_invalid("invalid Azure queue name"));
                }
                "raup"
            }
            // Preserve the existing low-level and URI-based Blob and Container
            // contracts. The typed grant validates their resource names.
            Self::Container { .. } | Self::Blob { .. } => return Ok(()),
        };
        let mut remaining = permission_order;
        for permission in permissions.chars() {
            remaining = remaining
                .split_once(permission)
                .map(|(_, rest)| rest)
                .ok_or_else(|| {
                    Error::request_invalid(
                        "invalid permission or permission order for this Azure Service SAS target",
                    )
                })?;
        }
        Ok(())
    }
}

fn decode_resource_path(path: &str) -> Result<(String, String)> {
    let (root, child) = path.split_once('/').unwrap_or((path, ""));
    let decode = |value: &str| {
        percent_decode_str(value)
            .decode_utf8()
            .map(|decoded| decoded.into_owned())
            .map_err(|_| Error::request_invalid("Azure SAS resource path must decode to UTF-8"))
    };
    Ok((decode(root)?, decode(child)?))
}

fn valid_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | "..") && !segment.chars().any(|ch| ch.is_control() || ch == '\\')
}
