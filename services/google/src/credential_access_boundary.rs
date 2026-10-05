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

use std::fmt::{self, Debug};
use std::net::Ipv4Addr;
use std::ops::{BitOr, BitOrAssign};

use reqsign_core::{Error, Result};
use serde::Serialize;

mod server_side;
pub use server_side::ServerSideCredentialAccessBoundaryGranter;

mod sts;

#[cfg(feature = "credential-access-boundary-client-side")]
mod client_side;
#[cfg(feature = "credential-access-boundary-client-side")]
pub use client_side::ClientSideCredentialAccessBoundaryGranter;

const MAX_ACCESS_BOUNDARY_RULES: usize = 10;
const MAX_ACCESS_BOUNDARY_CHARACTERS: usize = 2048;
const MAX_CONDITION_CHARACTERS: usize = 2048;
const MAX_OPTIONS_CHARACTERS: usize = 4 * 1024 * 1024;

const OBJECT_VIEWER_ROLE: u8 = 1 << 0;
const OBJECT_CREATOR_ROLE: u8 = 1 << 1;
const OBJECT_USER_ROLE: u8 = 1 << 2;
const OBJECT_ADMIN_ROLE: u8 = 1 << 3;
const ALL_ROLES: u8 =
    OBJECT_VIEWER_ROLE | OBJECT_CREATOR_ROLE | OBJECT_USER_ROLE | OBJECT_ADMIN_ROLE;

/// Typed Google Cloud Storage roles supported by Credential Access Boundaries.
///
/// The CAB schema names the field `availablePermissions`, but it does not accept
/// individual `storage.objects.*` permission names. It accepts IAM role
/// identifiers prefixed with `inRole:`. These constants deliberately expose only
/// the well-known predefined Cloud Storage object roles, preventing callers from
/// supplying arbitrary roles through this convenience API. Use
/// [`CredentialAccessBoundaryRule::new`] for caller-selected IAM roles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CredentialAccessBoundaryPermissions(u8);

impl CredentialAccessBoundaryPermissions {
    /// The predefined Storage Object Viewer role.
    pub const OBJECT_VIEWER: Self = Self(OBJECT_VIEWER_ROLE);
    /// The predefined Storage Object Creator role.
    pub const OBJECT_CREATOR: Self = Self(OBJECT_CREATOR_ROLE);
    /// The predefined Storage Object User role.
    pub const OBJECT_USER: Self = Self(OBJECT_USER_ROLE);
    /// The predefined Storage Object Admin role.
    pub const OBJECT_ADMIN: Self = Self(OBJECT_ADMIN_ROLE);

    /// Return whether no role is selected.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return whether all roles in `other` are selected.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn roles(self) -> Result<Vec<&'static str>> {
        if self.is_empty() || self.0 & !ALL_ROLES != 0 {
            return Err(Error::request_invalid(
                "credential access boundary permissions must contain supported roles",
            ));
        }

        let mut roles = Vec::with_capacity(self.0.count_ones() as usize);
        if self.contains(Self::OBJECT_VIEWER) {
            roles.push("inRole:roles/storage.objectViewer");
        }
        if self.contains(Self::OBJECT_CREATOR) {
            roles.push("inRole:roles/storage.objectCreator");
        }
        if self.contains(Self::OBJECT_USER) {
            roles.push("inRole:roles/storage.objectUser");
        }
        if self.contains(Self::OBJECT_ADMIN) {
            roles.push("inRole:roles/storage.objectAdmin");
        }
        Ok(roles)
    }
}

impl Debug for CredentialAccessBoundaryPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialAccessBoundaryPermissions(REDACTED)")
    }
}

impl BitOr for CredentialAccessBoundaryPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CredentialAccessBoundaryPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A caller-defined Cloud Storage Credential Access Boundary rule.
///
/// The caller owns the authorization policy, including any changes to custom
/// roles. Reqsign checks bucket names, role identifier structure, non-empty
/// conditions, and size/rule limits before granting. Google validates role
/// existence, permissions, and CEL syntax and semantics.
///
/// Use [`CredentialAccessBoundaryGrant::new`] and
/// [`CredentialAccessBoundaryGrant::with_rule`] to combine explicit rules with
/// the existing typed convenience constructors. Rules are evaluated as a union.
#[derive(Clone)]
pub struct CredentialAccessBoundaryRule {
    bucket: String,
    permissions: RulePermissions,
    condition: Option<RuleCondition>,
}

#[derive(Clone)]
enum RulePermissions {
    Typed(CredentialAccessBoundaryPermissions),
    Explicit(Vec<String>),
}

#[derive(Clone)]
enum RuleCondition {
    ObjectPrefix(String),
    Expression(String),
}

impl Debug for CredentialAccessBoundaryRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialAccessBoundaryRule")
            .finish_non_exhaustive()
    }
}

impl CredentialAccessBoundaryRule {
    /// Create a bucket-wide rule with caller-selected IAM role identifiers.
    ///
    /// Each role must include `inRole:` followed by `roles/ROLE`,
    /// `projects/PROJECT/roles/ROLE`, or `organizations/ORGANIZATION/roles/ROLE`.
    /// Individual permission names are not accepted. Role order and spelling
    /// are preserved; no roles are added or substituted.
    /// Validation is deferred until the grant is used, as with typed grants.
    pub fn new(
        bucket: impl Into<String>,
        roles: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            permissions: RulePermissions::Explicit(roles.into_iter().map(Into::into).collect()),
            condition: None,
        }
    }

    /// Set a caller-authored CEL availability condition, preserved verbatim.
    ///
    /// The caller must escape literals and choose the intended authorization
    /// semantics. Reqsign checks only that the expression is non-empty and
    /// within the size limit; it does not parse or evaluate arbitrary CEL.
    /// `objectListPrefix` conditions authorize list requests, not individual
    /// results within a listing.
    ///
    /// Explicit expressions require [`ServerSideCredentialAccessBoundaryGranter`].
    /// The client-side granter cannot compile arbitrary CEL and rejects these
    /// rules before I/O rather than omitting their conditions.
    pub fn with_condition(mut self, expression: impl Into<String>) -> Self {
        self.condition = Some(RuleCondition::Expression(expression.into()));
        self
    }
}

/// A bound Google Cloud Storage Credential Access Boundary.
///
/// Use [`CredentialAccessBoundaryGrant::for_bucket`] for bucket-wide access or
/// [`CredentialAccessBoundaryGrant::for_object_prefix`] for a non-empty object
/// prefix. Prefix grants generate the CEL expression internally, including the
/// `objectListPrefix` check that authorizes list requests. Bucket and
/// prefix values are never normalized.
///
/// Use [`CredentialAccessBoundaryGrant::new`] with an explicit
/// [`CredentialAccessBoundaryRule`] for other roles or conditions. For example,
/// this policy accepts the exact list prefix `table` while restricting object
/// access to `table/` (excluding sibling object prefixes such as `table-other/`):
///
/// ```
/// use reqsign_google::{CredentialAccessBoundaryGrant, CredentialAccessBoundaryRule};
///
/// let condition = "resource.name.startsWith('projects/_/buckets/example-bucket/objects/table/') || \
///     api.getAttribute('storage.googleapis.com/objectListPrefix', '') == 'table' || \
///     api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('table/')";
/// let grant = CredentialAccessBoundaryGrant::new(
///     CredentialAccessBoundaryRule::new("example-bucket", [
///         "inRole:roles/storage.legacyObjectReader",
///         "inRole:roles/storage.objectViewer",
///     ]).with_condition(condition),
/// );
/// ```
///
/// Additional rules can be added explicitly. Google evaluates CAB rules as a
/// union and allows at most ten rules.
#[derive(Clone)]
pub struct CredentialAccessBoundaryGrant {
    rules: Vec<CredentialAccessBoundaryRule>,
}

impl Debug for CredentialAccessBoundaryGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialAccessBoundaryGrant")
            .field("rules", &"REDACTED")
            .finish()
    }
}

impl CredentialAccessBoundaryGrant {
    /// Create a Credential Access Boundary from a caller-defined rule.
    pub fn new(rule: CredentialAccessBoundaryRule) -> Self {
        Self { rules: vec![rule] }
    }

    /// Add a caller-defined rule. All rules are evaluated as a union.
    pub fn with_rule(mut self, rule: CredentialAccessBoundaryRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Create a bucket-wide Credential Access Boundary.
    pub fn for_bucket(
        bucket: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        Self {
            rules: vec![CredentialAccessBoundaryRule {
                bucket: bucket.into(),
                condition: None,
                permissions: RulePermissions::Typed(permissions),
            }],
        }
    }

    /// Create a Credential Access Boundary for a non-empty object prefix.
    ///
    /// Prefix matching preserves the exact Unicode string. For directory-like
    /// semantics, include the trailing `/` explicitly.
    pub fn for_object_prefix(
        bucket: impl Into<String>,
        object_prefix: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        Self {
            rules: vec![CredentialAccessBoundaryRule {
                bucket: bucket.into(),
                condition: Some(RuleCondition::ObjectPrefix(object_prefix.into())),
                permissions: RulePermissions::Typed(permissions),
            }],
        }
    }

    /// Add another bucket-wide rule.
    ///
    /// All rules are evaluated as a union.
    pub fn with_bucket_rule(
        mut self,
        bucket: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        self.rules.push(CredentialAccessBoundaryRule {
            bucket: bucket.into(),
            condition: None,
            permissions: RulePermissions::Typed(permissions),
        });
        self
    }

    /// Add another non-empty object-prefix rule.
    ///
    /// All rules are evaluated as a union.
    pub fn with_object_prefix_rule(
        mut self,
        bucket: impl Into<String>,
        object_prefix: impl Into<String>,
        permissions: CredentialAccessBoundaryPermissions,
    ) -> Self {
        self.rules.push(CredentialAccessBoundaryRule {
            bucket: bucket.into(),
            condition: Some(RuleCondition::ObjectPrefix(object_prefix.into())),
            permissions: RulePermissions::Typed(permissions),
        });
        self
    }

    fn access_boundary(&self) -> Result<AccessBoundary> {
        if self.rules.is_empty() || self.rules.len() > MAX_ACCESS_BOUNDARY_RULES {
            return Err(Error::request_invalid(
                "credential access boundary must contain between one and ten rules",
            ));
        }

        let rules = self
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                rule.to_wire()
                    .map_err(|err| err.with_context(format!("rule_index: {index}")))
            })
            .collect::<Result<Vec<_>>>()?;

        let access_boundary = AccessBoundary {
            access_boundary_rules: rules,
        };
        let access_boundary_json = serde_json::to_string(&access_boundary).map_err(|err| {
            Error::unexpected("failed to serialize credential access boundary").with_source(err)
        })?;
        if access_boundary_json.chars().count() > MAX_ACCESS_BOUNDARY_CHARACTERS {
            return Err(Error::request_invalid(
                "credential access boundary exceeds the size limit",
            ));
        }
        Ok(access_boundary)
    }

    #[cfg(any(feature = "credential-access-boundary-client-side", test))]
    fn validate(&self) -> Result<()> {
        self.access_boundary().map(drop)
    }

    fn options_json(&self) -> Result<String> {
        let access_boundary = self.access_boundary()?;
        let json = serde_json::to_string(&StsOptions { access_boundary }).map_err(|err| {
            Error::unexpected("failed to serialize credential access boundary").with_source(err)
        })?;
        if json.chars().count() > MAX_OPTIONS_CHARACTERS {
            return Err(Error::request_invalid(
                "credential access boundary options exceed the STS size limit",
            ));
        }
        Ok(json)
    }
}

impl CredentialAccessBoundaryRule {
    fn to_wire(&self) -> Result<AccessBoundaryRule> {
        validate_bucket_name(&self.bucket)?;
        let available_permissions = match &self.permissions {
            RulePermissions::Typed(permissions) => permissions
                .roles()?
                .into_iter()
                .map(str::to_owned)
                .collect(),
            RulePermissions::Explicit(roles) => {
                if roles.is_empty() {
                    return Err(Error::request_invalid(
                        "credential access boundary roles must not be empty",
                    ));
                }
                for role in roles {
                    validate_role(role)?;
                }
                roles.clone()
            }
        };
        let available_resource = format!(
            "//storage.googleapis.com/projects/_/buckets/{}",
            self.bucket
        );

        let availability_condition = self
            .condition
            .as_ref()
            .map(|condition| match condition {
                RuleCondition::ObjectPrefix(prefix) => build_prefix_condition(&self.bucket, prefix),
                RuleCondition::Expression(expression) => {
                    if expression.trim().is_empty() {
                        return Err(Error::request_invalid(
                            "credential access boundary condition must not be empty",
                        ));
                    }
                    validate_condition_size(expression)?;
                    Ok(AvailabilityCondition {
                        expression: expression.clone(),
                    })
                }
            })
            .transpose()?;

        Ok(AccessBoundaryRule {
            available_resource,
            available_permissions,
            availability_condition,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StsOptions {
    access_boundary: AccessBoundary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessBoundary {
    access_boundary_rules: Vec<AccessBoundaryRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessBoundaryRule {
    available_resource: String,
    available_permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    availability_condition: Option<AvailabilityCondition>,
}

#[derive(Serialize)]
struct AvailabilityCondition {
    expression: String,
}

fn validate_role(role: &str) -> Result<()> {
    let valid = role.strip_prefix("inRole:").is_some_and(|identifier| {
        let parts: Vec<_> = identifier.split('/').collect();
        let valid_shape = matches!(
            parts.as_slice(),
            ["roles", _] | ["projects" | "organizations", _, "roles", _]
        );
        valid_shape
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
    });
    if !valid {
        return Err(Error::request_invalid(
            "credential access boundary role identifier is invalid",
        ));
    }
    Ok(())
}

fn validate_condition_size(expression: &str) -> Result<()> {
    if expression.chars().count() > MAX_CONDITION_CHARACTERS {
        return Err(Error::request_invalid(
            "credential access boundary condition exceeds the size limit",
        ));
    }
    Ok(())
}

fn validate_bucket_name(bucket: &str) -> Result<()> {
    let length = bucket.len();
    let valid_length = if bucket.contains('.') {
        (3..=222).contains(&length)
    } else {
        (3..=63).contains(&length)
    };
    let valid_characters = bucket
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte));
    let starts_and_ends_with_alphanumeric = bucket
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    let valid_components = bucket.split('.').all(|component| {
        !component.is_empty()
            && component.len() <= 63
            && (!bucket.contains('.')
                || (component.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }) && component
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                    && component
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)))
    });
    let reserved =
        bucket.starts_with("goog") || bucket.contains("google") || bucket.contains("g00gle");

    if !valid_length
        || !valid_characters
        || !starts_and_ends_with_alphanumeric
        || !valid_components
        || reserved
        || bucket.parse::<Ipv4Addr>().is_ok()
    {
        return Err(Error::request_invalid(
            "credential access boundary bucket name is invalid",
        ));
    }
    Ok(())
}

fn build_prefix_condition(bucket: &str, prefix: &str) -> Result<AvailabilityCondition> {
    if prefix.is_empty() || prefix.len() > 1024 || prefix.contains('\r') || prefix.contains('\n') {
        return Err(Error::request_invalid(
            "credential access boundary object prefix is invalid",
        ));
    }

    let object_resource_prefix = format!("projects/_/buckets/{bucket}/objects/{prefix}");
    let object_resource_literal =
        serde_json::to_string(&object_resource_prefix).map_err(|err| {
            Error::unexpected("failed to encode object resource prefix").with_source(err)
        })?;
    let list_prefix_literal = serde_json::to_string(prefix)
        .map_err(|err| Error::unexpected("failed to encode object prefix").with_source(err))?;

    let expression = format!(
        "resource.name.startsWith({object_resource_literal}) || \
         api.getAttribute(\"storage.googleapis.com/objectListPrefix\", \"\")\
         .startsWith({list_prefix_literal})"
    );
    validate_condition_size(&expression)?;

    Ok(AvailabilityCondition { expression })
}

#[cfg(test)]
mod tests {
    use reqsign_core::ErrorKind;

    use super::*;

    #[test]
    fn validates_bucket_prefix_permission_and_rule_limits() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_VIEWER;
        let invalid = [
            CredentialAccessBoundaryGrant::for_bucket("ab", permissions),
            CredentialAccessBoundaryGrant::for_bucket("UPPER", permissions),
            CredentialAccessBoundaryGrant::for_bucket("bucket/name", permissions),
            CredentialAccessBoundaryGrant::for_bucket("-bucket", permissions),
            CredentialAccessBoundaryGrant::for_bucket("bucket-", permissions),
            CredentialAccessBoundaryGrant::for_bucket("192.168.0.1", permissions),
            CredentialAccessBoundaryGrant::for_bucket("goog-reserved", permissions),
            CredentialAccessBoundaryGrant::for_bucket("bucket..name", permissions),
            CredentialAccessBoundaryGrant::for_bucket(
                "example-bucket",
                CredentialAccessBoundaryPermissions(0),
            ),
            CredentialAccessBoundaryGrant::for_object_prefix("example-bucket", "", permissions),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "line\nbreak",
                permissions,
            ),
            CredentialAccessBoundaryGrant::for_object_prefix(
                "example-bucket",
                "x".repeat(1025),
                permissions,
            ),
        ];
        for grant in invalid {
            let err = grant.validate().expect_err("invalid grant must fail");
            assert_eq!(err.kind(), ErrorKind::RequestInvalid);
        }

        let mut maximum = CredentialAccessBoundaryGrant::for_bucket("bucket-0", permissions);
        for index in 1..MAX_ACCESS_BOUNDARY_RULES {
            maximum = maximum.with_bucket_rule(format!("bucket-{index}"), permissions);
        }
        maximum
            .validate()
            .expect("ten valid rules must be accepted");

        let too_many = maximum.with_bucket_rule("bucket-10", permissions);
        let err = too_many
            .validate()
            .expect_err("more than ten rules must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    }

    #[test]
    fn serializes_typed_roles_and_escapes_prefix_without_widening() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_ADMIN
            | CredentialAccessBoundaryPermissions::OBJECT_VIEWER
            | CredentialAccessBoundaryPermissions::OBJECT_CREATOR;
        let bucket_json = CredentialAccessBoundaryGrant::for_bucket("bucket_123", permissions)
            .options_json()
            .expect("bucket grant must serialize");
        let bucket: serde_json::Value =
            serde_json::from_str(&bucket_json).expect("options must be JSON");
        let rule = &bucket["accessBoundary"]["accessBoundaryRules"][0];
        assert_eq!(
            rule["availableResource"],
            "//storage.googleapis.com/projects/_/buckets/bucket_123"
        );
        assert_eq!(
            rule["availablePermissions"],
            serde_json::json!([
                "inRole:roles/storage.objectViewer",
                "inRole:roles/storage.objectCreator",
                "inRole:roles/storage.objectAdmin"
            ])
        );
        assert!(rule.get("availabilityCondition").is_none());

        let prefix = r#"tenant/") || true || (""#;
        let prefix_json = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            prefix,
            CredentialAccessBoundaryPermissions::OBJECT_USER,
        )
        .options_json()
        .expect("prefix grant must serialize");
        let prefix_value: serde_json::Value =
            serde_json::from_str(&prefix_json).expect("options must be JSON");
        assert_eq!(
            prefix_value["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"],
            r#"resource.name.startsWith("projects/_/buckets/example-bucket/objects/tenant/\") || true || (\"") || api.getAttribute("storage.googleapis.com/objectListPrefix", "").startsWith("tenant/\") || true || (\"")"#
        );
    }

    #[test]
    fn preserves_prefix_semantics_without_normalization() {
        let prefix = "/leading//nested/";
        let json = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            prefix,
            CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
        )
        .options_json()
        .expect("prefix grant must serialize");
        let options: serde_json::Value = serde_json::from_str(&json).expect("options must be JSON");
        let expression = options["accessBoundary"]["accessBoundaryRules"][0]
            ["availabilityCondition"]["expression"]
            .as_str()
            .expect("condition must be a string");
        assert!(expression.contains("objects//leading//nested/"));
        assert!(expression.ends_with(r#".startsWith("/leading//nested/")"#));
    }

    #[test]
    fn explicit_rules_preserve_expressions_and_redact_debug() {
        let expression = r#"resource.name.endsWith("quote\\\"/雪&suffix")"#;
        let rule = CredentialAccessBoundaryRule::new(
            "sensitive-bucket",
            ["inRole:projects/sensitive-project/roles/custom_role"],
        )
        .with_condition(expression);
        let grant = CredentialAccessBoundaryGrant::new(rule.clone());
        let options: serde_json::Value =
            serde_json::from_str(&grant.options_json().unwrap()).unwrap();
        assert_eq!(
            options["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"],
            expression
        );
        for debug in [format!("{rule:?}"), format!("{grant:?}")] {
            assert!(!debug.contains("sensitive"));
            assert!(!debug.contains(expression));
        }
    }

    #[test]
    fn explicit_rules_retain_rule_and_size_limits() {
        let rule = CredentialAccessBoundaryRule::new(
            "example-bucket",
            ["inRole:roles/storage.objectViewer"],
        );
        let mut grant = CredentialAccessBoundaryGrant::new(rule.clone());
        for _ in 1..MAX_ACCESS_BOUNDARY_RULES {
            grant = grant.with_rule(rule.clone());
        }
        grant
            .validate()
            .expect("ten explicit rules must be accepted");
        assert_eq!(
            grant.with_rule(rule.clone()).validate().unwrap_err().kind(),
            ErrorKind::RequestInvalid
        );

        let empty_expression_size = serde_json::to_string(&AccessBoundary {
            access_boundary_rules: vec![AccessBoundaryRule {
                availability_condition: Some(AvailabilityCondition {
                    expression: String::new(),
                }),
                ..rule.to_wire().unwrap()
            }],
        })
        .unwrap()
        .chars()
        .count();
        let remaining = MAX_ACCESS_BOUNDARY_CHARACTERS - empty_expression_size;
        CredentialAccessBoundaryGrant::new(rule.clone().with_condition("x".repeat(remaining)))
            .validate()
            .expect("explicit boundary at the size limit must be accepted");
        assert_eq!(
            CredentialAccessBoundaryGrant::new(rule.with_condition("x".repeat(remaining + 1)))
                .validate()
                .unwrap_err()
                .kind(),
            ErrorKind::RequestInvalid
        );
    }

    #[test]
    fn enforces_access_boundary_size_limit() {
        let permissions = CredentialAccessBoundaryPermissions::OBJECT_VIEWER;
        CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "x".repeat(772),
            permissions,
        )
        .with_bucket_rule("aaa", permissions)
        .validate()
        .expect("boundary at the documented size limit must be accepted");

        let err = CredentialAccessBoundaryGrant::for_object_prefix(
            "example-bucket",
            "x".repeat(773),
            permissions,
        )
        .with_bucket_rule("aaa", permissions)
        .validate()
        .expect_err("boundary over the documented size limit must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    }
}
