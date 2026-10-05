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

use std::collections::BTreeMap;
use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use reqsign_core::{Context, ErrorKind, Granter, HttpSend, Result, time::Timestamp};
use reqsign_google::{
    CredentialAccessBoundaryGrant, CredentialAccessBoundaryPermissions,
    CredentialAccessBoundaryRule, ServerSideCredentialAccessBoundaryGranter,
    TokenCredentialProvider,
};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct MockSts(Arc<Mutex<Vec<http::Request<Bytes>>>>);

impl Debug for MockSts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockSts").finish_non_exhaustive()
    }
}

impl HttpSend for MockSts {
    async fn http_send(&self, request: http::Request<Bytes>) -> Result<http::Response<Bytes>> {
        self.0.lock().unwrap().push(request);
        Ok(http::Response::new(Bytes::from_static(
            br#"{
            "access_token": "downscoped-token",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#,
        )))
    }
}

fn source(expires_at: Timestamp) -> TokenCredentialProvider {
    TokenCredentialProvider::new("source+token&options=other").with_expires_at(expires_at)
}

const CONDITION: &str = "resource.name.startsWith('projects/_/buckets/example-bucket/objects/table/') ||\n\
api.getAttribute('storage.googleapis.com/objectListPrefix', '') == 'table' ||\n\
api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('table/')";

#[tokio::test]
async fn exchanges_caller_policy_without_changing_roles_or_prefixes() -> Result<()> {
    let http = MockSts::default();
    let expires_at = Timestamp::now() + Duration::from_secs(600);
    // These mappings belong to the caller, including overwrite and delete via
    // legacyBucketWriter. The library must not substitute objectCreator alone
    // or broaden the write policy to objectAdmin.
    let roles = [
        vec![
            "inRole:roles/storage.legacyObjectReader",
            "inRole:roles/storage.objectViewer",
        ],
        vec![
            "inRole:roles/storage.legacyBucketWriter",
            "inRole:roles/storage.objectCreator",
        ],
        vec!["inRole:roles/storage.objectAdmin"],
    ];
    let mut grant = CredentialAccessBoundaryGrant::new(
        CredentialAccessBoundaryRule::new("example-bucket", roles[0].clone())
            .with_condition(CONDITION),
    );
    for count in 1..=roles.len() {
        if count > 1 {
            grant = grant.with_rule(
                CredentialAccessBoundaryRule::new("example-bucket", roles[count - 1].clone())
                    .with_condition(CONDITION),
            );
        }
        let output = Granter::new(
            Context::new().with_http_send(http.clone()),
            source(expires_at),
            ServerSideCredentialAccessBoundaryGranter::new(grant.clone()),
        )
        .grant(None)
        .await?;
        let token = output.token.unwrap();
        assert_eq!(token.access_token, "downscoped-token");
        // The returned token may never outlive its source.
        assert_eq!(token.expires_at, Some(expires_at));

        let requests = http.0.lock().unwrap();
        assert_eq!(requests.len(), count);
        let request = &requests[count - 1];
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://sts.googleapis.com/v1/token");
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        let fields: BTreeMap<_, _> = form_urlencoded::parse(request.body())
            .into_owned()
            .collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(
            fields["grant_type"],
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(
            fields["requested_token_type"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(
            fields["subject_token_type"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(fields["subject_token"], "source+token&options=other");
        let options: Value = serde_json::from_str(&fields["options"]).unwrap();
        let expected: Vec<_> = roles[..count].iter().map(|roles| json!({
            "availableResource": "//storage.googleapis.com/projects/_/buckets/example-bucket",
            "availablePermissions": roles,
            "availabilityCondition": {"expression": CONDITION},
        })).collect();
        assert_eq!(
            options,
            json!({"accessBoundary": {"accessBoundaryRules": expected}})
        );
        // The exact list prefix must survive alongside a distinct object prefix.
        let expression = options["accessBoundary"]["accessBoundaryRules"][0]
            ["availabilityCondition"]["expression"].as_str().unwrap();
        assert!(expression.contains("objects/table/')"));
        assert!(expression.contains("== 'table'"));
        assert!(expression.contains(".startsWith('table/')"));
        assert!(!expression.contains("objects/table')"));
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_explicit_rules_before_sts_io() {
    let valid = || {
        CredentialAccessBoundaryRule::new("example-bucket", ["inRole:roles/storage.objectViewer"])
    };
    let mut invalid = vec![
        CredentialAccessBoundaryGrant::new(CredentialAccessBoundaryRule::new(
            "bad/bucket",
            ["inRole:roles/storage.objectViewer"],
        )),
        CredentialAccessBoundaryGrant::new(CredentialAccessBoundaryRule::new(
            "example-bucket",
            Vec::<String>::new(),
        )),
        CredentialAccessBoundaryGrant::new(valid().with_condition(" \n\t")),
        CredentialAccessBoundaryGrant::new(valid().with_condition("x".repeat(2049))),
        // The expression itself fits, but the complete boundary exceeds 2048 characters.
        CredentialAccessBoundaryGrant::new(valid().with_condition("x".repeat(2000))),
    ];
    for role in [
        "",
        "roles/storage.objectViewer",
        "storage.objects.get",
        "inRole:storage.objects.get",
        "inRole:roles/",
        "inRole:roles/a/b",
        "inRole:projects//roles/a",
        "inRole:organizations/123/roles/",
        "inRole:roles/storage.objectViewer\n",
        "inRole:roles/a b",
    ] {
        invalid.push(CredentialAccessBoundaryGrant::new(
            CredentialAccessBoundaryRule::new("example-bucket", [role]),
        ));
    }
    let mut too_many = CredentialAccessBoundaryGrant::new(valid());
    for _ in 0..10 {
        too_many = too_many.with_rule(valid());
    }
    invalid.push(too_many);
    let http = MockSts::default();
    for grant in invalid {
        let err = Granter::new(
            Context::new().with_http_send(http.clone()),
            source(Timestamp::now() + Duration::from_secs(600)),
            ServerSideCredentialAccessBoundaryGranter::new(grant),
        )
        .grant(None)
        .await
        .expect_err("invalid explicit policy must fail");
        assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    }
    assert!(http.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn combines_custom_roles_and_typed_rules_without_normalization() -> Result<()> {
    let http = MockSts::default();
    let roles = [
        "inRole:projects/example-project/roles/custom_role",
        "inRole:organizations/123/roles/customRole",
    ];
    let grant = CredentialAccessBoundaryGrant::for_object_prefix(
        "example-bucket",
        "table/",
        CredentialAccessBoundaryPermissions::OBJECT_VIEWER,
    )
    .with_rule(CredentialAccessBoundaryRule::new("example-bucket", roles));
    Granter::new(
        Context::new().with_http_send(http.clone()),
        source(Timestamp::now() + Duration::from_secs(600)),
        ServerSideCredentialAccessBoundaryGranter::new(grant),
    )
    .grant(None)
    .await?;
    let requests = http.0.lock().unwrap();
    let fields: BTreeMap<_, _> = form_urlencoded::parse(requests[0].body())
        .into_owned()
        .collect();
    let options: Value = serde_json::from_str(&fields["options"]).unwrap();
    let rules = &options["accessBoundary"]["accessBoundaryRules"];
    assert_eq!(rules[1]["availablePermissions"], json!(roles));
    assert!(rules[1].get("availabilityCondition").is_none());
    assert_eq!(
        rules[0]["availabilityCondition"]["expression"],
        r#"resource.name.startsWith("projects/_/buckets/example-bucket/objects/table/") || api.getAttribute("storage.googleapis.com/objectListPrefix", "").startsWith("table/")"#
    );
    Ok(())
}

#[cfg(feature = "credential-access-boundary-client-side")]
#[tokio::test]
async fn client_side_rejects_explicit_conditions_before_io() {
    use reqsign_google::ClientSideCredentialAccessBoundaryGranter;

    let http = MockSts::default();
    let grant = CredentialAccessBoundaryGrant::new(
        CredentialAccessBoundaryRule::new("example-bucket", ["inRole:roles/storage.objectViewer"])
            .with_condition(CONDITION),
    );
    let err = Granter::new(
        Context::new().with_http_send(http.clone()),
        source(Timestamp::now() + Duration::from_secs(3600)),
        ClientSideCredentialAccessBoundaryGranter::new(grant),
    )
    .grant(None)
    .await
    .expect_err("client-side must not drop explicit conditions");
    assert_eq!(err.kind(), ErrorKind::RequestInvalid);
    assert!(
        err.to_string()
            .contains("explicit CEL conditions require server-side")
    );
    assert!(http.0.lock().unwrap().is_empty());
}
