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

use reqsign_openstack_keystone::{CatalogEntry, Credential, Endpoint};

fn entry(service_type: &str, interface: &str, region: &str, url: &str) -> CatalogEntry {
    CatalogEntry {
        service_type: service_type.into(),
        endpoints: vec![Endpoint {
            interface: interface.into(),
            url: url.into(),
            region_id: Some(region.into()),
            region: None,
        }],
    }
}

#[test]
fn finds_interface_in_later_service_entry() {
    let credential = Credential {
        service_catalog: vec![
            entry(
                "object-store",
                "internal",
                "RegionOne",
                "http://internal/v1",
            ),
            entry("identity", "public", "RegionOne", "https://identity/v3"),
            entry("object-store", "public", "RegionOne", "https://swift/v1"),
        ],
        ..Default::default()
    };

    assert_eq!(
        credential.endpoint("object-store", "public"),
        Some("https://swift/v1")
    );
    assert_eq!(
        credential.endpoint_in_region("object-store", "public", "RegionOne"),
        Some("https://swift/v1")
    );
}

#[test]
fn finds_region_in_later_service_entry() {
    let credential = Credential {
        service_catalog: vec![
            entry(
                "object-store",
                "public",
                "RegionOne",
                "https://swift-one/v1",
            ),
            entry("identity", "public", "RegionTwo", "https://identity/v3"),
            entry(
                "object-store",
                "public",
                "RegionTwo",
                "https://swift-two/v1",
            ),
        ],
        ..Default::default()
    };

    assert_eq!(
        credential.endpoint_in_region("object-store", "public", "RegionTwo"),
        Some("https://swift-two/v1")
    );
}

#[test]
fn skips_empty_service_entries() {
    let credential = Credential {
        service_catalog: vec![
            CatalogEntry {
                service_type: "object-store".into(),
                endpoints: vec![],
            },
            entry("object-store", "public", "RegionOne", "https://swift/v1"),
        ],
        ..Default::default()
    };

    assert_eq!(
        credential.endpoint("object-store", "public"),
        Some("https://swift/v1")
    );
    assert_eq!(
        credential.endpoint_in_region("object-store", "public", "RegionOne"),
        Some("https://swift/v1")
    );
}

#[test]
fn preserves_service_and_endpoint_order() {
    let mut first = entry(
        "object-store",
        "internal",
        "RegionOne",
        "http://internal/v1",
    );
    first
        .endpoints
        .extend(entry("object-store", "public", "RegionOne", "https://first/v1").endpoints);
    first
        .endpoints
        .extend(entry("object-store", "public", "RegionOne", "https://second/v1").endpoints);
    let credential = Credential {
        service_catalog: vec![
            first,
            entry("object-store", "public", "RegionOne", "https://third/v1"),
        ],
        ..Default::default()
    };

    assert_eq!(
        credential.endpoint("object-store", "public"),
        Some("https://first/v1")
    );
    assert_eq!(
        credential.endpoint_in_region("object-store", "public", "RegionOne"),
        Some("https://first/v1")
    );
}

#[test]
fn requires_all_filters_to_match_the_same_endpoint() {
    let credential = Credential {
        service_catalog: vec![
            entry("object-store", "public", "RegionOne", "https://swift/v1"),
            entry(
                "object-store",
                "internal",
                "RegionTwo",
                "http://internal/v1",
            ),
            entry("identity", "public", "RegionTwo", "https://identity/v3"),
        ],
        ..Default::default()
    };

    assert_eq!(credential.endpoint("compute", "public"), None);
    assert_eq!(credential.endpoint("object-store", "admin"), None);
    for (service_type, interface, region) in [
        ("compute", "public", "RegionOne"),
        ("object-store", "admin", "RegionOne"),
        ("object-store", "public", "RegionTwo"),
        ("object-store", "public", "UnknownRegion"),
    ] {
        assert_eq!(
            credential.endpoint_in_region(service_type, interface, region),
            None
        );
    }
}

#[test]
fn resolves_region_fields_in_later_service_entries() {
    for (region_id, region, expected_region) in [
        (Some("RegionTwo"), None, "RegionTwo"),
        (None, Some("LegacyRegion"), "LegacyRegion"),
        (Some("RegionTwo"), Some("LegacyRegion"), "RegionTwo"),
    ] {
        let mut later = entry("object-store", "public", "RegionTwo", "https://later/v1");
        later.endpoints[0].region_id = region_id.map(String::from);
        later.endpoints[0].region = region.map(String::from);
        let credential = Credential {
            service_catalog: vec![
                entry("object-store", "public", "RegionOne", "https://first/v1"),
                later,
            ],
            ..Default::default()
        };

        assert_eq!(
            credential.endpoint_in_region("object-store", "public", expected_region),
            Some("https://later/v1")
        );
        if region_id.is_some() {
            assert_eq!(
                credential.endpoint_in_region("object-store", "public", "LegacyRegion"),
                None
            );
        }
    }
}
