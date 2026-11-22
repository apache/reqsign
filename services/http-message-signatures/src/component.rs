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

//! A component covered by an RFC 9421 HTTP message signature.
//!
//! The first version supports ordinary request fields and the derived
//! request components that are defined by RFC 9421 Section 2.2. Response
//! components, `@request-target`, component parameters, and
//! `@signature-params` are intentionally not represented.

use http::HeaderName;

/// One component in a [`RequestSigner`](crate::RequestSigner)'s ordered
/// coverage list.
///
/// `Header` names are the ordinary HTTP field names. The derived variants map
/// to the RFC 9421 component identifiers of the same name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Component {
    /// An ordinary HTTP request field.
    Header(HeaderName),
    /// The request method, preserving its original case.
    Method,
    /// The absolute target URI.
    TargetUri,
    /// The target authority with the hostname lowercased and the default port
    /// omitted.
    Authority,
    /// The target scheme, lowercased.
    Scheme,
    /// The wire path, preserving percent escapes, with an empty path represented
    /// as `/`.
    Path,
    /// The wire query, including the leading `?`. An absent query is `?`.
    Query,
}

impl Component {
    /// Create a header component from a [`HeaderName`].
    pub fn header(name: HeaderName) -> Self {
        Self::Header(name)
    }

    pub(crate) fn identifier(&self) -> String {
        match self {
            Self::Header(name) => name.as_str().to_string(),
            Self::Method => "@method".to_string(),
            Self::TargetUri => "@target-uri".to_string(),
            Self::Authority => "@authority".to_string(),
            Self::Scheme => "@scheme".to_string(),
            Self::Path => "@path".to_string(),
            Self::Query => "@query".to_string(),
        }
    }
}
