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

/// Percent-encoding applied to the URI path in an AWS canonical request.
///
/// Requests must already contain a wire-ready URI. This setting encodes the
/// canonical path after any normalization selected by [`crate::UriPathNormalizationMode`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PercentEncodingMode {
    /// Keep Reqsign's existing single-encoding behavior.
    ///
    /// Each path segment is percent-decoded as UTF-8, then encoded using AWS's
    /// unreserved character set. For example, `/a%20b` stays `/a%20b`, `%2f`
    /// becomes `%2F`, and `%7E` becomes `~`. Invalid UTF-8 escapes are rejected.
    /// This is the default for every signing service so that existing signatures
    /// survive upgrades.
    #[default]
    Single,
    /// Apply one additional encoding pass to the encoded path.
    ///
    /// Existing escapes are encoded without decoding them first: `/a%20b`
    /// becomes `/a%2520b`, `%2f` becomes `%252f`, and `%FF` becomes `%25FF`.
    /// Literal `/` separators remain unchanged; literal `@` and `=` become
    /// `%40` and `%3D`. Callers must select this explicitly when a service
    /// requires double URI encoding.
    Double,
}
