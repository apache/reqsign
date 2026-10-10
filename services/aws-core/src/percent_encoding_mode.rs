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
/// Requests must already contain a wire-ready URI. This setting affects only the
/// canonical URI used for signing; it does not rewrite the request URI, normalize
/// path segments, or change query encoding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PercentEncodingMode {
    /// Keep the existing single-encoding behavior, suitable for Amazon S3.
    ///
    /// Each path segment is percent-decoded as UTF-8, then encoded using AWS's
    /// unreserved character set. For example, `/a%20b` stays `/a%20b`, `%2f`
    /// becomes `%2F`, and `%7E` becomes `~`. Invalid UTF-8 escapes are rejected.
    /// This remains the default for all services for backwards compatibility.
    #[default]
    Single,
    /// Apply one additional encoding pass to the caller's wire path.
    ///
    /// Existing escapes are encoded without decoding them first: `/a%20b`
    /// becomes `/a%2520b`, `%2f` becomes `%252f`, and `%FF` becomes `%25FF`.
    /// Literal `/` separators remain unchanged; literal `@` and `=` become
    /// `%40` and `%3D`. Use this for services that require double URI encoding.
    Double,
}
