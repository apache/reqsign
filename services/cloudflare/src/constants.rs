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

/// The API token variable used by Wrangler and Cloudflare's official SDKs.
///
/// Cloudflare documents this variable for non-interactive authentication, so an
/// environment that already drives Wrangler or an official client works as is.
pub(crate) const CLOUDFLARE_API_TOKEN: &str = "CLOUDFLARE_API_TOKEN";
