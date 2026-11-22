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

/// Microsoft Entra token endpoint tenant used by the documented default.
///
/// `common` accepts both work or school accounts and personal Microsoft
/// accounts, which is what the Microsoft Graph `me` endpoints address.
pub(crate) const DEFAULT_TENANT: &str = "common";

/// Microsoft Entra global service authentication endpoint.
///
/// National clouds publish separate authentication endpoints; callers in those
/// clouds replace the whole token endpoint instead of the tenant.
pub(crate) const ENTRA_AUTH_ENDPOINT: &str = "https://login.microsoftonline.com";

/// Path suffix of the Microsoft Entra v2.0 token endpoint.
pub(crate) const ENTRA_TOKEN_PATH: &str = "/oauth2/v2.0/token";
