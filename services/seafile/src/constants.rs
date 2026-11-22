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

/// The relative path of the Seafile account-token endpoint.
pub(crate) const AUTH_TOKEN_PATH: &str = "/api2/auth-token/";

/// The default user configuration file read by the first-party `seaf-cli`.
pub(crate) const CLI_CONFIG_PATH: &str = "~/.seafile.conf";

/// The configuration section that `seaf-cli` reads account values from.
pub(crate) const CLI_CONFIG_SECTION: &str = "account";

/// The configuration key that holds the account token.
pub(crate) const CLI_CONFIG_TOKEN_KEY: &str = "token";

/// The configuration key that holds the deployment server URL.
pub(crate) const CLI_CONFIG_SERVER_KEY: &str = "server";

/// The configuration key that holds the account login name.
pub(crate) const CLI_CONFIG_USER_KEY: &str = "user";
