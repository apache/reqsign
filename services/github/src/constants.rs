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

/// The token variable documented by the GitHub CLI. It takes precedence over
/// `GITHUB_TOKEN`.
pub(crate) const GH_TOKEN: &str = "GH_TOKEN";

/// The token variable used by GitHub and the GitHub CLI.
pub(crate) const GITHUB_TOKEN: &str = "GITHUB_TOKEN";

/// The only host this crate discovers credentials for and signs requests to.
pub(crate) const GITHUB_HOST: &str = "github.com";

/// The GitHub CLI program invoked for stored-token discovery.
pub(crate) const GH_CLI: &str = "gh";
