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

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

// Headers used in azure services.
pub const X_MS_DATE: &str = "x-ms-date";
pub const CONTENT_MD5: &str = "content-md5";

pub static AZURE_QUERY_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'/')
    .remove(b'~');

pub(crate) const STORAGE_ACCOUNT_KEY_LENGTH: usize = 64;
pub(crate) const SAS_ENCRYPTION_SCOPE_VERSION: &str = "2020-12-06";

// Versions with signed IP and protocol that predate Blob SAS encryption scopes.
pub(crate) const LEGACY_SAS_VERSIONS_WITH_IP_AND_PROTOCOL: &[&str] = &[
    "2015-04-05",
    "2015-07-08",
    "2015-12-11",
    "2016-05-31",
    "2017-04-17",
    "2017-07-29",
    "2017-11-09",
    "2018-03-28",
    "2018-11-09",
    "2019-02-02",
    "2019-07-07",
    "2019-12-12",
    "2020-02-10",
    "2020-04-08",
    "2020-06-12",
    "2020-08-04",
    "2020-10-02",
];

// Azure Storage versions supported by the SAS string-to-sign with encryption scope.
pub(crate) const SAS_VERSIONS_WITH_ENCRYPTION_SCOPE: &[&str] = &[
    SAS_ENCRYPTION_SCOPE_VERSION,
    "2021-02-12",
    "2021-04-10",
    "2021-06-08",
    "2021-08-06",
    "2021-10-04",
    "2021-12-02",
    "2022-11-02",
    "2023-01-03",
    "2023-05-03",
    "2023-08-03",
    "2023-11-03",
    "2024-02-04",
    "2024-05-04",
    "2024-08-04",
    "2024-11-04",
    "2025-01-05",
    "2025-05-05",
    "2025-07-05",
    "2025-11-05",
    "2026-02-06",
    "2026-04-06",
    "2026-06-06",
    "2026-10-06",
];
