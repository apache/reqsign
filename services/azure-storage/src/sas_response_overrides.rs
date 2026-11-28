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

use reqsign_core::{Error, Result};
use std::fmt::{Debug, Formatter};

/// Response headers to override through a Blob Storage or Azure Files SAS.
///
/// Supply the decoded header values. Empty values omit the corresponding query
/// parameters.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SasResponseOverrides {
    cache_control: String,
    content_disposition: String,
    content_encoding: String,
    content_language: String,
    content_type: String,
}

impl Debug for SasResponseOverrides {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SasResponseOverrides")
            .finish_non_exhaustive()
    }
}

impl SasResponseOverrides {
    /// Override the `Cache-Control` response header (`rscc`).
    pub fn with_cache_control(mut self, value: impl Into<String>) -> Self {
        self.cache_control = value.into();
        self
    }

    /// Override the `Content-Disposition` response header (`rscd`).
    pub fn with_content_disposition(mut self, value: impl Into<String>) -> Self {
        self.content_disposition = value.into();
        self
    }

    /// Override the `Content-Encoding` response header (`rsce`).
    pub fn with_content_encoding(mut self, value: impl Into<String>) -> Self {
        self.content_encoding = value.into();
        self
    }

    /// Override the `Content-Language` response header (`rscl`).
    pub fn with_content_language(mut self, value: impl Into<String>) -> Self {
        self.content_language = value.into();
        self
    }

    /// Override the `Content-Type` response header (`rsct`).
    pub fn with_content_type(mut self, value: impl Into<String>) -> Self {
        self.content_type = value.into();
        self
    }

    pub(crate) fn from_query(query: &[(String, String)]) -> Result<Self> {
        let value =
            |name| sas_query_value(query, name).map(|value| value.unwrap_or_default().to_owned());
        Ok(Self {
            cache_control: value("rscc")?,
            content_disposition: value("rscd")?,
            content_encoding: value("rsce")?,
            content_language: value("rscl")?,
            content_type: value("rsct")?,
        })
    }

    // Azure places these fields at the end of each applicable string-to-sign.
    pub(crate) fn fields(&self) -> [(&'static str, &str); 5] {
        [
            ("rscc", &self.cache_control),
            ("rscd", &self.content_disposition),
            ("rsce", &self.content_encoding),
            ("rscl", &self.content_language),
            ("rsct", &self.content_type),
        ]
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.fields().iter().any(|(_, value)| {
            value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\t')
        }) {
            return Err(Error::request_invalid(
                "Azure SAS response overrides must not contain control characters other than horizontal tabs",
            ));
        }
        Ok(())
    }

    pub(crate) fn append_to_query(&self, query: &mut Vec<(String, String)>) {
        query.extend(
            self.fields()
                .into_iter()
                .filter(|(_, value)| !value.is_empty())
                .map(|(name, value)| (name.to_owned(), value.to_owned())),
        );
    }
}

// Use the decoded view for signing. The request retains the original query bytes.
pub(crate) fn sas_query_value<'a>(
    query: &'a [(String, String)],
    name: &str,
) -> Result<Option<&'a str>> {
    let mut matches = query
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str());
    let value = matches.next();
    if matches.next().is_some() {
        return Err(
            Error::request_invalid("duplicate signed Azure SAS query parameter").with_context(name),
        );
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) const TEST_RESPONSE_OVERRIDE_QUERY: &str = concat!(
    "rscc=public%2C%20max-age%3D60",
    "&rscd=attachment%3B%20filename%3D%22a%2Bb.txt%22",
    "&rsce=gzip&rscl=en-US&rsct=text/plain%3B%20charset%3Dutf-8",
);

#[cfg(test)]
pub(crate) fn test_response_overrides() -> SasResponseOverrides {
    SasResponseOverrides::default()
        .with_cache_control("public, max-age=60")
        .with_content_disposition("attachment; filename=\"a+b.txt\"")
        .with_content_encoding("gzip")
        .with_content_language("en-US")
        .with_content_type("text/plain; charset=utf-8")
}
