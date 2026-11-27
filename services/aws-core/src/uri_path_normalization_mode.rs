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

use std::borrow::Cow;

/// URI path normalization applied before percent-encoding for AWS signing.
///
/// This setting affects the canonical path used by SigV4 and SigV4a for header
/// signing and presigning. The outgoing URI keeps the caller's wire path and
/// existing query bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UriPathNormalizationMode {
    /// Skip path normalization. This is the default for every signing service,
    /// including S3.
    #[default]
    Disabled,
    /// Resolve literal `.` and `..` segments and collapse repeated slashes.
    ///
    /// Normalization works on the encoded path, treating percent-encoded dots
    /// and slashes as data. A trailing slash or trailing dot segment retains
    /// the directory slash in the normalized path.
    Enabled,
}

impl UriPathNormalizationMode {
    pub(crate) fn normalize(self, path: &str) -> Cow<'_, str> {
        if self == Self::Disabled
            || (path.starts_with('/')
                && !path.contains("//")
                && !path.split('/').any(|segment| matches!(segment, "." | "..")))
        {
            return Cow::Borrowed(path);
        }

        // Remove dot segments from the encoded absolute path (RFC 3986 §5.2.4)
        // while collapsing empty segments as AWS does.
        let mut normalized = String::with_capacity(path.len());
        for segment in path.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    if let Some(last_slash) = normalized.rfind('/') {
                        normalized.truncate(last_slash);
                    }
                }
                _ => {
                    normalized.push('/');
                    normalized.push_str(segment);
                }
            }
        }

        if normalized.is_empty() {
            return Cow::Borrowed("/");
        }
        if path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..") {
            normalized.push('/');
        }
        Cow::Owned(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::UriPathNormalizationMode;

    #[test]
    fn normalizes_literal_segments_on_the_encoded_path() {
        for (path, expected) in [
            ("", "/"),
            ("/", "/"),
            ("//", "/"),
            ("/.", "/"),
            ("/..", "/"),
            ("relative/path", "/relative/path"),
            ("/../../a//b", "/a/b"),
            ("/a//../b", "/b"),
            ("//a//b///", "/a/b/"),
            ("/a//b/.", "/a/b/"),
            ("/a//b/..", "/a/"),
            ("/a/b/c/./../../g", "/a/g"),
            ("/a/.file/.../end", "/a/.file/.../end"),
            ("/a//./%2e/%2E%2e/x%2F.%2f/", "/a/%2e/%2E%2e/x%2F.%2f/"),
        ] {
            assert_eq!(
                UriPathNormalizationMode::Enabled.normalize(path),
                expected,
                "{path:?}"
            );
            assert_eq!(
                UriPathNormalizationMode::default().normalize(path),
                path,
                "{path:?}"
            );
        }
    }
}
