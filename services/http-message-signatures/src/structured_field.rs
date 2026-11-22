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

//! The small subset of RFC 8941 Structured Fields serialization used by
//! RFC 9421 signature parameters.

use reqsign_core::hash::base64_encode;
use reqsign_core::{Error, Result};

/// The largest integer representable by an RFC 8941 Structured Field.
pub(crate) const MAX_INTEGER: i64 = 999_999_999_999_999;

/// The smallest integer representable by an RFC 8941 Structured Field.
pub(crate) const MIN_INTEGER: i64 = -999_999_999_999_999;

/// Return whether `value` can be serialized as an RFC 8941 String.
pub(crate) fn is_string(value: &str) -> bool {
    value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Return whether `value` can be serialized as an RFC 8941 key.
pub(crate) fn is_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    (first.is_ascii_lowercase() || first == b'*')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b'*')
        })
}

/// Serialize a value as an RFC 8941 String, including quotes and escaping.
pub(crate) fn serialize_string(value: &str) -> Result<String> {
    if !is_string(value) {
        return Err(Error::request_invalid(
            "value is not representable as an RFC 8941 String",
        ));
    }

    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            output.push('\\');
        }
        output.push(character);
    }
    output.push('"');
    Ok(output)
}

/// Serialize an RFC 8941 Integer after checking its specified range.
pub(crate) fn serialize_integer(value: i64) -> Result<String> {
    if !(MIN_INTEGER..=MAX_INTEGER).contains(&value) {
        return Err(Error::request_invalid(
            "integer is outside the RFC 8941 range",
        ));
    }

    Ok(value.to_string())
}

/// Serialize bytes as an RFC 8941 Byte Sequence.
pub(crate) fn serialize_byte_sequence(value: &[u8]) -> String {
    format!(":{}:", base64_encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_strings_and_keys_per_rfc_8941() {
        assert_eq!(serialize_string("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
        assert!(is_key("sig1"));
        assert!(is_key("*"));
        assert!(!is_key(""));
        assert!(!is_key("Sig1"));
        assert!(!is_string("caf\u{e9}"));
    }

    #[test]
    fn serializes_bounded_integers_and_byte_sequences() {
        assert_eq!(serialize_integer(0).unwrap(), "0");
        assert_eq!(serialize_integer(-1).unwrap(), "-1");
        assert!(serialize_integer(MAX_INTEGER + 1).is_err());
        assert_eq!(serialize_byte_sequence(b"hello"), ":aGVsbG8=:");
    }
}
