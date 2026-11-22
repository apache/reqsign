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

use crate::constants::AUTH_TOKEN_PATH;
use http::header;
use http::uri::Authority;
use reqsign_core::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("http") {
            Some(Self::Http)
        } else if value.eq_ignore_ascii_case("https") {
            Some(Self::Https)
        } else {
            None
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeploymentScope {
    scheme: Scheme,
    authority: String,
    host: String,
    port: u16,
    base_path: String,
}

impl DeploymentScope {
    /// Parse the `server` value from `seaf-cli` configuration or an explicit
    /// account-exchange server.
    pub(crate) fn from_server_url(server: &str) -> Result<Self> {
        if server.is_empty() {
            return Err(Error::config_invalid(
                "Seafile server URL must not be empty",
            ));
        }

        let uri: http::Uri = server
            .parse()
            .map_err(|_| Error::config_invalid("Seafile server URL is not a valid URI"))?;
        let scheme = uri
            .scheme_str()
            .and_then(Scheme::parse)
            .ok_or_else(|| Error::config_invalid("Seafile server URL must use http or https"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| Error::config_invalid("Seafile server URL must include a host"))?;
        if uri.query().is_some() {
            return Err(Error::config_invalid(
                "Seafile server URL must not contain a query",
            ));
        }

        let target = parse_authority(authority, scheme).ok_or_else(|| {
            Error::config_invalid("Seafile server URL has an invalid host or port")
        })?;
        let base_path = normalize_base_path(uri.path())?;

        Ok(Self {
            scheme,
            authority: authority.as_str().to_string(),
            host: target.host.to_ascii_lowercase(),
            port: target.port,
            base_path,
        })
    }

    /// Build the account-token endpoint for this deployment.
    pub(crate) fn auth_token_url(&self) -> Result<http::Uri> {
        format!(
            "{}://{}{}{}",
            self.scheme.as_str(),
            self.authority,
            self.base_path,
            AUTH_TOKEN_PATH
        )
        .parse()
        .map_err(|_| Error::config_invalid("failed to build the Seafile account-token URL"))
    }

    /// Check that the request targets this deployment.
    pub(crate) fn validate_request(&self, req: &http::request::Parts) -> Result<()> {
        let uri = &req.uri;
        let scheme = uri
            .scheme_str()
            .and_then(Scheme::parse)
            .ok_or_else(scope_error)?;
        if scheme != self.scheme {
            return Err(scope_error());
        }

        let authority = uri.authority().ok_or_else(scope_error)?;
        let target = parse_authority(authority, scheme).ok_or_else(scope_error)?;
        if !target.host.eq_ignore_ascii_case(&self.host) || target.port != self.port {
            return Err(scope_error());
        }

        let path = uri.path();
        validate_path_form(path).map_err(|_| scope_error())?;
        if !self.contains_path(path) {
            return Err(scope_error());
        }

        self.validate_host_header(req, scheme, &target)?;

        Ok(())
    }

    fn validate_host_header(
        &self,
        req: &http::request::Parts,
        scheme: Scheme,
        uri_target: &AuthorityTarget<'_>,
    ) -> Result<()> {
        let mut host_values = req.headers.get_all(header::HOST).iter();
        let Some(value) = host_values.next() else {
            return Ok(());
        };
        if host_values.next().is_some() {
            return Err(scope_error());
        }

        let value = value.to_str().map_err(|_| scope_error())?;
        let authority: Authority = value.parse().map_err(|_| scope_error())?;
        let host_target = parse_authority(&authority, scheme).ok_or_else(scope_error)?;
        if !host_target.host.eq_ignore_ascii_case(uri_target.host)
            || host_target.port != uri_target.port
        {
            return Err(scope_error());
        }
        if !host_target.host.eq_ignore_ascii_case(&self.host) || host_target.port != self.port {
            return Err(scope_error());
        }

        Ok(())
    }

    fn contains_path(&self, path: &str) -> bool {
        if self.base_path.is_empty() {
            return true;
        }
        if path == self.base_path {
            return true;
        }

        path.strip_prefix(&self.base_path)
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

#[derive(Clone, Copy, Debug)]
struct AuthorityTarget<'a> {
    host: &'a str,
    port: u16,
}

fn parse_authority<'a>(authority: &'a Authority, scheme: Scheme) -> Option<AuthorityTarget<'a>> {
    if authority.as_str().contains('@') {
        return None;
    }

    let host = authority.host();
    if host.is_empty() {
        return None;
    }

    let port = explicit_port(authority.as_str())
        .ok()?
        .unwrap_or_else(|| scheme.default_port());

    Some(AuthorityTarget { host, port })
}

/// Read an explicit port without letting the HTTP authority parser silently
/// turn an invalid value into "no port".
fn explicit_port(authority: &str) -> std::result::Result<Option<u16>, ()> {
    let port = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(())?;
        let after_host = &rest[close + 1..];
        if after_host.is_empty() {
            None
        } else {
            Some(after_host.strip_prefix(':').ok_or(())?)
        }
    } else if let Some((_, port)) = authority.rsplit_once(':') {
        Some(port)
    } else {
        None
    };

    let Some(port) = port else {
        return Ok(None);
    };
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let port = port.parse::<u16>().map_err(|_| ())?;
    if port == 0 {
        return Err(());
    }

    Ok(Some(port))
}

fn normalize_base_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Ok(String::new());
    }
    if !path.starts_with('/') {
        return Err(Error::config_invalid(
            "Seafile server URL path must be absolute",
        ));
    }
    validate_path_form(path).map_err(|_| {
        Error::config_invalid("Seafile server URL path uses an ambiguous representation")
    })?;

    Ok(path.trim_end_matches('/').to_string())
}

/// Reject path forms that the HTTP adapter normalizes before sending.
fn validate_path_form(path: &str) -> std::result::Result<(), ()> {
    if path.contains('\\') {
        return Err(());
    }
    if path.split('/').any(is_dot_segment) {
        return Err(());
    }

    Ok(())
}

fn is_dot_segment(segment: &str) -> bool {
    matches!(
        segment,
        "." | ".."
            | "%2e"
            | "%2E"
            | "%2e%2e"
            | "%2e%2E"
            | "%2E%2e"
            | "%2E%2E"
            | "%2e."
            | "%2E."
            | ".%2e"
            | ".%2E"
    )
}

fn scope_error() -> Error {
    Error::credential_invalid(
        "Seafile credential deployment scope does not match the request endpoint",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str) -> http::request::Parts {
        http::Request::get(uri)
            .body(())
            .expect("request must build")
            .into_parts()
            .0
    }

    #[test]
    fn scope_matches_only_the_configured_deployment() {
        let scope = DeploymentScope::from_server_url("https://Files.Example.com:443/seafile/")
            .expect("scope must parse");

        for uri in [
            "https://files.example.com/seafile",
            "https://files.example.com/seafile/",
            "https://files.example.com/seafile/api2/repos/?x=%2F",
            "https://FILES.example.com:443/seafile/api2/repos/",
        ] {
            scope
                .validate_request(&request(uri))
                .expect("matching request must pass");
        }

        for uri in [
            "http://files.example.com/seafile/api2/repos/",
            "https://other.example.com/seafile/api2/repos/",
            "https://files.example.com:8443/seafile/api2/repos/",
            "https://files.example.com/seafile-other/api2/repos/",
            "https://files.example.com/other/api2/repos/",
            "https://files.example.com/api2/repos/",
            "https://files.example.com/seafile/./api2/repos/",
            "https://files.example.com/seafile/../other/api2/repos/",
            "https://files.example.com/seafile/%2e/api2/repos/",
            "https://files.example.com/seafile/%2e%2e/other/api2/repos/",
        ] {
            let error = scope
                .validate_request(&request(uri))
                .expect_err("mismatched request must fail");
            assert_eq!(reqsign_core::ErrorKind::CredentialInvalid, error.kind());
            assert_eq!(
                error.to_string(),
                "Seafile credential deployment scope does not match the request endpoint"
            );
            assert!(!format!("{error:?}").contains("files.example.com"));
            assert!(!format!("{error:?}").contains("other.example.com"));
        }
    }

    #[test]
    fn root_scope_accepts_every_path_on_the_same_origin() {
        let scope =
            DeploymentScope::from_server_url("http://127.0.0.1:8080").expect("scope must parse");

        scope
            .validate_request(&request("http://127.0.0.1:8080/api2/repos/"))
            .expect("root path must match");
        scope
            .validate_request(&request("http://127.0.0.1:80/api2/repos/"))
            .expect_err("a different effective port must fail");
    }

    #[test]
    fn server_ports_must_be_explicit_and_in_range() {
        for server in [
            "https://files.example.com:0/seafile",
            "https://files.example.com:65536/seafile",
            "https://files.example.com:/seafile",
            "https://files.example.com:not-a-port/seafile",
        ] {
            assert!(
                DeploymentScope::from_server_url(server).is_err(),
                "invalid port must fail: {server}"
            );
        }

        assert!(
            DeploymentScope::from_server_url("https://files.example.com:65535/seafile").is_ok()
        );
    }

    #[test]
    fn server_paths_reject_ambiguous_forms() {
        for server in [
            "https://files.example.com/seafile/../other",
            "https://files.example.com/seafile/./other",
            "https://files.example.com/seafile/%2e%2e/other",
        ] {
            assert!(
                DeploymentScope::from_server_url(server).is_err(),
                "ambiguous path must fail: {server}"
            );
        }
    }
}
