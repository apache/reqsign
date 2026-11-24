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

use std::fmt;

/// The error type for reqsign operations
pub struct Error {
    /// The category of error that occurred
    kind: ErrorKind,

    /// Human-readable error message
    message: String,

    /// The underlying error source
    source: Option<anyhow::Error>,

    /// Additional context information for debugging
    context: Vec<String>,

    /// Whether this error is retryable
    retryable: bool,

    /// Whether a command executor reports the operation as unavailable
    command_unavailable: bool,
}

/// The kind of error that occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Credentials are invalid, expired, or malformed
    /// User action: Check credential format, refresh if expired
    CredentialInvalid,

    /// Permission denied when accessing credentials or resources
    /// User action: Check IAM policies, role trust relationships
    PermissionDenied,

    /// Required configuration is missing or invalid
    /// User action: Check configuration files, environment variables
    ConfigInvalid,

    /// Request cannot be signed or is malformed
    /// User action: Check request parameters, headers
    RequestInvalid,

    /// Rate limit exceeded
    /// User action: Implement backoff, check quotas
    RateLimited,

    /// Unexpected error that doesn't fit other categories
    /// User action: Check logs, report bug if persistent
    Unexpected,
}

impl Error {
    /// Create a new error with the given kind and message
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
            context: Vec::new(),
            retryable: kind.default_retryable(),
            command_unavailable: false,
        }
    }

    /// Create an error for a command execution that is unavailable here.
    ///
    /// A [`CommandExecute`](crate::CommandExecute) adapter uses this
    /// constructor when it cannot run commands at all: no executor is
    /// configured, the executor does not support the current target, or the
    /// requested program cannot be spawned. Command providers can then
    /// distinguish an unavailable operation from an execution that ran and
    /// failed without inspecting error sources or matching text.
    ///
    /// This marker is specific to command execution. File and HTTP adapters do
    /// not set it. A consumer decides where unavailability is acceptable: it
    /// may treat an optional command as absent, but a required command that
    /// reports this marker must still fail.
    pub fn command_unavailable(message: impl Into<String>) -> Self {
        Self {
            command_unavailable: true,
            ..Self::new(ErrorKind::Unexpected, message)
        }
    }

    /// Add a source error
    pub fn with_source(mut self, source: impl Into<anyhow::Error>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Add context information for debugging
    pub fn with_context(mut self, context: impl fmt::Display) -> Self {
        self.context.push(context.to_string());
        self
    }

    /// Override the retryable status
    pub fn set_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Get the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Check whether a command executor reports this operation as unavailable.
    ///
    /// Only [`CommandExecute`](crate::CommandExecute) adapters set this marker:
    /// the no-op executor, adapters that do not support the target, and
    /// adapters that confirm the requested program cannot be spawned. It does
    /// not cover file or HTTP operations, and it is not set by an arbitrary
    /// execution failure or by a `NotFound` source inside a custom adapter's
    /// error.
    pub fn is_command_unavailable(&self) -> bool {
        self.command_unavailable
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// Get the context information
    pub fn context(&self) -> &[String] {
        &self.context
    }
}

impl ErrorKind {
    /// Default retryable status for each error kind
    fn default_retryable(&self) -> bool {
        matches!(self, ErrorKind::RateLimited)
    }
}

// Convenience constructors
impl Error {
    /// Create a credential invalid error
    pub fn credential_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::CredentialInvalid, message)
    }

    /// Create a permission denied error
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PermissionDenied, message)
    }

    /// Create a config invalid error
    pub fn config_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ConfigInvalid, message)
    }

    /// Create a request invalid error
    pub fn request_invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::RequestInvalid, message)
    }

    /// Create a rate limited error
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::RateLimited, message)
    }

    /// Create an unexpected error
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unexpected, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

// Custom Debug implementation for better error display
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Error");
        debug.field("kind", &self.kind);
        debug.field("message", &self.message);

        if !self.context.is_empty() {
            debug.field("context", &self.context);
        }

        if let Some(source) = &self.source {
            debug.field("source", source);
        }

        debug.field("retryable", &self.retryable);

        if self.command_unavailable {
            debug.field("command_unavailable", &true);
        }

        debug.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref())
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::CredentialInvalid => write!(f, "invalid credentials"),
            ErrorKind::PermissionDenied => write!(f, "permission denied"),
            ErrorKind::ConfigInvalid => write!(f, "invalid configuration"),
            ErrorKind::RequestInvalid => write!(f, "invalid request"),
            ErrorKind::RateLimited => write!(f, "rate limited"),
            ErrorKind::Unexpected => write!(f, "unexpected error"),
        }
    }
}

/// Convenience type alias for Results
pub type Result<T> = std::result::Result<T, Error>;

// Common From implementations for better ergonomics
impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self::unexpected(err.to_string()).with_source(err)
    }
}

impl From<fmt::Error> for Error {
    fn from(err: fmt::Error) -> Self {
        Self::unexpected(err.to_string()).with_source(err)
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::request_invalid(err.to_string()).with_source(err)
    }
}

impl From<http::header::InvalidHeaderValue> for Error {
    fn from(err: http::header::InvalidHeaderValue) -> Self {
        Self::request_invalid(err.to_string()).with_source(err)
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(err: http::uri::InvalidUri) -> Self {
        Self::request_invalid(err.to_string()).with_source(err)
    }
}

impl From<http::uri::InvalidUriParts> for Error {
    fn from(err: http::uri::InvalidUriParts) -> Self {
        Self::request_invalid(err.to_string()).with_source(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::unexpected(err.to_string()).with_source(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;

        let kind = err.kind();
        let message = err.to_string();
        let source = anyhow::Error::from(err);

        match kind {
            ErrorKind::NotFound => Self::config_invalid(message).with_source(source),
            ErrorKind::PermissionDenied => Self::permission_denied(message).with_source(source),
            _ => Self::unexpected(message)
                .with_source(source)
                .set_retryable(matches!(
                    kind,
                    ErrorKind::TimedOut | ErrorKind::Interrupted | ErrorKind::ConnectionRefused
                )),
        }
    }
}

impl From<http::header::InvalidHeaderName> for Error {
    fn from(err: http::header::InvalidHeaderName) -> Self {
        Self::request_invalid(err.to_string()).with_source(err)
    }
}

impl From<http::header::ToStrError> for Error {
    fn from(err: http::header::ToStrError) -> Self {
        Self::request_invalid(err.to_string()).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::credential_invalid("token expired");
        assert_eq!(err.kind(), ErrorKind::CredentialInvalid);
        assert!(!err.is_retryable());
        assert!(!err.is_command_unavailable());
    }

    #[test]
    fn test_command_unavailable_marker_is_typed() {
        let err = Error::command_unavailable("no command executor configured");
        assert!(err.is_command_unavailable());
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert!(!err.is_retryable());
        assert!(format!("{err:?}").contains("command_unavailable: true"));

        let err = Error::unexpected("the executor failed");
        assert!(!err.is_command_unavailable());
        assert!(!format!("{err:?}").contains("command_unavailable"));
    }

    #[test]
    fn test_error_with_context() {
        let err = Error::permission_denied("access denied")
            .with_context("role: arn:aws:iam::123456789012:role/MyRole")
            .with_context("operation: AssumeRole");

        assert_eq!(err.context().len(), 2);
        assert_eq!(
            err.context()[0],
            "role: arn:aws:iam::123456789012:role/MyRole"
        );
        assert_eq!(err.context()[1], "operation: AssumeRole");
    }

    #[test]
    fn test_rate_limited_default_retryable() {
        let err = Error::rate_limited("too many requests");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_override_retryable() {
        let err = Error::unexpected("network timeout").set_retryable(true);
        assert!(err.is_retryable());

        let err = Error::rate_limited("quota exceeded").set_retryable(false);
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_error_debug_format() {
        let err = Error::config_invalid("missing region")
            .with_context("file: ~/.aws/config")
            .with_context("profile: default");

        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ConfigInvalid"));
        assert!(debug_str.contains("missing region"));
        assert!(debug_str.contains("~/.aws/config"));
    }
}
