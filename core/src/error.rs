use std::fmt;
use std::time::SystemTimeError;

use ed25519_dalek::SignatureError;

/// An error returned by a JWT operation
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// An authentication error
    Auth(String),
    Base64(String),
    Fetch(String),
    Format(String),
    Json(String),
    Time(String),
}

impl Error {
    /// Construct a new authentication [`Error`].
    pub fn auth<M: fmt::Display>(message: M) -> Self {
        Self::Auth(message.to_string())
    }

    /// Construct a new JWT format [`Error`].
    pub fn format<M: fmt::Display>(cause: M) -> Self {
        Self::Format(cause.to_string())
    }

    /// Construct a new JWT actor retrieval [`Error`].
    pub fn fetch<Info: fmt::Debug>(info: Info) -> Self {
        Self::Fetch(format!("{info:?}"))
    }

    /// Borrow the message of this [`Error`].
    pub fn message(&self) -> &str {
        match self {
            Self::Auth(m)
            | Self::Base64(m)
            | Self::Fetch(m)
            | Self::Format(m)
            | Self::Json(m)
            | Self::Time(m) => m,
        }
    }

    fn variant_name(&self) -> &'static str {
        match self {
            Self::Auth(_) => "Auth",
            Self::Base64(_) => "Base64",
            Self::Fetch(_) => "Fetch",
            Self::Format(_) => "Format",
            Self::Json(_) => "Json",
            Self::Time(_) => "Time",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.variant_name(), self.message())
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(cause: base64::DecodeError) -> Self {
        Self::Base64(cause.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(cause: serde_json::Error) -> Self {
        Self::Json(cause.to_string())
    }
}

impl From<SignatureError> for Error {
    fn from(cause: SignatureError) -> Self {
        Self::Auth(cause.to_string())
    }
}

impl From<SystemTimeError> for Error {
    fn from(cause: SystemTimeError) -> Self {
        Self::Time(cause.to_string())
    }
}
