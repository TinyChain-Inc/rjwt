use std::{fmt, time::SystemTimeError};
use ed25519_dalek::SignatureError;

/// The category of error returned by a JWT operation
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// An authentication error
    Auth,
    Base64,
    Fetch,
    Format,
    Json,
    Time,
}

/// An error returned by a JWT operation
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    /// Construct a new [`Error`].
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self { kind, message }
    }

    /// Return the [`ErrorKind`] of this [`Error`].
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Destructure this [`Error`] into its [`ErrorKind`] and an error message [`String`].
    pub fn into_inner(self) -> (ErrorKind, String) {
        (self.kind, self.message)
    }

    /// Construct a new authentication [`Error`].
    pub fn auth<M: fmt::Display>(message: M) -> Self {
        Self::new(ErrorKind::Auth, message.to_string())
    }

    /// Construct a new JWT format [`Error`].
    pub fn format<M: fmt::Display>(cause: M) -> Self {
        Self::new(ErrorKind::Format, cause.to_string())
    }

    /// Construct a new JWT actor retrieval [`Error`].
    pub fn fetch<Info: fmt::Debug>(info: Info) -> Self {
        Self::new(ErrorKind::Fetch, format!("{info:?}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(cause: base64::DecodeError) -> Self {
        Self::new(ErrorKind::Base64, cause.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(cause: serde_json::Error) -> Self {
        Self::new(ErrorKind::Json, cause.to_string())
    }
}

impl From<SignatureError> for Error {
    fn from(cause: SignatureError) -> Self {
        Self::new(ErrorKind::Auth, cause.to_string())
    }
}

impl From<SystemTimeError> for Error {
    fn from(cause: SystemTimeError) -> Self {
        Self::new(ErrorKind::Time, cause.to_string())
    }
}