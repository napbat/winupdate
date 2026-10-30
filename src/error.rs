//! Error types for the readers of update packages.
//!
//! An error can have a context: a byte offset in the input, a structure name and details. An
//! I/O error from a [`ReadAt`](crate::ReadAt) reader keeps the original error as its source.
//!
//! # Example
//!
//! ```
//! match winupdate::psf::strip_crc(b"\x01\x02") {
//!     Ok(_) => println!("valid"),
//!     Err(e) => eprintln!("Error: {e}"),
//! }
//! ```

use std::fmt;
use std::io;

/// Result type alias for winupdate operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Information about the location of an error.
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// Byte offset in the input where the error occurred (if known).
    pub offset: Option<u64>,
    /// Name of the structure that the reader was reading (if known).
    pub structure: Option<String>,
    /// Additional details about the error.
    pub details: Option<String>,
}

impl ErrorContext {
    /// Return `true` if the context has no information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offset.is_none() && self.structure.is_none() && self.details.is_none()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(offset) = self.offset {
            parts.push(format!("offset {offset:#x}"));
        }
        if let Some(structure) = &self.structure {
            parts.push(format!("in {structure}"));
        }
        if let Some(details) = &self.details {
            parts.push(details.clone());
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// An error from reading an update package.
#[derive(Debug)]
pub struct Error {
    /// The error kind.
    pub kind: ErrorKind,
    /// Optional context about where the error occurred.
    pub context: Option<ErrorContext>,
    /// The error that caused this error (if any).
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

/// The kind of error that occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The reader returned an I/O error.
    Io(io::ErrorKind),
    /// The input does not start with the expected signature.
    InvalidSignature(Vec<u8>),
    /// The input ended before the reader read all data.
    UnexpectedEnd,
    /// A value in the input is not valid.
    InvalidData(String),
    /// The input uses a feature that the crate does not support.
    Unsupported(String),
    /// The archive has no item with this name.
    NotFound(String),
    /// A stored hash is not equal to the hash of the data.
    HashMismatch {
        /// The name of the hash algorithm.
        algorithm: &'static str,
    },
    /// The data is larger than the limit allows.
    LimitExceeded {
        /// The size that the data needs, in bytes.
        needed: u64,
        /// The limit, in bytes.
        limit: u64,
    },
}

impl Error {
    /// Create a new error with the given kind.
    #[must_use]
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
            source: None,
        }
    }

    /// Add offset context.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.context
            .get_or_insert_with(ErrorContext::default)
            .offset = Some(offset);
        self
    }

    /// Add structure name context.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        self.context
            .get_or_insert_with(ErrorContext::default)
            .structure = Some(name.into());
        self
    }

    /// Add details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.context
            .get_or_insert_with(ErrorContext::default)
            .details = Some(details.into());
        self
    }

    /// Get the context if present.
    #[must_use]
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Get the error kind.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Create an `UnexpectedEnd` error.
    #[must_use]
    pub fn unexpected_end() -> Self {
        Self::new(ErrorKind::UnexpectedEnd)
    }

    /// Create an `InvalidData` error.
    pub fn invalid_data(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidData(msg.into()))
    }

    /// Create an `Unsupported` error.
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported(msg.into()))
    }

    /// Create a `NotFound` error.
    pub fn not_found(name: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound(name.into()))
    }

    /// Create a `LimitExceeded` error.
    #[must_use]
    pub fn limit_exceeded(needed: u64, limit: u64) -> Self {
        Self::new(ErrorKind::LimitExceeded { needed, limit })
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(kind) => write!(f, "I/O error ({kind})"),
            ErrorKind::InvalidSignature(sig) => write!(f, "Invalid signature {sig:02x?}"),
            ErrorKind::UnexpectedEnd => write!(f, "Unexpected end of data"),
            ErrorKind::InvalidData(msg) => write!(f, "Invalid data: {msg}"),
            ErrorKind::Unsupported(msg) => write!(f, "Unsupported feature: {msg}"),
            ErrorKind::NotFound(name) => write!(f, "No item with the name {name:?}"),
            ErrorKind::HashMismatch { algorithm } => write!(f, "{algorithm} hash mismatch"),
            ErrorKind::LimitExceeded { needed, limit } => {
                write!(
                    f,
                    "The data needs {needed} bytes, more than the limit of {limit}"
                )
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ctx) = &self.context
            && !ctx.is_empty()
        {
            write!(f, " ({ctx})")?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Self::unexpected_end();
        }
        Self {
            kind: ErrorKind::Io(error.kind()),
            context: None,
            source: Some(Box::new(error)),
        }
    }
}

impl From<lzms::Error> for Error {
    fn from(error: lzms::Error) -> Self {
        let kind = match &error.kind {
            lzms::ErrorKind::Unsupported(msg) => ErrorKind::Unsupported(msg.clone()),
            lzms::ErrorKind::LimitExceeded { needed, limit } => ErrorKind::LimitExceeded {
                needed: *needed,
                limit: *limit,
            },
            _ => ErrorKind::InvalidData("the LZMS data is not valid".into()),
        };
        Self {
            kind,
            context: None,
            source: Some(Box::new(error)),
        }
    }
}
