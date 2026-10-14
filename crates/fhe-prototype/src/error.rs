use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    TooManyRows { count: usize, limit: usize },
    DifferentKeyDomain,
    InvalidImage(String),
    ImageTooLarge { limit: usize },
    Cryptography(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRows { count, limit } => {
                write!(
                    formatter,
                    "{count} rows exceed the prototype limit of {limit}"
                )
            }
            Self::DifferentKeyDomain => {
                write!(formatter, "objects belong to different key domains")
            }
            Self::InvalidImage(reason) => write!(formatter, "invalid table image: {reason}"),
            Self::ImageTooLarge { limit } => write!(formatter, "table image exceeds {limit} bytes"),
            Self::Cryptography(reason) => write!(formatter, "FHE operation failed: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn crypto_error(error: impl fmt::Display) -> Error {
    Error::Cryptography(error.to_string())
}
