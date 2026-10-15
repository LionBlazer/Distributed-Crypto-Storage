use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidInput(String),
    UnsupportedSql(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::UnsupportedSql(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for Error {}
