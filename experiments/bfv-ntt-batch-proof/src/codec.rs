use crate::{Error, MAX_DECODE_ELEMENTS, MAX_SEQUENCE_ELEMENTS};
use serde::Deserialize;
pub(crate) fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    let (value, trailing) = bounded_postcard::take_from_bytes(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE_ELEMENTS,
            max_total_elements: MAX_DECODE_ELEMENTS,
        },
    )
    .map_err(|e| match e {
        bounded_postcard::Error::ResourceLimit => Error::ResourceLimit,
        bounded_postcard::Error::Encoding => Error::Encoding,
    })?;
    if !trailing.is_empty() {
        return Err(Error::Encoding);
    }
    Ok(value)
}
