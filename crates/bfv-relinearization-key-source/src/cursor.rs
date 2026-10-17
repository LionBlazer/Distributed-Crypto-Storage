//! Nonallocating cursor for one exact pinned protobuf language, not a general decoder.
use crate::{Error, Result};

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn tag(&mut self, expected: u8) -> Result<()> {
        if self.bytes.get(self.offset).copied() != Some(expected) {
            return Err(Error::CanonicalEncoding);
        }
        self.offset += 1;
        Ok(())
    }

    pub(super) fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or(Error::CanonicalEncoding)?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(Error::CanonicalEncoding);
            }
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                if index != 0 && byte == 0 {
                    return Err(Error::CanonicalEncoding);
                }
                return Ok(value);
            }
        }
        Err(Error::CanonicalEncoding)
    }

    pub(super) fn delimited(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = usize::try_from(self.varint()?).map_err(|_| Error::ByteLimit)?;
        if length > maximum {
            return Err(Error::ByteLimit);
        }
        let end = self.offset.checked_add(length).ok_or(Error::ByteLimit)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::CanonicalEncoding)?;
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    pub(super) fn finish(self) -> Result<()> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(Error::CanonicalEncoding)
        }
    }
}
