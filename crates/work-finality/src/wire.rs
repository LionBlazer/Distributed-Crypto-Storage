use crate::{Error, Hash, Result, profile_digest};

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.position.checked_add(N).ok_or(Error::ResourceLimit)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::InvalidEncoding)?;
        let value = slice.try_into().map_err(|_| Error::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }
    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(crate) fn header(&mut self, magic: &[u8; 8]) -> Result<()> {
        if self.array::<8>()? != *magic || self.array::<32>()? != profile_digest() {
            return Err(Error::WrongDomain);
        }
        Ok(())
    }
    pub(crate) fn end(self) -> Result<()> {
        if self.position != self.bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }
}

pub(crate) fn length(header: usize, count: usize, record: usize, cap: usize) -> Result<usize> {
    let bytes = count
        .checked_mul(record)
        .and_then(|n| header.checked_add(n))
        .ok_or(Error::ResourceLimit)?;
    if bytes > cap {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

pub(crate) fn key(bytes: Hash) -> Result<ed25519_dalek::VerifyingKey> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
    if key.is_weak() {
        return Err(Error::InvalidKey);
    }
    Ok(key)
}
