use super::{Error, Result};

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(n).ok_or(Error::ResourceLimit)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidEncoding)?;
        self.offset = end;
        Ok(result)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidEncoding)
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
    pub(crate) fn blob(&mut self, cap: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > cap {
            return Err(Error::ResourceLimit);
        }
        self.take(n)
    }
    pub(crate) fn end(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }
}
pub(crate) fn blob(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Result<()> {
    if bytes.len() > cap {
        return Err(Error::ResourceLimit);
    }
    let n = u32::try_from(bytes.len()).map_err(|_| Error::ResourceLimit)?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
