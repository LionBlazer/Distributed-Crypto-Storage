//! Transport-only omission of three immutable frames, never Journal evidence.
//! Resolution requires the installed verifier's actual retained DATA theorem.
use super::*;
use crate::word::{Evidence, Lane};

const PREFIX: usize = 40;
const TRANSPORT_MAGIC: &[u8; 8] = b"DCSWJT01";

pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/Word-Predicate/transport-only/v1/DCSWJT01");
    hash.update(super::profile_digest());
    hash.update(b"exact-full-header416-and-eight-lengths;omit-only-State-Role3-DATA;original-GOPREQ-CT3-Word-Query-product;retained-full-Expected-no-token;restore-DCSWJE01-before-Body-signature-OperationId-native;no-durable-reference-no-fallback");
    hash.finalize().into()
}

/// Compact complete original evidence for the actual Word TLS consumer.
/// This checks public codec association only, and verifies no proof or signature.
pub fn compact(source: &SourceVersionExpected, full: &[u8]) -> Result<Vec<u8>> {
    let (_, packet) = Evidence::split(Lane::Predicate, full)?;
    drop(BorrowedPredicate::parse(source, packet)?);
    let header = Header::parse(&packet[..HEADER])?;
    let start = HEADER + header.lengths[0] + header.lengths[1];
    let end = start + header.lengths[2..5].iter().sum::<usize>();
    let mut out = Vec::with_capacity(PREFIX + packet.len() - (end - start));
    out.extend(TRANSPORT_MAGIC);
    out.extend(profile_digest());
    out.extend_from_slice(&packet[..start]);
    out.extend_from_slice(&packet[end..]);
    Ok(out)
}

fn geometry(raw: &[u8]) -> Result<Header> {
    if raw.len() > MAX_PREDICATE_PACKET_BYTES + PREFIX {
        return Err(Error::ResourceLimit);
    }
    if raw.len() < PREFIX + HEADER || &raw[..8] != TRANSPORT_MAGIC {
        return Err(Error::InvalidEncoding);
    }
    if raw[8..PREFIX] != profile_digest() {
        return Err(Error::WrongDomain);
    }
    let header = Header::parse(&raw[PREFIX..PREFIX + HEADER])?;
    let omitted = header.lengths[2..5].iter().sum::<usize>();
    if raw.len()
        != PREFIX
            .checked_add(header.total - omitted)
            .ok_or(Error::ResourceLimit)?
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(header)
}

/// Preflight the exact eventual full evidence allocation, without a cache lookup
/// or proof check. The real TLS consumer charges its expanded Body before use.
pub fn restored_evidence_bytes(compact: &[u8]) -> Result<usize> {
    24usize
        .checked_add(geometry(compact)?.total)
        .ok_or(Error::ResourceLimit)
}

pub(in crate::word) struct Borrowed<'a> {
    header: Header,
    original_header: &'a [u8],
    before: &'a [u8],
    after: &'a [u8],
    data: installed::Expected,
}
impl<'a> Borrowed<'a> {
    pub(in crate::word) fn parse(source: &SourceVersionExpected, raw: &'a [u8]) -> Result<Self> {
        let header = geometry(raw)?;
        let original_header = &raw[PREFIX..PREFIX + HEADER];
        let begin = PREFIX + HEADER;
        let end = begin + header.lengths[0] + header.lengths[1];
        let request = PublicRequest::decode(&raw[begin..begin + header.lengths[0]])
            .map_err(|_| Error::InvalidEncoding)?;
        let data = header.data_expected(source, &request)?;
        // No native product or query check belongs to this transport resolver.
        Ok(Self {
            header,
            original_header,
            before: &raw[begin..end],
            after: &raw[end..],
            data,
        })
    }
    pub(in crate::word) fn data_expected(&self) -> &installed::Expected {
        &self.data
    }

    /// Append directly into the final Body allocation, after all cache checks.
    /// An error leaves the caller's prefix unchanged; these bytes grant nothing.
    pub(in crate::word) fn append_full(&self, frames: [&[u8]; 3], out: &mut Vec<u8>) -> Result<()> {
        if frames
            .iter()
            .map(|v| v.len())
            .ne(self.header.lengths[2..5].iter().copied())
        {
            return Err(Error::WrongDomain);
        }
        let evidence_len = 24usize
            .checked_add(self.header.total)
            .ok_or(Error::ResourceLimit)?;
        let child_len = u32::try_from(self.header.total).map_err(|_| Error::ResourceLimit)?;
        if out
            .len()
            .checked_add(evidence_len)
            .filter(|n| *n <= version_journal::MAX_BODY_BYTES)
            .is_none()
        {
            return Err(Error::ResourceLimit);
        }
        out.try_reserve_exact(evidence_len)
            .map_err(|_| Error::ResourceLimit)?;
        out.extend(b"DCSWJE01");
        out.push(Lane::Predicate.tag());
        out.extend([0; 7]);
        out.extend(0u32.to_le_bytes());
        out.extend(child_len.to_le_bytes());
        out.extend_from_slice(self.original_header);
        out.extend_from_slice(self.before);
        for frame in frames {
            out.extend_from_slice(frame);
        }
        out.extend_from_slice(self.after);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_namespace_and_unbounded_or_incomplete_headers_are_rejected() {
        for raw in [&[][..], b"DCSWJE01", b"DCSWJT01"] {
            assert!(restored_evidence_bytes(raw).is_err());
        }
        let mut raw = vec![0; PREFIX + HEADER];
        raw[..8].copy_from_slice(TRANSPORT_MAGIC);
        raw[8..PREFIX].copy_from_slice(&profile_digest());
        raw[PREFIX..PREFIX + 8].copy_from_slice(MAGIC);
        raw[PREFIX + 8..PREFIX + 40].copy_from_slice(&super::super::profile_digest());
        assert!(restored_evidence_bytes(&raw).is_err());
        raw[PREFIX + 376..PREFIX + 380].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(restored_evidence_bytes(&raw).is_err());
        assert!(Evidence::split(Lane::Predicate, &raw).is_err());
    }
}
