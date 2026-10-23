//! Word TLS consumer's compact Body codec; durable/consensus Bodies remain full.
use super::{Binding, CandidateBlock, Error, Result};
use registry200_joint::word::{Lane, REQUEST_BYTES, Request, Verifier, predicate::transport};
use sha2::{Digest, Sha256};
use std::ops::Range;
use version_journal::{Header, MAX_BODY_BYTES, ProtocolProfile};

// This mode is solely the existing Word Predicate transition: one canonical
// Request and one fixed-width ShardUpdate. It is not a generic Body parser.
const REQUEST_AT: usize = 45;
const UPDATES_AT: usize = REQUEST_AT + REQUEST_BYTES;
const PROOF_LENGTH_AT: usize = UPDATES_AT + 4 + 456;
const PROOF_AT: usize = PROOF_LENGTH_AT + 4;
const SIGNATURE: usize = 64;

pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/Word/TLS-compact-Body/v1/full-signed-durable-Body-only");
    hash.update(transport::profile_digest());
    hash.update(b"one-Request368-one-ShardUpdate456;same-parent-update-signature;bodyhash-before-owner-OperationId-native;no-cache-no-fallback");
    hash.update((PROOF_AT as u64).to_le_bytes());
    hash.finalize().into()
}
fn proof(bytes: &[u8], profile: &ProtocolProfile, parent: [u8; 32]) -> Result<Range<usize>> {
    profile.validate()?;
    if bytes.len() > MAX_BODY_BYTES || bytes.len() > profile.max_body_bytes as usize {
        return Err(Error::ResourceLimit);
    }
    if bytes.len() < PROOF_AT + SIGNATURE
        || &bytes[..9] != b"DCSJB001\x01"
        || bytes[9..41] != parent
        || u32::from_le_bytes(bytes[41..45].try_into().unwrap()) as usize != REQUEST_BYTES
        || REQUEST_BYTES > profile.max_request_bytes as usize
        || u32::from_le_bytes(bytes[UPDATES_AT..UPDATES_AT + 4].try_into().unwrap()) != 1
        || profile.max_updates == 0
    {
        return Err(Error::Encoding);
    }
    let request = Request::decode(&bytes[REQUEST_AT..UPDATES_AT])?;
    if request.lane() != Lane::Predicate || request.parent() != parent {
        return Err(Error::Binding);
    }
    let n = u32::from_le_bytes(bytes[PROOF_LENGTH_AT..PROOF_AT].try_into().unwrap()) as usize;
    let end = PROOF_AT.checked_add(n).ok_or(Error::ResourceLimit)?;
    if n == 0
        || n > profile.max_proof_bytes as usize
        || end.checked_add(SIGNATURE) != Some(bytes.len())
    {
        return Err(Error::Encoding);
    }
    Ok(PROOF_AT..end)
}

/// Encode an already authored original full candidate for the actual TLS client.
/// The original Body/hash/signature/intent remain the caller's canonical pins.
/// Compaction verifies no native proof and creates no new signed representation.
pub fn compact_body(binding: &Binding, block: &CandidateBlock) -> Result<Vec<u8>> {
    if block.header().genesis != binding.journal_genesis().id()?
        || block.header().body_hash != version_journal::hash(block.body())
    {
        return Err(Error::Binding);
    }
    let range = proof(
        block.body(),
        &binding.journal_genesis().profile,
        block.header().parent,
    )?;
    let compact = transport::compact(
        binding.application_descriptor().source(),
        &block.body()[range.clone()],
    )?;
    let mut out = Vec::with_capacity(PROOF_AT + compact.len() + SIGNATURE);
    out.extend_from_slice(&block.body()[..PROOF_AT]);
    out[PROOF_LENGTH_AT..PROOF_AT].copy_from_slice(
        &u32::try_from(compact.len())
            .map_err(|_| Error::ResourceLimit)?
            .to_le_bytes(),
    );
    out.extend(compact);
    out.extend_from_slice(&block.body()[range.end..]);
    Ok(out)
}

pub(crate) fn restore_body(
    binding: &Binding,
    verifier: &Verifier,
    header: Header,
    compact: Vec<u8>,
) -> Result<CandidateBlock> {
    if header.genesis != binding.journal_genesis().id()? {
        return Err(Error::Binding);
    }
    let range = proof(&compact, &binding.journal_genesis().profile, header.parent)?;
    let original_len = transport::restored_evidence_bytes(&compact[range.clone()])?;
    let total = PROOF_AT
        .checked_add(original_len)
        .and_then(|n| n.checked_add(SIGNATURE))
        .ok_or(Error::ResourceLimit)?;
    if total > binding.journal_genesis().profile.max_body_bytes as usize
        || total > MAX_BODY_BYTES
        || original_len > binding.journal_genesis().profile.max_proof_bytes as usize
    {
        return Err(Error::ResourceLimit);
    }
    // Only ONE full Body allocation. The bounded compact input remains borrowed;
    // immutable bytes copy straight from the actual cache into this final buffer.
    let mut full = Vec::new();
    full.try_reserve_exact(total)
        .map_err(|_| Error::ResourceLimit)?;
    full.extend_from_slice(&compact[..PROOF_AT]);
    full[PROOF_LENGTH_AT..PROOF_AT].copy_from_slice(
        &u32::try_from(original_len)
            .map_err(|_| Error::ResourceLimit)?
            .to_le_bytes(),
    );
    verifier.append_predicate_transport(&compact[range.clone()], &mut full)?;
    full.extend_from_slice(&compact[range.end..]);
    if full.len() != total || version_journal::hash(&full) != header.body_hash {
        return Err(Error::Binding);
    }
    // This is still unverified. The TLS handler must now perform its existing
    // complete Body authorization/OperationId preparation and normal import.
    Ok(CandidateBlock::new(header, full)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_body_layout_rejects_wrong_lane_parent_counts_extents_and_resource_caps() {
        let profile = ProtocolProfile {
            initial_target: version_journal::Target([255; 32]),
            pow_limit: version_journal::Target([255; 32]),
            block_spacing_secs: 1,
            retarget_interval: 2,
            max_future_secs: 1,
            confirmation_depth: 1,
            max_headers: 4,
            max_shards: 1,
            max_updates: 1,
            max_body_bytes: MAX_BODY_BYTES as u32,
            max_request_bytes: REQUEST_BYTES as u32,
            max_proof_bytes: MAX_BODY_BYTES as u32,
            max_journal_bytes: 1024 * 1024,
        };
        // Canonical untrusted layout only; these bytes are no proof or owner.
        let parent = [7; 32];
        let mut request = vec![0; REQUEST_BYTES];
        request[..8].copy_from_slice(b"DCSWRQ01");
        request[8] = 2;
        request[48..80].copy_from_slice(&parent);
        request[208] = 1; // required nonzero Predicate statement root
        let heads = version_journal::HeadPair {
            data: [0; 112],
            index: [0; 112],
        };
        // Use the independent authoritative Body encoder; these are solely
        // untrusted layout inputs, never a valid computation/state fixture.
        let raw = version_journal::Body::Transition(version_journal::AuthorizedTransition {
            parent,
            request,
            updates: vec![version_journal::ShardUpdate {
                id: 1,
                old: heads,
                new: heads,
            }],
            proof: b"DCSWJT01".to_vec(),
            owner_signature: [55; SIGNATURE],
        })
        .encode(&profile)
        .unwrap();
        assert_eq!(
            proof(&raw, &profile, parent).unwrap(),
            PROOF_AT..PROOF_AT + 8
        );
        assert_eq!(&raw[proof(&raw, &profile, parent).unwrap()], b"DCSWJT01");
        assert!(proof(&raw, &profile, [8; 32]).is_err());
        for at in [8, 41, REQUEST_AT + 8, UPDATES_AT, PROOF_LENGTH_AT] {
            let mut damaged = raw.clone();
            damaged[at] ^= 1;
            assert!(proof(&damaged, &profile, parent).is_err(), "offset {at}");
        }
        assert!(proof(&raw[..raw.len() - 1], &profile, parent).is_err());
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(proof(&trailing, &profile, parent).is_err());
        let mut small = profile;
        small.max_request_bytes -= 1;
        assert!(proof(&raw, &small, parent).is_err());
    }
}
