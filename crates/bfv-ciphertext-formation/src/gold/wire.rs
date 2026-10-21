//! Closed canonical Gold Formation frame and complete native five-round topology.
use super::program::{Assessment, DEGREE_BITS, PP_WIDTH, WIDTH};
use super::{Error, Expected, Result, profile_digest};
use bfv_hiding_stark::{Challenge, Config, LOG_BLOWUP, QUERIES, Val};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"DCSGFM01";
pub(super) const HEADER_BYTES: usize = 128;
pub(super) const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - HEADER_BYTES;
pub(super) const MAX_SEQUENCE: usize = 4096;
pub(super) const MAX_SLOTS: usize = 8 * 1024 * 1024;
const CHUNKS: usize = 8;
const PACKED: usize = 43;
const AUX: usize = 220;
const ROUNDS: usize = 5;
const INPUT_DEPTH: usize = DEGREE_BITS + LOG_BLOWUP;
// Fixed H8192 native shape: <=232026 direct Gold,4536 EF5 and19365 digests.
// Gold costs9 bounded-serde slots including its parent, EF5<=48, digest4<=37.
// All remaining nested containers/scalars cost<32768 slots and<3 bytes each.
const HONEST_SLOTS: usize = 232_026 * 9 + 4_536 * 48 + 19_365 * 37 + 32_768;
const HONEST_PAYLOAD_BYTES: usize = 232_026 * 8 + 4_536 * 40 + 19_365 * 32 + 3 * 32_768;

pub(super) fn profile() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/GOLD-FORMATION/one-full-AIR/native-frame/v1\0");
    hash.update(profile_digest());
    hash.update(b"batch0.8/Gold-canonical-LE8/EF5;one8192x512;PP272-PV36;degree14;default43-AUX220-chunks8;MAIN2-AUX2-PP1;5rounds-random-main-quotient-PP-AUX;14binaryFRI;terminal0+actualnativeverify;PUBLIC-PP-only;freshOSprivate;boundedPostcard+reencode+EOF");
    for n in [
        HEADER_BYTES,
        MAX_FRAME_BYTES,
        MAX_SEQUENCE,
        MAX_SLOTS,
        CHUNKS,
        PACKED,
        AUX,
    ] {
        hash.update((n as u64).to_le_bytes());
    }
    hash.finalize().into()
}

pub(super) fn require_assessment(assessment: &Assessment) -> Result<()> {
    if WIDTH != 512
        || PP_WIDTH != 272
        || DEGREE_BITS != 14
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || assessment.chunks() != CHUNKS
        || assessment.packed_lookup_count() != PACKED
        || assessment.aux_width() != AUX
        || HONEST_SLOTS > MAX_SLOTS
        || HONEST_PAYLOAD_BYTES > MAX_PAYLOAD_BYTES
    {
        return Err(Error::Security);
    }
    Ok(())
}

/// Full independently retained binding is checked BEFORE PP or proof decoding.
pub(super) fn payload<'a>(expected: &Expected, frame: &'a [u8]) -> Result<&'a [u8]> {
    if frame.len() < HEADER_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Resource);
    }
    if &frame[..8] != MAGIC || frame[108..HEADER_BYTES] != [0; 20] {
        return Err(Error::Encoding);
    }
    if frame[8..40] != profile() || frame[40..104] != expected.binding() {
        return Err(Error::Binding);
    }
    let len = u32::from_le_bytes(frame[104..108].try_into().map_err(|_| Error::Encoding)?) as usize;
    if len == 0 || len > MAX_PAYLOAD_BYTES || len.checked_add(HEADER_BYTES) != Some(frame.len()) {
        return Err(Error::Encoding);
    }
    Ok(&frame[HEADER_BYTES..])
}
fn frame(expected: &Expected, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + bytes.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&profile());
    out.extend_from_slice(&expected.binding());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(super) fn encode(
    expected: &Expected,
    proof: &BatchProof<Config>,
    assessment: &Assessment,
) -> Result<Vec<u8>> {
    check(proof, assessment)?;
    // Shape is finite BEFORE encoding: no unchecked remote native object reaches here.
    let bytes = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    frame(expected, &bytes)
}
pub(super) fn decode(bytes: &[u8], assessment: &Assessment) -> Result<BatchProof<Config>> {
    require_assessment(assessment)?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    // The pinned Gold Deserialize rejects EVERY underlying noncanonical field
    // representative>=p, including all EF coordinates, salts, blind openings,
    // hash digests, FRI leaves, OOD values and PoW fields. No raw-u64 substitute.
    let (proof, tail) = bounded_postcard::take_from_bytes::<BatchProof<Config>>(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE,
            max_total_elements: MAX_SLOTS,
        },
    )
    .map_err(|error| match error {
        bounded_postcard::Error::Encoding => Error::Encoding,
        bounded_postcard::Error::ResourceLimit => Error::Resource,
    })?;
    if !tail.is_empty() {
        return Err(Error::Encoding);
    }
    check(&proof, assessment)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}

/// Fixed topology/policy only. A zero decoded terminal or valid metadata NEVER
/// mints a result: evidence::verify must still call the real native verifier.
pub(super) fn check(proof: &BatchProof<Config>, assessment: &Assessment) -> Result<()> {
    require_assessment(assessment)?;
    if proof.degree_bits != [DEGREE_BITS]
        || proof.opened_values.instances.len() != 1
        || proof.lookup_terminals.len() != 1
        || !proof.lookup_terminals[0]
            .as_ref()
            .is_some_and(|t| t.0 == Challenge::ZERO)
        || proof.lookup_pow_witness != Some(Val::ZERO)
        || proof.ood_pow_witness != Val::ZERO
        || proof.commitments.main.num_roots() != 1
        || proof.commitments.quotient_chunks.num_roots() != 1
        || proof
            .commitments
            .permutation
            .as_ref()
            .map(|c| c.num_roots())
            != Some(1)
        || proof.commitments.random.as_ref().map(|c| c.num_roots()) != Some(1)
    {
        return Err(Error::Shape);
    }
    let opened = &proof.opened_values.instances[0];
    let base = &opened.base_opened_values;
    if base.trace_local.len() != WIDTH
        || base.trace_next.as_ref().map(Vec::len) != Some(WIDTH)
        || base.preprocessed.as_ref().map(|p| p.local.len()) != Some(PP_WIDTH)
        || base.preprocessed.as_ref().is_some_and(|p| p.next.is_some())
        || base.random.as_ref().map(Vec::len) != Some(5)
        || base.quotient_chunks.len() != CHUNKS
        || base.quotient_chunks.iter().any(|v| v.len() != 5)
        || opened.permutation_local.len() != AUX
        || opened.permutation_next.len() != AUX
    {
        return Err(Error::Shape);
    }
    let (hidden, fri) = &proof.opening_proof;
    if hidden.len() != ROUNDS {
        return Err(Error::Shape);
    }
    for (round, matrices) in hidden.iter().enumerate() {
        let count = if round == 2 { CHUNKS } else { 1 };
        let points = if round == 1 || round == 4 { 2 } else { 1 };
        let blind_width = if round == 3 { 0 } else { 5 };
        if matrices.len() != count
            || matrices
                .iter()
                .any(|m| m.len() != points || m.iter().any(|v| v.len() != blind_width))
        {
            return Err(Error::Shape);
        }
    }
    if fri.batch_pow_witness != Val::ZERO
        || fri.query_pow_witness != Val::ZERO
        || fri.commit_phase_commits.len() != DEGREE_BITS
        || fri.commit_phase_commits.iter().any(|c| c.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != DEGREE_BITS
        || fri.commit_pow_witnesses.iter().any(|&v| v != Val::ZERO)
        || fri.input_openings.len() != ROUNDS
        || fri.commit_phase_openings.len() != DEGREE_BITS
        || fri.final_poly.len() != 1
    {
        return Err(Error::Shape);
    }
    for (round, opened) in fri.input_openings.iter().enumerate() {
        let matrices = if round == 2 { CHUNKS } else { 1 };
        let width = match round {
            0 | 2 => 10,
            1 => WIDTH + 5,
            3 => PP_WIDTH,
            4 => AUX + 5,
            _ => return Err(Error::Shape),
        };
        if !rows(&opened.opened_values, matrices, width)
            || !rows(&opened.opening_proof.0, matrices, 4)
            || opened.opening_proof.1.sibling_hashes.len() > frontier_bound(INPUT_DEPTH)?
        {
            return Err(Error::Shape);
        }
    }
    for (round, opened) in fri.commit_phase_openings.iter().enumerate() {
        if opened.sibling_values.len() != QUERIES
            || opened.sibling_values.iter().any(|v| v.len() != 1)
            || !rows(&opened.opening_proof.0, 1, 4)
            || opened.opening_proof.1.sibling_hashes.len()
                > frontier_bound(INPUT_DEPTH - 1 - round)?
        {
            return Err(Error::Shape);
        }
    }
    Ok(())
}
fn rows<T>(values: &[Vec<Vec<T>>], matrices: usize, width: usize) -> bool {
    values.len() == QUERIES
        && values
            .iter()
            .all(|q| q.len() == matrices && q.iter().all(|r| r.len() == width))
}
fn frontier_bound(depth: usize) -> Result<usize> {
    if depth > INPUT_DEPTH {
        return Err(Error::Shape);
    }
    (0..depth).try_fold(0usize, |sum, level| {
        let parents = 1usize
            .checked_shl((depth - level - 1) as u32)
            .ok_or(Error::Resource)?;
        sum.checked_add(QUERIES.min(parents)).ok_or(Error::Resource)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_full_geometry_fits_the_unchanged_new_namespace_limits() {
        assert_eq!(INPUT_DEPTH, 17);
        assert_eq!(frontier_bound(INPUT_DEPTH).unwrap(), 1983);
        let folded = (0..DEGREE_BITS)
            .map(|r| frontier_bound(INPUT_DEPTH - 1 - r).unwrap())
            .sum::<usize>();
        assert_eq!(5 * 1983 + folded, 19_365);
        assert_eq!(HONEST_SLOTS, 3_055_235);
        assert_eq!(HONEST_PAYLOAD_BYTES, 2_755_632);
        const { assert!(HONEST_SLOTS < MAX_SLOTS) };
        const { assert!(HONEST_PAYLOAD_BYTES + HEADER_BYTES < MAX_FRAME_BYTES) };
        assert!(matches!(frontier_bound(18), Err(Error::Shape)));
    }
    #[test]
    fn native_gold_and_every_extension_coordinate_reject_noncanonical_wire_values() {
        use p3_field::PrimeField64;
        let limits = bounded_postcard::Limits {
            max_sequence_elements: 8,
            max_total_elements: 256,
        };
        let p = 0xffff_ffff_0000_0001_u64;
        let bytes = (p - 1).to_le_bytes();
        let (value, tail) = bounded_postcard::take_from_bytes::<Val>(&bytes, limits).unwrap();
        assert!(tail.is_empty());
        assert_eq!(value.as_canonical_u64(), p - 1);
        assert!(matches!(
            bounded_postcard::take_from_bytes::<Val>(&p.to_le_bytes(), limits),
            Err(bounded_postcard::Error::Encoding)
        ));
        let original = postcard::to_allocvec(&Challenge::ZERO).unwrap();
        assert_eq!(original.len(), 40);
        let (_, tail) = bounded_postcard::take_from_bytes::<Challenge>(&original, limits).unwrap();
        assert!(tail.is_empty());
        for coordinate in 0..5 {
            let mut bytes = original.clone();
            bytes[8 * coordinate..8 * coordinate + 8].copy_from_slice(&p.to_le_bytes());
            assert!(matches!(
                bounded_postcard::take_from_bytes::<Challenge>(&bytes, limits),
                Err(bounded_postcard::Error::Encoding)
            ));
        }
    }
}
