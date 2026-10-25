// Separate SHA-suite frame; no old frame, supplied topology or verifier fallback.
use super::assessment::Assessment;
use super::layout::{
    AUX, DOMAIN, EXT_BOUND, GOLD_BOUND, H, LOG_H, PACKED, PP as PP_WIDTH, W as WIDTH,
};
use super::{Expected, native_wire};
#[cfg(test)]
use crate::gold::public_hash_trace::Sha256;
use crate::gold::{Error, Result};
use bfv_hiding_stark::hash::{Challenger, Config, Pcs};
use bfv_hiding_stark::{Challenge, LOG_BLOWUP, QUERIES, Val};
use p3_batch_stark::BatchProof;
use p3_commit::UnivariateStarkPcs;
use p3_field::PrimeCharacteristicRing;
#[cfg(not(test))]
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = if WIDTH == 512 {
    b"DCSHDD01"
} else {
    b"DCSHQF01"
};
const HEADER_BYTES: usize = 128;
pub(in crate::gold) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - HEADER_BYTES;
const MAX_SEQUENCE: usize = 4096;
const MAX_SLOTS: usize = 4 * 1024 * 1024;
const DEGREE_BITS: usize = LOG_H + 1;
const CHUNKS: usize = 8;
const ROUNDS: usize = 5;
const INPUT_DEPTH: usize = DEGREE_BITS + LOG_BLOWUP;
// Same direct Gold/EF5 openings as the original AIR. Every digest is 32 raw
// bytes, not four reduced Gold words. Raw32 plus its outer cell costs33 slots,
// bounded by the old four-Gold <=37-slot allowance. Keep that conservative
// envelope, including its separately reserved control/container overhead.
const HONEST_SLOTS: usize = GOLD_BOUND * 9 + EXT_BOUND * 48 + 15_000 * 37 + 32_768;
const HONEST_PAYLOAD_BYTES: usize = GOLD_BOUND * 8 + EXT_BOUND * 40 + 15_000 * 32 + 3 * 32_768;

pub(in crate::gold) fn profile() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/CoreGold/closed-hash-formation-frame/v1/no-admission\0");
    hash.update(bfv_hiding_stark::hash::profile_digest());
    hash.update(native_wire::profile());
    hash.update(MAGIC);
    hash.update((DOMAIN.len() as u64).to_le_bytes());
    hash.update(DOMAIN);
    hash.update(b"public-PP=SHA512(DCS/hash-formation/PUBLIC-PP-ONLY/v1\\0,lenLE64(DOMAIN),DOMAIN,profile,Expected64,label)/first32/StdRng0.10.3");
    hash.update(b"same-AIR-PP-Prepared;raw32-digests;independent-public-PP/fresh-OS-private;canonical-Gold-EF5/bounded-Postcard/reencode/EOF;no-cached-verdict");
    for value in [
        HEADER_BYTES,
        MAX_FRAME_BYTES,
        MAX_SEQUENCE,
        MAX_SLOTS,
        CHUNKS,
        PACKED,
        AUX,
        H,
        WIDTH,
        PP_WIDTH,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    hash.finalize().into()
}

pub(super) fn require_assessment(assessment: &Assessment) -> Result<()> {
    // Original owner-derived AIR, packing, constraints and resource assessment.
    // The hash suite preserves its field, hiding degree and FRI parameters.
    native_wire::require_assessment(assessment)?;
    if !<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK
        || DEGREE_BITS != 12
        || INPUT_DEPTH != 15
        || HONEST_SLOTS > MAX_SLOTS
        || HONEST_PAYLOAD_BYTES > MAX_PAYLOAD_BYTES
    {
        return Err(Error::Security);
    }
    Ok(())
}

pub(super) fn payload<'a>(expected: &Expected, frame: &'a [u8]) -> Result<&'a [u8]> {
    payload_for(expected.binding(), frame)
}

fn payload_for(binding: [u8; 64], frame: &[u8]) -> Result<&[u8]> {
    if frame.len() < HEADER_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Resource);
    }
    if &frame[..8] != MAGIC || frame[108..HEADER_BYTES] != [0; 20] {
        return Err(Error::Encoding);
    }
    if frame[8..40] != profile() || frame[40..104] != binding {
        return Err(Error::Binding);
    }
    let size =
        u32::from_le_bytes(frame[104..108].try_into().map_err(|_| Error::Encoding)?) as usize;
    if size == 0 || size > MAX_PAYLOAD_BYTES || size.checked_add(HEADER_BYTES) != Some(frame.len())
    {
        return Err(Error::Encoding);
    }
    Ok(&frame[HEADER_BYTES..])
}

fn frame(binding: [u8; 64], bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    let mut output = Vec::with_capacity(HEADER_BYTES + bytes.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&profile());
    output.extend_from_slice(&binding);
    output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&[0; 20]);
    output.extend_from_slice(bytes);
    Ok(output)
}

pub(super) fn encode(
    expected: &Expected,
    proof: &BatchProof<Config>,
    assessment: &Assessment,
) -> Result<Vec<u8>> {
    check(proof, assessment)?;
    let bytes = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    frame(expected.binding(), &bytes)
}

pub(super) fn decode(bytes: &[u8], assessment: &Assessment) -> Result<BatchProof<Config>> {
    require_assessment(assessment)?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    // Pinned Gold Deserialize rejects noncanonical representatives in every
    // field/EF5 opening, salt and PoW. Digests remain all 256 arbitrary SHA bits.
    let (proof, trailing) = bounded_postcard::take_from_bytes::<BatchProof<Config>>(
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
    if !trailing.is_empty() {
        return Err(Error::Encoding);
    }
    check(&proof, assessment)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}

// These are finite shape checks only; actual verify_batch remains mandatory.
fn check(proof: &BatchProof<Config>, assessment: &Assessment) -> Result<()> {
    require_assessment(assessment)?;
    if proof.degree_bits != [DEGREE_BITS]
        || proof.opened_values.instances.len() != 1
        || proof.lookup_terminals.len() != 1
        || !proof.lookup_terminals[0]
            .as_ref()
            .is_some_and(|terminal| terminal.0 == Challenge::ZERO)
        || proof.lookup_pow_witness != Some(Val::ZERO)
        || proof.ood_pow_witness != Val::ZERO
        || proof.commitments.main.num_roots() != 1
        || proof.commitments.quotient_chunks.num_roots() != 1
        || proof
            .commitments
            .permutation
            .as_ref()
            .map(|cap| cap.num_roots())
            != Some(1)
        || proof.commitments.random.as_ref().map(|cap| cap.num_roots()) != Some(1)
    {
        return Err(Error::Shape);
    }
    let opened = &proof.opened_values.instances[0];
    let base = &opened.base_opened_values;
    if base.trace_local.len() != WIDTH
        || base.trace_next.as_ref().map(Vec::len) != Some(WIDTH)
        || base.preprocessed.as_ref().map(|values| values.local.len()) != Some(PP_WIDTH)
        || base
            .preprocessed
            .as_ref()
            .is_some_and(|values| values.next.is_some())
        || base.random.as_ref().map(Vec::len) != Some(5)
        || base.quotient_chunks.len() != CHUNKS
        || base.quotient_chunks.iter().any(|values| values.len() != 5)
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
        let masks = if round == 3 { 0 } else { 5 };
        if matrices.len() != count
            || matrices.iter().any(|matrix| {
                matrix.len() != points || matrix.iter().any(|values| values.len() != masks)
            })
        {
            return Err(Error::Shape);
        }
    }
    if fri.batch_pow_witness != Val::ZERO
        || fri.query_pow_witness != Val::ZERO
        || fri.commit_phase_commits.len() != DEGREE_BITS
        || fri
            .commit_phase_commits
            .iter()
            .any(|cap| cap.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != DEGREE_BITS
        || fri
            .commit_pow_witnesses
            .iter()
            .any(|&value| value != Val::ZERO)
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
            || opened.sibling_values.iter().any(|values| values.len() != 1)
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
            .all(|query| query.len() == matrices && query.iter().all(|row| row.len() == width))
}

fn frontier_bound(depth: usize) -> Result<usize> {
    if depth > INPUT_DEPTH {
        return Err(Error::Shape);
    }
    (0..depth).try_fold(0usize, |total, level| {
        let parents = 1usize
            .checked_shl((depth - level - 1) as u32)
            .ok_or(Error::Resource)?;
        total
            .checked_add(QUERIES.min(parents))
            .ok_or(Error::Resource)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField64;

    #[test]
    fn byte_digest_shape_fits_the_existing_caps_without_relabeling_the_original_profile() {
        assert_eq!((INPUT_DEPTH, DEGREE_BITS), (15, 12));
        assert_eq!(frontier_bound(INPUT_DEPTH).unwrap(), 1599);
        let folded: usize = (0..DEGREE_BITS)
            .map(|round| frontier_bound(INPUT_DEPTH - 1 - round).unwrap())
            .sum();
        assert_eq!(folded, 6060);
        const {
            assert!(HONEST_SLOTS < MAX_SLOTS);
            assert!(HONEST_PAYLOAD_BYTES < MAX_PAYLOAD_BYTES);
        };
        assert_ne!(profile(), native_wire::profile());
        assert_ne!(profile(), bfv_hiding_stark::hash::profile_digest());
        assert!(matches!(frontier_bound(INPUT_DEPTH + 1), Err(Error::Shape)));
    }

    #[test]
    fn raw_sha_digest_bits_remain_bytes_while_native_gold_fields_stay_canonical() {
        use p3_symmetric::MerkleCap;
        let cap: MerkleCap<Val, [u8; 32]> = MerkleCap::new(vec![[0xff; 32]]);
        let encoded = postcard::to_allocvec(&cap).unwrap();
        let limits = bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE,
            max_total_elements: MAX_SLOTS,
        };

        let (decoded, trailing) =
            bounded_postcard::take_from_bytes::<MerkleCap<Val, [u8; 32]>>(&encoded, limits)
                .unwrap();

        assert!(trailing.is_empty());
        assert_eq!(decoded.roots(), &[[0xff; 32]]);
        assert_eq!(postcard::to_allocvec(&decoded).unwrap(), encoded);
        for noncanonical in [Val::ORDER_U64, u64::MAX] {
            assert!(matches!(
                bounded_postcard::take_from_bytes::<Val>(&noncanonical.to_le_bytes(), limits),
                Err(bounded_postcard::Error::Encoding)
            ));
        }
    }

    #[test]
    fn complete_binding_and_new_family_identity_precede_any_native_payload_decode() {
        let binding = [0x41; 64];
        // Header-only unit fixture, deliberately not cryptographic evidence.
        let bytes = frame(binding, &[0x21, 0x22, 0x23]).unwrap();
        assert_eq!(payload_for(binding, &bytes).unwrap(), [0x21, 0x22, 0x23]);
        for index in [0, 31, 63] {
            let mut other = binding;
            other[index] ^= 1;
            assert!(matches!(payload_for(other, &bytes), Err(Error::Binding)));
        }
        for magic in [b"DCSGDD01", b"DCSGQF03", b"DCSGQF02", b"DCSGQF01"] {
            let mut old = bytes.clone();
            old[..8].copy_from_slice(magic);
            assert!(matches!(payload_for(binding, &old), Err(Error::Encoding)));
        }
        let mut other_profile = bytes.clone();
        other_profile[8] ^= 1;
        assert!(matches!(
            payload_for(binding, &other_profile),
            Err(Error::Binding)
        ));
    }

    #[test]
    fn short_trailing_truncated_reserved_and_inconsistent_length_frames_are_rejected() {
        let binding = [0x42; 64];
        let bytes = frame(binding, &[0x21, 0x22]).unwrap();
        assert!(matches!(
            payload_for(binding, &bytes[..127]),
            Err(Error::Resource)
        ));
        assert!(matches!(
            payload_for(binding, &bytes[..bytes.len() - 1]),
            Err(Error::Encoding)
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            payload_for(binding, &trailing),
            Err(Error::Encoding)
        ));
        for offset in [108, 127] {
            let mut reserved = bytes.clone();
            reserved[offset] = 1;
            assert!(matches!(
                payload_for(binding, &reserved),
                Err(Error::Encoding)
            ));
        }
        for size in [0, u32::MAX] {
            let mut malformed = bytes.clone();
            malformed[104..108].copy_from_slice(&size.to_le_bytes());
            assert!(matches!(
                payload_for(binding, &malformed),
                Err(Error::Encoding)
            ));
        }
        assert!(matches!(frame(binding, &[]), Err(Error::Resource)));
    }
}
