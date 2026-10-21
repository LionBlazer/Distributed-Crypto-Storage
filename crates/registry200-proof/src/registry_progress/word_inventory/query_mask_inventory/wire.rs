//! New bounded canonical private mathematical frame; shape is never acceptance.
//! Uses the existing bounded-postcard decoder, not a copied parser implementation.
use super::{
    Expected,
    backend::{Error, Result},
    layout::*,
    security::Gate,
};
use bfv_hiding_stark::{Config, LOG_BLOWUP, QUERIES, Val};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};

const MAGIC: &[u8; 8] = b"DCSQME01";
pub(super) const HEADER_BYTES: usize = 128;
pub(super) const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_PAYLOAD: usize = MAX_FRAME - HEADER_BYTES;
const MAX_SEQUENCE: usize = 4096;
const MAX_SLOTS: usize = 4 * 1024 * 1024;
const DEGREE_BITS: usize = LOG_HEIGHT + 1;
const DEPTH: usize = DEGREE_BITS + LOG_BLOWUP;
const CHUNKS: usize = 8;
const ROUNDS: usize = 4;
// Complete fixed-topology upper envelope, not measured output/RSS:
// 210346 Gold (digests/salts/PoWs included),3560 EF5,10281 frontier digests.
// The same bounded-serde accounting as the existing Word frame: Gold<=9 slots,
// EF5<=48;32768 additional container/control slots,<=3 bytes per control.
const GOLD_FIELDS: usize = 210_346;
const EXT_FIELDS: usize = 3_560;
const CONTROL_RESERVE: usize = 32_768;
const HONEST_SLOTS: usize = GOLD_FIELDS * 9 + EXT_FIELDS * 48 + CONTROL_RESERVE;
const HONEST_PAYLOAD: usize = GOLD_FIELDS * 8 + EXT_FIELDS * 40 + 3 * CONTROL_RESERVE;

fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/QueryMaskEncoding/canonical-private-frame/v1\0");
    h.update(super::profile());
    h.update(b"DCSQME01;H1024-MAIN649-PP49-PUBLIC33;extended11;chunks8;noAUX-noLogUp-noLookupPow;GoldEF5-Q192-rate8-random5-salt4;MAIN2-PP1;openings1447;4rounds-random-main-quotient-PP;binaryFRI11;native-mandatory;independentPUBLICsetup;freshOS-private;boundedPostcard-EOF-reencode;no-QueryCt-Cs-request-freshness-SQL");
    for value in [
        HEADER_BYTES,
        MAX_FRAME,
        MAX_SEQUENCE,
        MAX_SLOTS,
        CHUNKS,
        GOLD_FIELDS,
        EXT_FIELDS,
        CONTROL_RESERVE,
    ] {
        h.update((value as u64).to_le_bytes());
    }
    h.finalize().into()
}
fn binding(expected: &Expected) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/research/QueryMaskEncoding/complete-independent-Expected33/v1\0");
    h.update(profile());
    for value in expected.values() {
        h.update(value.as_canonical_u64().to_le_bytes());
    }
    h.finalize().into()
}
pub(super) fn require_gate(gate: &Gate) -> Result<()> {
    gate.require_floor().map_err(|_| Error::Security)?;
    let input_frontiers = ROUNDS * frontier(DEPTH)?;
    let fold_frontiers = (0..DEGREE_BITS).try_fold(0usize, |sum, round| {
        Ok::<_, Error>(sum + frontier(DEPTH - 1 - round)?)
    })?;
    let gold_fields = QUERIES
        * (10 + WIDTH + 5 + CHUNKS * 10 + PP_WIDTH + 4 * (CHUNKS + 3) + 4 * DEGREE_BITS)
        + 4 * (input_frontiers + fold_frontiers)
        + 4 * (3 + DEGREE_BITS)
        + 3
        + DEGREE_BITS;
    let extension_fields = gate.metadata.openings + QUERIES * DEGREE_BITS + 1;
    if WIDTH != 649
        || PP_WIDTH != 49
        || super::PUBLIC_COUNT != 33
        || gate.metadata.chunks != CHUNKS
        || gate.metadata.extension != 0
        || gate.metadata.openings != 1447
        || DEGREE_BITS != 11
        || DEPTH != 14
        || gold_fields != GOLD_FIELDS
        || extension_fields != EXT_FIELDS
        || HONEST_SLOTS > MAX_SLOTS
        || HONEST_PAYLOAD > MAX_PAYLOAD
    {
        return Err(Error::Shape);
    }
    Ok(())
}
pub(super) fn payload<'a>(expected: &Expected, frame: &'a [u8]) -> Result<&'a [u8]> {
    if frame.len() < HEADER_BYTES || frame.len() > MAX_FRAME {
        return Err(Error::Resource);
    }
    if &frame[..8] != MAGIC || frame[108..HEADER_BYTES] != [0; 20] {
        return Err(Error::Encoding);
    }
    if frame[8..40] != profile() || frame[40..104] != binding(expected) {
        return Err(Error::Binding);
    }
    let length =
        u32::from_le_bytes(frame[104..108].try_into().map_err(|_| Error::Encoding)?) as usize;
    if length == 0 || length > MAX_PAYLOAD || length.checked_add(HEADER_BYTES) != Some(frame.len())
    {
        return Err(Error::Encoding);
    }
    Ok(&frame[HEADER_BYTES..])
}
pub(super) fn frame(expected: &Expected, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(Error::Resource);
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&profile());
    out.extend_from_slice(&binding(expected));
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(payload);
    Ok(out)
}
pub(super) fn encode(
    expected: &Expected,
    proof: &BatchProof<Config>,
    gate: &Gate,
) -> Result<Vec<u8>> {
    check(proof, gate)?;
    frame(
        expected,
        &postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?,
    )
}
pub(super) fn decode(bytes: &[u8], gate: &Gate) -> Result<BatchProof<Config>> {
    require_gate(gate)?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(Error::Resource);
    }
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
    check(&proof, gate)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}
/// Closed shape/resource check only. Every successful receiving still calls
/// verify_batch against freshly supplied Expected33 and independently owned PP.
pub(super) fn check(proof: &BatchProof<Config>, gate: &Gate) -> Result<()> {
    require_gate(gate)?;
    if proof.degree_bits != [DEGREE_BITS]
        || proof.opened_values.instances.len() != 1
        || proof.lookup_terminals.len() != 1
        || proof.lookup_terminals[0].is_some()
        || proof.lookup_pow_witness.is_some()
        || proof.ood_pow_witness != Val::ZERO
        || proof.commitments.main.num_roots() != 1
        || proof.commitments.quotient_chunks.num_roots() != 1
        || proof.commitments.permutation.is_some()
        || proof.commitments.random.as_ref().map(|c| c.num_roots()) != Some(1)
    {
        return Err(Error::Shape);
    }
    let opened = &proof.opened_values.instances[0];
    let base = &opened.base_opened_values;
    if base.trace_local.len() != WIDTH
        || base.trace_next.as_ref().map(Vec::len) != Some(WIDTH)
        || base.preprocessed.as_ref().map(|p| p.local.len()) != Some(PP_WIDTH)
        || base
            .preprocessed
            .as_ref()
            .and_then(|p| p.next.as_ref())
            .is_some()
        || base.random.as_ref().map(Vec::len) != Some(5)
        || base.quotient_chunks.len() != CHUNKS
        || base.quotient_chunks.iter().any(|chunk| chunk.len() != 5)
        || !opened.permutation_local.is_empty()
        || !opened.permutation_next.is_empty()
    {
        return Err(Error::Shape);
    }
    let (hidden, fri) = &proof.opening_proof;
    if hidden.len() != ROUNDS {
        return Err(Error::Shape);
    }
    for (round, matrices) in hidden.iter().enumerate() {
        let count = if round == 2 { CHUNKS } else { 1 };
        let points = if round == 1 { 2 } else { 1 };
        let width = if round == 3 { 0 } else { 5 };
        if matrices.len() != count
            || matrices.iter().any(|matrix| {
                matrix.len() != points || matrix.iter().any(|point| point.len() != width)
            })
        {
            return Err(Error::Shape);
        }
    }
    if fri.batch_pow_witness != Val::ZERO
        || fri.query_pow_witness != Val::ZERO
        || fri.commit_phase_commits.len() != DEGREE_BITS
        || fri.commit_phase_commits.iter().any(|c| c.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != DEGREE_BITS
        || fri
            .commit_pow_witnesses
            .iter()
            .any(|value| *value != Val::ZERO)
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
            _ => return Err(Error::Shape),
        };
        if !rows(&opened.opened_values, matrices, width)
            || !rows(&opened.opening_proof.0, matrices, 4)
            || opened.opening_proof.1.sibling_hashes.len() > frontier(DEPTH)?
        {
            return Err(Error::Shape);
        }
    }
    for (round, opened) in fri.commit_phase_openings.iter().enumerate() {
        if opened.sibling_values.len() != QUERIES
            || opened.sibling_values.iter().any(|value| value.len() != 1)
            || !rows(&opened.opening_proof.0, 1, 4)
            || opened.opening_proof.1.sibling_hashes.len() > frontier(DEPTH - 1 - round)?
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
fn frontier(depth: usize) -> Result<usize> {
    if depth > DEPTH {
        return Err(Error::Shape);
    }
    (0..depth).try_fold(0usize, |sum, level| {
        let nodes = 1usize
            .checked_shl((depth - level - 1) as u32)
            .ok_or(Error::Resource)?;
        sum.checked_add(QUERIES.min(nodes)).ok_or(Error::Resource)
    })
}
