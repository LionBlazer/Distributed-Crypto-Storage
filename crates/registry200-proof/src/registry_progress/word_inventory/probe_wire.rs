//! Canonical closed diagnostic proof frame. No decoded shape is an acceptance.
use super::{
    Metadata,
    assessment::Assessment,
    plan::{PP_WIDTH, WIDTH},
    probe::{self, DEGREE_BITS, Error, Result},
};
use bfv_hiding_stark::{Challenge, Config, LOG_BLOWUP, QUERIES, Val};
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"DCSWCW01";
pub(super) const HEADER_BYTES: usize = 128;
pub(super) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - HEADER_BYTES;
const MAX_SEQUENCE: usize = 4096;
const MAX_SLOTS: usize = 4 * 1024 * 1024;
const CHUNKS: usize = 8;
const PACKED: usize = 34;
const AUX: usize = 175;
const ROUNDS: usize = 5;
const INPUT_DEPTH: usize = DEGREE_BITS + LOG_BLOWUP;
// Complete fixed topology: 352810 Gold fields (INCLUDING digest coordinates,
// salts and PoWs),4934 EF5,9513 frontier digests. Conservative container reserve:
// every Gold <=9 bounded-serde slots, EF5<=48; remaining containers <=32768 slots.
// Fixed fields cost3019840 bytes, plus <=3 bytes per reserved container/control.
// These are codec bounds, not a whole-process memory/security theorem.
const HONEST_SLOTS: usize = 352_810 * 9 + 4_934 * 48 + 32_768;
const HONEST_PAYLOAD_BYTES: usize = 352_810 * 8 + 4_934 * 40 + 3 * 32_768;

pub(super) fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/word208/native-probe/canonical-frame/v1\0");
    h.update(super::profile());
    h.update(b"oneH512/MAIN568/PP708/PV0;extended10;default34/AUX175/chunks8;GoldEF5-Q192-blowup3-random5-salt4;MAIN2-PP2-AUX2/openings3012/hiding404;5rounds-random-main-quotient-PP-AUX;binaryFRI10;sole-terminal0+actualnative;PUBLIC-PP-only;freshOS-private;boundedPostcard-reencode-EOF;math-probe-NO-Source-DATA-head-SQL");
    for n in [
        HEADER_BYTES,
        MAX_FRAME_BYTES,
        MAX_SEQUENCE,
        MAX_SLOTS,
        CHUNKS,
        PACKED,
        AUX,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}
pub(super) fn require_assessment(report: &Assessment) -> Result<()> {
    if WIDTH != 568
        || PP_WIDTH != 708
        || DEGREE_BITS != 10
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || report.chunks() != CHUNKS
        || report.packed_lookup_count() != PACKED
        || report.aux_width() != AUX
        || report.openings() != 3012
        || HONEST_SLOTS > MAX_SLOTS
        || HONEST_PAYLOAD_BYTES > MAX_PAYLOAD_BYTES
    {
        return Err(Error::Security);
    }
    Ok(())
}
/// Independent complete public expectation BEFORE proof decoding or PP allocation.
pub(super) fn payload<'a>(m: &Metadata, frame: &'a [u8]) -> Result<&'a [u8]> {
    if frame.len() < HEADER_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Resource);
    }
    if &frame[..8] != MAGIC || frame[108..HEADER_BYTES] != [0; 20] {
        return Err(Error::Encoding);
    }
    if frame[8..40] != profile() || frame[40..104] != probe::binding(m) {
        return Err(Error::Binding);
    }
    let n = u32::from_le_bytes(frame[104..108].try_into().map_err(|_| Error::Encoding)?) as usize;
    if n == 0 || n > MAX_PAYLOAD_BYTES || n.checked_add(HEADER_BYTES) != Some(frame.len()) {
        return Err(Error::Encoding);
    }
    Ok(&frame[HEADER_BYTES..])
}
pub(super) fn frame(m: &Metadata, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&profile());
    out.extend_from_slice(&probe::binding(m));
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 20]);
    out.extend_from_slice(payload);
    Ok(out)
}
pub(super) fn encode(
    m: &Metadata,
    proof: &BatchProof<Config>,
    report: &Assessment,
) -> Result<Vec<u8>> {
    check(proof, report)?;
    let bytes = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    frame(m, &bytes)
}
pub(super) fn decode(bytes: &[u8], report: &Assessment) -> Result<BatchProof<Config>> {
    require_assessment(report)?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    let (proof, tail) = bounded_postcard::take_from_bytes::<BatchProof<Config>>(
        bytes,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE,
            max_total_elements: MAX_SLOTS,
        },
    )
    .map_err(|e| match e {
        bounded_postcard::Error::Encoding => Error::Encoding,
        bounded_postcard::Error::ResourceLimit => Error::Resource,
    })?;
    if !tail.is_empty() {
        return Err(Error::Encoding);
    }
    check(&proof, report)?;
    if postcard::to_allocvec(&proof).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}
/// Fixed shape only. verify() must independently reconstruct trusted PUBLIC PP
/// and execute native PCS/AIR/LogUp verification even after every check below.
pub(super) fn check(proof: &BatchProof<Config>, report: &Assessment) -> Result<()> {
    require_assessment(report)?;
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
        || base
            .preprocessed
            .as_ref()
            .and_then(|p| p.next.as_ref())
            .map(Vec::len)
            != Some(PP_WIDTH)
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
        let points = if matches!(round, 1 | 3 | 4) { 2 } else { 1 };
        let width = if round == 3 { 0 } else { 5 };
        if matrices.len() != count
            || matrices
                .iter()
                .any(|m| m.len() != points || m.iter().any(|v| v.len() != width))
        {
            return Err(Error::Shape);
        }
    }
    if fri.batch_pow_witness != Val::ZERO
        || fri.query_pow_witness != Val::ZERO
        || fri.commit_phase_commits.len() != DEGREE_BITS
        || fri.commit_phase_commits.iter().any(|c| c.num_roots() != 1)
        || fri.commit_pow_witnesses.len() != DEGREE_BITS
        || fri.commit_pow_witnesses.iter().any(|v| *v != Val::ZERO)
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
pub(super) fn frontier_bound(depth: usize) -> Result<usize> {
    if depth > INPUT_DEPTH {
        return Err(Error::Shape);
    }
    (0..depth).try_fold(0usize, |sum, level| {
        let p = 1usize
            .checked_shl((depth - level - 1) as u32)
            .ok_or(Error::Resource)?;
        sum.checked_add(QUERIES.min(p)).ok_or(Error::Resource)
    })
}
