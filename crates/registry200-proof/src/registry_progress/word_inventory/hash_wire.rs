//! Separate fixed SHA Predicate frame. Native success supplies no live admission.
use super::{
    Metadata,
    assessment::Assessment,
    plan::{PP_WIDTH, WIDTH},
    probe::{self, DEGREE_BITS, Error, Result},
    probe_wire::frontier_bound,
};
use bfv_hiding_stark::{Challenge, LOG_BLOWUP, QUERIES, Val, hash};
use hash::Config;
use p3_batch_stark::BatchProof;
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256, Sha512};

const MAGIC: &[u8; 8] = b"DCSWHS01";
pub(super) const HEADER_BYTES: usize = 128;
pub(in crate::registry_progress) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES - HEADER_BYTES;
const MAX_SEQUENCE: usize = 4096;
const MAX_SLOTS: usize = 4 * 1024 * 1024;
const CHUNKS: usize = 8;
const PACKED: usize = 34;
const AUX: usize = 175;
const ROUNDS: usize = 5;
const INPUT_DEPTH: usize = DEGREE_BITS + LOG_BLOWUP;
// Conservative original topology envelope:353962 Gold-equivalent fields
// (including old digest coordinates, salts and PoWs),4946 EF5,9513 frontier digests.
// Conservative container reserve:
// every Gold <=9 bounded-serde slots, EF5<=48; remaining containers <=32768 slots.
// Six additional PP columns add1152 query fields and12 EF openings; fixed fields cost3029536 bytes, plus <=3 bytes per reserved container/control.
// SHA digests replace four Gold coordinates (at most36 charged slots and32
// canonical bytes) with32 raw bytes/slots. The conservative old envelope still
// bounds this unchanged topology; it is not a process-memory/security theorem.
const HONEST_SLOTS: usize = 353_962 * 9 + 4_946 * 48 + 32_768;
const HONEST_PAYLOAD_BYTES: usize = 353_962 * 8 + 4_946 * 40 + 3 * 32_768;

pub(in crate::registry_progress) fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/word208/hash-suite/canonical-frame/v1\0");
    h.update(super::profile());
    h.update(hash::profile_digest());
    h.update(MAGIC);
    h.update(b"fixedPredicate/SHA256-digest32/SHA512-full-prefix/no-old-frame;oneH512/MAIN568/PP714/PV309;extended10;default34/AUX175/chunks8;GoldEF5-Q192-blowup3-random5-salt4;MAIN2-PP2-AUX2/openings3024/hiding404;5rounds-random-main-quotient-PP-AUX;binaryFRI10;sole-terminal0+actualnative;role-profile-only-PUBLIC-PP;independent-Expected309;freshOS-private;boundedPostcard-reencode-EOF;math-probe-NO-Source-DATA-head-SQL");
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

fn binding(metadata: &Metadata) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(b"DCS/research/word208/hash-suite/complete-expectation/v1\0");
    hash.update(profile());
    hash.update(probe::binding(metadata));
    hash.finalize().into()
}
pub(super) fn require_assessment(report: &Assessment) -> Result<()> {
    if WIDTH != 568
        || PP_WIDTH != 714
        || DEGREE_BITS != 10
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || report.chunks() != CHUNKS
        || report.packed_lookup_count() != PACKED
        || report.aux_width() != AUX
        || super::public_values::COUNT != 309
        || report.openings() != 3024
        || HONEST_SLOTS > MAX_SLOTS
        || HONEST_PAYLOAD_BYTES > MAX_PAYLOAD_BYTES
    {
        return Err(Error::Security);
    }
    Ok(())
}
/// Independent complete public expectation BEFORE proof decoding or PP allocation.
pub(super) fn payload<'a>(m: &Metadata, frame: &'a [u8]) -> Result<&'a [u8]> {
    if !m.predicate {
        return Err(Error::Binding);
    }
    if frame.len() < HEADER_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Resource);
    }
    if &frame[..8] != MAGIC || frame[108..HEADER_BYTES] != [0; 20] {
        return Err(Error::Encoding);
    }
    if frame[8..40] != profile() || frame[40..104] != binding(m) {
        return Err(Error::Binding);
    }
    let n = usize::try_from(u32::from_le_bytes(
        frame[104..108].try_into().map_err(|_| Error::Encoding)?,
    ))
    .map_err(|_| Error::Encoding)?;
    if n == 0 || n > MAX_PAYLOAD_BYTES || n.checked_add(HEADER_BYTES) != Some(frame.len()) {
        return Err(Error::Encoding);
    }
    Ok(&frame[HEADER_BYTES..])
}
pub(super) fn frame(m: &Metadata, payload: &[u8]) -> Result<Vec<u8>> {
    if !m.predicate {
        return Err(Error::Binding);
    }
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::Resource);
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&profile());
    out.extend_from_slice(&binding(m));
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| Error::Resource)?
            .to_le_bytes(),
    );
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_frame_checks_complete_binding_and_fixed_predicate_before_decode() {
        let metadata = Metadata::sample(true);
        let bytes = frame(&metadata, &[0]).unwrap();
        // Framing is deliberately not a proof-verification result.
        assert_eq!(payload(&metadata, &bytes).unwrap(), &[0]);
        assert_ne!(profile(), super::super::probe_wire::profile());
        let mutations: [fn(&mut Metadata); 6] = [
            |m| m.parent[0] += Val::ONE,
            |m| m.old[0] += Val::ONE,
            |m| m.result[0] += Val::ONE,
            |m| m.statement[0] += Val::ONE,
            |m| m.registry_header[0] += Val::ONE,
            |m| m.blind_sql[0] += Val::ONE,
        ];
        for mutate in mutations {
            let mut foreign = metadata.clone();
            mutate(&mut foreign);
            assert_eq!(payload(&foreign, &bytes), Err(Error::Binding));
        }
        let mut control = metadata.clone();
        control.predicate = false;
        assert_eq!(payload(&control, &bytes), Err(Error::Binding));
        assert_eq!(frame(&control, &[0]), Err(Error::Binding));
    }

    #[test]
    fn legacy_domains_reserved_bytes_lengths_and_budget_fail_before_native_setup() {
        let metadata = Metadata::sample(true);
        let bytes = frame(&metadata, &[0]).unwrap();
        for magic in [b"DCSWCW01", b"DCSWCW02"] {
            let mut old = bytes.clone();
            old[..8].copy_from_slice(magic);
            assert_eq!(payload(&metadata, &old), Err(Error::Encoding));
        }
        for (offset, error) in [
            (8, Error::Binding),
            (40, Error::Binding),
            (108, Error::Encoding),
        ] {
            let mut damaged = bytes.clone();
            damaged[offset] ^= 1;
            assert_eq!(payload(&metadata, &damaged), Err(error));
        }
        let mut zero = bytes.clone();
        zero[104..108].fill(0);
        assert_eq!(payload(&metadata, &zero), Err(Error::Encoding));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(payload(&metadata, &trailing), Err(Error::Encoding));
        assert_eq!(
            payload(&metadata, &bytes[..HEADER_BYTES]),
            Err(Error::Encoding)
        );
        assert_eq!(payload(&metadata, &[]), Err(Error::Resource));
        assert_eq!(frame(&metadata, &[]), Err(Error::Resource));
        assert_eq!(
            frame(&metadata, &vec![0; MAX_PAYLOAD_BYTES + 1]),
            Err(Error::Resource)
        );
    }

    #[test]
    fn malformed_payload_and_unbounded_sequence_reject_without_constructing_pp() {
        let report = super::super::hash_backend::assessed();
        for bytes in [&[0u8][..], &[0xff; 16][..]] {
            assert!(decode(bytes, &report).is_err());
        }
        assert!(matches!(decode(&[], &report), Err(Error::Resource)));
    }
}
