//! NONSECRET encoding examples and genuine native proof rejection boundaries.
//! No example is a SQL answer, Source/DATA proof or accepted Word history.
use super::super::owner_cases::{self, Kind};
use super::{
    Expected,
    air::QueryMaskAir,
    backend::{self, Error},
    layout::*,
    security, wire, writer,
};
use bfv_hiding_stark::{Challenge, Val, poseidon};
use p3_field::PrimeCharacteristicRing;
use std::time::Instant;

struct Nonsecret {
    expected: Expected,
    statement: [Val; 96],
    mask: [u8; 32],
    salt: [Val; 4],
}
impl Nonsecret {
    fn opening(&self) -> writer::Opening {
        writer::Opening::checked(&self.expected, self.statement, self.mask, self.salt).unwrap()
    }
}
fn example(pattern: bool) -> Nonsecret {
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    if pattern {
        // Different nonsecret mask tests every reversed bit position. It is an
        // encoding example, not an assertion that this case's SQL outcome holds.
        case.input.mask = core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0xa7);
    }
    let statement: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
        .try_into()
        .expect("original owning Stmt96 serializer");
    let root = writer::digest(&statement).unwrap();
    if !pattern {
        assert_eq!(
            root, case.metadata.statement,
            "same original Word Stmt96 root"
        );
    }
    let context = [Val::from_u32(0x3159); 8];
    let salt = [Val::from_u32(0x7149); 4];
    let fields = vector_fields(context, salt, case.input.mask, None);
    let expected =
        Expected::checked(root, writer::digest(&fields).unwrap(), context, [0x49; 32]).unwrap();
    Nonsecret {
        expected,
        statement,
        mask: case.input.mask,
        salt,
    }
}
fn vector_fields(
    context: [Val; 8],
    salt: [Val; 4],
    mask: [u8; 32],
    high: Option<usize>,
) -> Vec<Val> {
    let mut fields = context
        .into_iter()
        .chain(salt)
        .chain([Val::ZERO; 4])
        .collect::<Vec<_>>();
    fields.extend((0..4096).map(|index| {
        if high == Some(index) {
            Val::ONE
        } else if index < 256 {
            let bit = 255 - index;
            Val::from_u8((mask[bit / 8] >> (bit % 8)) & 1) * Val::from_u64(SCALE)
        } else {
            Val::ZERO
        }
    }));
    fields
}
fn prepare(example: &Nonsecret) -> writer::PrivateTrace {
    writer::prepare(
        &QueryMaskAir::closed().unwrap(),
        &example.expected,
        &example.opening(),
    )
    .unwrap()
}

#[test]
fn complete_writer_opens_original_statement_and_every_reversed_or_zero_w_coefficient() {
    for pattern in [false, true] {
        let example = example(pattern);
        let trace = prepare(&example);
        backend::check_trace(&trace, &example.expected).expect("actual full native BASE equations");
        for word in 0..96 {
            assert_eq!(
                trace.0.values[(word / 8) * WIDTH + word % 8],
                example.statement[word]
            );
        }
        let words = vector_fields(example.expected.context, example.salt, example.mask, None);
        for coefficient in 0..4096 {
            let absorb = 14 + coefficient / 8;
            assert_eq!(
                trace.0.values[absorb * WIDTH + coefficient % 8],
                words[16 + coefficient]
            );
        }
        assert!(
            trace.0.values[ABSORBS * WIDTH..]
                .iter()
                .all(|value| *value == Val::ZERO)
        );
    }
}

#[test]
fn malformed_private_openings_fail_before_allocating_main() {
    let example = example(true);
    let mut statement = example.statement;
    statement[78] += Val::ONE;
    assert!(matches!(
        writer::Opening::checked(&example.expected, statement, example.mask, example.salt),
        Err(Error::Binding)
    ));
    let mut statement = example.statement;
    statement[95] = Val::ONE;
    assert!(matches!(
        writer::Opening::checked(&example.expected, statement, example.mask, example.salt),
        Err(Error::Shape)
    ));
    let mut salt = example.salt;
    salt[0] += Val::ONE;
    assert!(matches!(
        writer::Opening::checked(&example.expected, example.statement, example.mask, salt),
        Err(Error::Binding)
    ));
}

/// Repair every P2 witness/checkpoint/provider after a controlled wrong outcome.
/// Only unit diagnostics call this; the honest producer has no override path.
fn repair_hashes(trace: &mut writer::PrivateTrace, expected: &Expected, high: Option<usize>) {
    let plan = Plan::closed().unwrap();
    let mut checkpoint = [Val::ZERO; 12];
    for (index, absorb) in plan.rows.iter().copied().enumerate() {
        let row = &mut trace.0.values[index * WIDTH..(index + 1) * WIDTH];
        row[PUBLIC..].copy_from_slice(&expected.values());
        row[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(&checkpoint);
        let mut input = [Val::ZERO; 12];
        for (lane, value) in input[..8].iter_mut().enumerate() {
            *value = match absorb.field(lane) {
                Field::Statement(word) => row[STATEMENT + word],
                Field::Context(word) => expected.context[word],
                Field::VectorSalt(word) => row[VECTOR_SALT + word],
                Field::ScaledMask { bit, .. } => row[MASK + bit] * Val::from_u64(SCALE),
                Field::Zero => Val::ZERO,
            };
            if absorb.stream == Stream::Vector
                && high.is_some_and(|coefficient| 16 + coefficient == 8 * absorb.block + lane)
            {
                *value = Val::ONE;
            }
        }
        input[8..].copy_from_slice(&checkpoint[8..]);
        let output = poseidon::write(&mut row[..P2], input);
        checkpoint = if index == 11 || index == 525 {
            [Val::ZERO; 12]
        } else {
            output
        };
    }
}

#[test]
fn actual_air_rejects_repaired_mask_pack_boolean_reset_and_missing_absorb() {
    let example = example(true);
    let mut bad_statement = example.statement;
    bad_statement[78] += Val::ONE;
    let wrong = Expected::checked(
        writer::digest(&bad_statement).unwrap(),
        example.expected.vector,
        example.expected.context,
        example.expected.nonce,
    )
    .unwrap();
    let mut trace = prepare(&example);
    for row in 0..ABSORBS {
        trace.0.values[row * WIDTH + STATEMENT + 78] = bad_statement[78];
    }
    repair_hashes(&mut trace, &wrong, None);
    assert_eq!(
        backend::check_trace(&trace, &wrong),
        Err(Error::Proving),
        "hash repaired, mask packing still false"
    );

    let mut trace = prepare(&example);
    trace.0.values[MASK + 7] = Val::TWO;
    assert_eq!(
        backend::check_trace(&trace, &example.expected),
        Err(Error::Proving)
    );
    let mut trace = prepare(&example);
    trace.0.values[ABSORBS * WIDTH + STATEMENT + 20] = Val::ONE;
    assert_eq!(
        backend::check_trace(&trace, &example.expected),
        Err(Error::Proving),
        "private bank must reset"
    );
    let mut trace = prepare(&example);
    trace.0.values[525 * WIDTH..525 * WIDTH + P2].fill(Val::ZERO);
    assert_eq!(
        backend::check_trace(&trace, &example.expected),
        Err(Error::Proving),
        "last actual absorb cannot be omitted"
    );
}

#[test]
fn public_setup_has_identical_independently_reconstructed_identity() {
    use sha2::{Digest, Sha512};
    let first = backend::public_identity().unwrap();
    let second = backend::public_identity().unwrap();
    assert_eq!(
        first, second,
        "both fixed public factories, no Expected/witness input"
    );
    eprintln!(
        "query_mask_public_setup commitment_sha512={:x} private_MAIN=false proof=false admission=false",
        Sha512::digest(&first)
    );
}

#[test]
fn genuine_honest_proof_cold_verifies_and_repaired_foreign_header_or_ood_fails_native() {
    let example = example(false);
    let began = Instant::now();
    let producer = backend::ProverSetup::new().unwrap();
    let frame = producer
        .produce(&example.expected, example.opening())
        .expect("genuine fresh OS native proof");
    let produce = began.elapsed();
    let receive = Instant::now();
    backend::verify(&example.expected, &frame)
        .expect("cold independently built receiver PP + full native verify");
    let received = receive.elapsed();
    eprintln!(
        "query_mask_native produce_with_setup_ms={:.3} cold_receive_ms={:.3} roundtrip_ms={:.3} frame_bytes={} math_only=true QueryCt=false Cs=false Source=false DATA=false fresh_head=false SQL=false",
        produce.as_secs_f64() * 1000.0,
        received.as_secs_f64() * 1000.0,
        (produce + received).as_secs_f64() * 1000.0,
        frame.len()
    );
    assert!(frame.len() <= wire::MAX_FRAME);

    let receiver = backend::VerifierSetup::new().unwrap();
    let air = QueryMaskAir::closed().unwrap();
    let gate = security::assess(&air).unwrap();
    let payload = wire::payload(&example.expected, &frame).unwrap();
    let mut nonce = example.expected.nonce;
    nonce[0] ^= 1;
    let foreign = Expected::checked(
        example.expected.statement,
        example.expected.vector,
        example.expected.context,
        nonce,
    )
    .unwrap();
    let repaired = wire::frame(&foreign, payload).unwrap();
    wire::decode(wire::payload(&foreign, &repaired).unwrap(), &gate).unwrap();
    assert_eq!(
        receiver.verify(&foreign, &repaired),
        Err(Error::Verification)
    );
    let warm = Instant::now();
    let second = producer
        .produce(
            &foreign,
            writer::Opening::checked(&foreign, example.statement, example.mask, example.salt)
                .unwrap(),
        )
        .unwrap();
    let warm_produced = warm.elapsed();
    let warm = Instant::now();
    receiver
        .verify(&foreign, &second)
        .expect("distinct Expected, fresh OS proof, same public setups");
    let warm_received = warm.elapsed();
    assert_ne!(second, frame, "no private proof or verdict reused");
    eprintln!(
        "query_mask_native_warm produce_ms={:.3} receive_ms={:.3} roundtrip_ms={:.3} frame_bytes={} distinct_PUBLIC=true fresh_private_proof=true QueryCt=false Cs=false SQL=false",
        warm_produced.as_secs_f64() * 1000.0,
        warm_received.as_secs_f64() * 1000.0,
        (warm_produced + warm_received).as_secs_f64() * 1000.0,
        second.len()
    );

    let mut proof = wire::decode(payload, &gate).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let damaged = wire::encode(&example.expected, &proof, &gate).unwrap();
    assert_eq!(
        receiver.verify(&example.expected, &damaged),
        Err(Error::Verification)
    );
    assert_eq!(
        receiver.verify(&example.expected, &[]),
        Err(Error::Resource)
    );
    let mut trailing = payload.to_vec();
    trailing.push(0);
    assert_eq!(
        receiver.verify(
            &example.expected,
            &wire::frame(&example.expected, &trailing).unwrap()
        ),
        Err(Error::Encoding)
    );
    let mut legacy = frame.clone();
    legacy[..8].copy_from_slice(b"DCSWCW02");
    assert_eq!(
        receiver.verify(&example.expected, &legacy),
        Err(Error::Encoding)
    );

    let mut proof = wire::decode(payload, &gate).unwrap();
    proof.degree_bits = vec![11; 4097];
    let oversized = postcard::to_allocvec(&proof).unwrap();
    assert_eq!(
        receiver.verify(
            &example.expected,
            &wire::frame(&example.expected, &oversized).unwrap()
        ),
        Err(Error::Resource)
    );
    let mut proof = wire::decode(payload, &gate).unwrap();
    // Every individual length fits4096, but the one subtree alone charges
    // 240+240*128+240*128*16+240*128*16*8 =4,454,640 decoded slots.
    // Gold's canonical binary [u8;8] contributes the final term. Remove other
    // large fields so the complete frame fits the byte cap: Resource must come
    // from the shared decoder budget before the deliberately false shape.
    proof.opened_values.instances.clear();
    proof.opening_proof.0.clear();
    let fri = &mut proof.opening_proof.1;
    fri.commit_phase_commits.clear();
    fri.commit_pow_witnesses.clear();
    fri.commit_phase_openings.clear();
    fri.final_poly.clear();
    fri.input_openings.truncate(1);
    let input = &mut fri.input_openings[0];
    input.opening_proof.0.clear();
    input.opening_proof.1.sibling_hashes.clear();
    input.opened_values = vec![vec![vec![Val::ZERO; 16]; 128]; 240];
    let slots = input
        .opened_values
        .iter()
        .fold(input.opened_values.len(), |total, matrix| {
            total + matrix.len() + matrix.iter().map(|row| row.len() * 9).sum::<usize>()
        });
    assert_eq!(slots, 4_454_640);
    assert!(slots > 4 * 1024 * 1024);
    let oversized = postcard::to_allocvec(&proof).unwrap();
    let oversized = wire::frame(&example.expected, &oversized).unwrap();
    assert!(oversized.len() <= wire::MAX_FRAME);
    assert_eq!(
        receiver.verify(&example.expected, &oversized),
        Err(Error::Resource)
    );
    receiver
        .verify(&example.expected, &frame)
        .expect("restored honest proof still natively verifies");
}

#[test]
fn fully_repaired_high_w_tail_false_main_is_rejected_by_the_native_verifier() {
    let example = example(true);
    let fields = vector_fields(
        example.expected.context,
        example.salt,
        example.mask,
        Some(256),
    );
    let wrong = Expected::checked(
        example.expected.statement,
        writer::digest(&fields).unwrap(),
        example.expected.context,
        example.expected.nonce,
    )
    .unwrap();
    let mut trace = prepare(&example);
    repair_hashes(&mut trace, &wrong, Some(256));
    assert_eq!(
        trace.0.values[46 * WIDTH],
        Val::ONE,
        "first forbidden high coefficient"
    );
    assert_eq!(backend::check_trace(&trace, &wrong), Err(Error::Proving));
    let producer = backend::ProverSetup::new().unwrap();
    let frame = producer
        .prove_negative_trace(&wrong, &trace)
        .expect("release native prover, same fixed AIR and a fresh genuine false-input proof");
    let receiver = backend::VerifierSetup::new().unwrap();
    assert_eq!(
        receiver.verify(&wrong, &frame),
        Err(Error::Verification),
        "all hash paths/root/PUBLIC repaired; mandatory native AIR verification rejects false high W"
    );
}
