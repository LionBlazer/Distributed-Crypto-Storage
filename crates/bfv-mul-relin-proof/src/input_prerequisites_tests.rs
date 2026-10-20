//! One genuinely proved, bounded PUBLIC NONSECRET Input16 fixture.
use super::*;
use bfv_basis_convolution::Expected as BasisExpected;
use bfv_ciphertext_formation::{EncodedOpening, Expected as FormationExpected};
use bfv_query_core::{CoefficientRow, Geometry, KeyScope, OperandInput, Owner, QueryContext};
use p3_field::PrimeCharacteristicRing;
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        self as encoding,
        statement::{BfvBinding, Expected as EncodingExpected},
    },
    source,
};

struct Fixture {
    provenance: Provenance,
    frames: [Vec<u8>; INPUT_FRAMES],
    foreign_key: Vec<u8>,
    formations: [FormationExpected; 2],
}
impl Fixture {
    fn evidence(&self) -> InputEvidence<'_> {
        InputEvidence::from_frames(self.frames.each_ref().map(Vec::as_slice)).unwrap()
    }
}
fn fixture() -> Fixture {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: [0x42; 16],
                bfv_key_domain: [0x71; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let anchor = handle.public_anchor().clone();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    let mut frames: [Vec<u8>; INPUT_FRAMES] = core::array::from_fn(|_| Vec::new());
    frames[0] = epoch.prove_key().unwrap().as_bytes().to_vec();
    let key = setup.verify_key_transform(&anchor, &frames[0]).unwrap();
    let foreign_key = handle.prove().unwrap().into_bytes();

    let aead_key = [0x61; 32]; // Explicit public fixture key, never production custody.
    let store = compact_store::Owner::from_key([0x42; 16], [0x73; 16], aead_key.into());
    let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let stored = store
        .seal(
            compact_store::Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &data,
            source::statement::limits(),
        )
        .unwrap();
    let suffix: Vec<u8> = include_str!("../tests/fixtures/index-v3-four-row-suffix.hex")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|word| u8::from_str_radix(word, 16).unwrap())
        .collect();
    assert_eq!(suffix.len(), 2224);
    let mut index = stored.commitment().encode().to_vec();
    index.extend(suffix);
    let indexed = store
        .seal(
            compact_store::Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &index,
            source::statement::limits(),
        )
        .unwrap();
    let query = [0x83; 32];
    let mut claim = source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&stored.encode(), &indexed.encode()],
        [stored.commitment(), indexed.commitment()],
        query,
        source::statement::encode_digest(source::commitment::digest(
            &source::commitment::key_fields(&stored.commitment().encode(), aead_key, [Val::ONE; 4]),
        )),
        [0; 32],
    )
    .unwrap();
    let mut plain = data.to_vec();
    plain.extend_from_slice(&index);
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        [Val::TWO; 4],
        &plain,
    ));
    let canonical = CanonicalSource::checked_claim(&claim).unwrap();
    let source_frame = source::prove(
        &canonical,
        &source::circuit::Witness::new(aead_key, [Val::ONE; 4], [Val::TWO; 4], [255, 0, 255, 128]),
    )
    .unwrap();
    let binding = BfvBinding::new(anchor.full_setup_id(), key.statement().clone());
    let source_expected = EncodingExpected::source(&canonical, binding.clone()).unwrap();
    let source_witness =
        encoding::circuit::Witness::source(&source_expected, plain.into(), [2; 4], [3; 4]).unwrap();
    let mut mask = [0u8; 32];
    for age in [0usize, 128, 255] {
        mask[age / 8] |= 1 << (age % 8);
    }
    let draft = EncodingExpected::private_mask(
        &canonical,
        binding.clone(),
        [0x84; 32],
        [0x85; 32],
        [0; 32],
    )
    .unwrap();
    let command = encoding::commitment::command_digest(&encoding::commitment::command_fields(
        &draft,
        mask,
        [Val::from_u64(4); 4],
    ));
    let predicate_expected = EncodingExpected::private_mask(
        &canonical,
        binding,
        [0x84; 32],
        [0x85; 32],
        source::statement::encode_digest(command),
    )
    .unwrap();
    let predicate_witness =
        encoding::circuit::Witness::private_mask(&predicate_expected, mask.into(), [4; 4], [5; 4])
            .unwrap();
    let witnesses = [source_witness, predicate_witness];
    let statements: [EncodingStatement; 2] = core::array::from_fn(|i| {
        let expected = if i == 0 {
            &source_expected
        } else {
            &predicate_expected
        };
        let evidence = encoding::prove(expected, &witnesses[i], source_frame.as_bytes()).unwrap();
        let (statement, bytes) = evidence.into_parts();
        frames[1 + i] = bytes;
        statement
    });
    let rows: [CoefficientRow; 4] = core::array::from_fn(|i| CoefficientRow {
        age: data[3 * i],
        amount: u16::from_le_bytes([data[3 * i + 1], data[3 * i + 2]]),
    });
    let encrypted = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows)
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            QueryContext::new([0x86; 16], claim.heads[0], claim.heads[1]),
            query,
            &encrypted,
            &mask,
        )
        .unwrap();
    let ciphertexts = prepared.operand_ciphertexts().unwrap();
    let mut formations = Vec::with_capacity(2);
    for operand in 0..2 {
        let statement = &statements[operand];
        let commitment = EncodedCommitment::new(
            statement.producer_identity(),
            statement
                .expected
                .encoding_context()
                .map(|v| v.as_canonical_u64()),
            statement.encoded.map(|v| v.as_canonical_u64()),
        )
        .unwrap();
        let mut job = epoch
            .begin_operand(
                query,
                OperandInput {
                    ciphertext: ciphertexts[operand],
                    encoding: commitment.clone(),
                },
            )
            .unwrap();
        let mut bases = Vec::with_capacity(5);
        for basis in 0..5 {
            let at = 3 + 5 * operand + basis;
            frames[at] = job.prove_next_basis().unwrap().into_bytes();
            let expected = BasisExpected::new(
                key.statement().clone(),
                setup.relinearization_material().unwrap().parameters(),
                ciphertexts[operand],
                query,
                basis,
            )
            .unwrap();
            let checked = bfv_basis_convolution::verify_scoped(
                anchor.full_setup_id(),
                &key,
                &expected,
                &frames[at],
            )
            .unwrap();
            bases.push(checked.statement().clone());
        }
        let expected =
            FormationExpected::new(commitment.clone(), bases.try_into().ok().unwrap()).unwrap();
        job.begin_formation(
            EncodedOpening::new(
                witnesses[operand].coefficients(),
                [if operand == 0 { 3 } else { 5 }; 4],
                commitment,
            )
            .unwrap(),
        )
        .unwrap();
        frames[13 + operand] = job
            .prove_formation(
                &expected,
                core::array::from_fn(|i| frames[3 + 5 * operand + i].as_slice()),
            )
            .unwrap()
            .into_bytes();
        formations.push(expected);
    }
    let provenance = Provenance::new(
        setup.clone(),
        anchor,
        statements,
        ciphertexts.map(<[u8]>::to_vec),
    )
    .unwrap();
    drop(epoch);
    drop(handle);
    drop(owner);
    Fixture {
        provenance,
        frames,
        foreign_key,
        formations: formations.try_into().ok().unwrap(),
    }
}
fn rebind_formation(bytes: &[u8], setup: [u8; 32], expected: &FormationExpected) -> Vec<u8> {
    // Attack control: repair only canonical public labels, NEVER the genuine proof.
    let mut changed = bytes.to_vec();
    changed[40..72].copy_from_slice(&setup);
    changed[72..104].copy_from_slice(&expected.binding(setup));
    changed
}
fn different_inputs(
    original: &FormationExpected,
    key: &bfv_key_transform::Statement,
    ciphertext: &[u8],
    query: [u8; 32],
) -> FormationExpected {
    FormationExpected::new(
        original.encoding().clone(),
        core::array::from_fn(|i| bfv_basis_convolution::Statement {
            expected: BasisExpected::new(
                key.clone(),
                original.ciphertext().parameter_bytes(),
                ciphertext,
                query,
                i,
            )
            .unwrap(),
            result: original.bases()[i].result,
        }),
    )
    .unwrap()
}

#[test]
fn fresh_input16_borrows_exact_key_and_basis_prerequisites_without_accepting_foreign_scopes() {
    let f = fixture(); // ONE actual setup/Source/Key/two Encoding/ten Basis/two Formation.
    let p = &f.provenance;
    let evidence = f.evidence();
    assert_eq!(p.verify_inputs(&evidence), Ok(()));

    let key = p
        .setup()
        .verify_key_transform(p.anchor(), evidence.key)
        .unwrap();
    let foreign = p
        .setup()
        .verify_key_transform(p.anchor(), &f.foreign_key)
        .unwrap();
    assert_eq!(foreign.statement().expected, key.statement().expected);
    assert_ne!(foreign.statement().transformed, key.statement().transformed);
    let material = p.setup().relinearization_material().unwrap();
    let bases = p
        .verify_bases(0, material.parameters(), &key, &evidence)
        .unwrap();
    let setup = p.anchor().full_setup_id();
    assert!(
        bfv_basis_convolution::verify_scoped(
            setup,
            &foreign,
            &f.formations[0].bases()[0].expected,
            evidence.bases[0][0]
        )
        .is_err()
    );

    let expected = &f.formations[0];
    for different in [
        different_inputs(
            expected,
            key.statement(),
            expected.ciphertext().bytes(),
            [0x93; 32],
        ),
        different_inputs(
            expected,
            key.statement(),
            p.ciphertexts()[1].as_slice(),
            p.query(),
        ),
        different_inputs(
            expected,
            foreign.statement(),
            expected.ciphertext().bytes(),
            p.query(),
        ),
    ] {
        let repaired = rebind_formation(evidence.formations[0], setup, &different);
        assert!(
            bfv_ciphertext_formation::verify_scoped(setup, &different, bases.each_ref(), &repaired)
                .is_err()
        );
    }
    let mut parameters = material.parameters().to_vec();
    parameters[0] ^= 1;
    assert!(
        BasisExpected::new(
            key.statement().clone(),
            &parameters,
            expected.ciphertext().bytes(),
            p.query(),
            0
        )
        .is_err()
    );

    let mut reordered = bases.each_ref();
    reordered.swap(0, 4);
    assert!(
        bfv_ciphertext_formation::verify_scoped(setup, expected, reordered, evidence.formations[0])
            .is_err()
    );
    // Same exact proof/ALL33 but a distinct fresh transform object cannot be
    // mixed into the first scope. Without scope checking this genuine child
    // would satisfy all identical mathematical public claims.
    let second_key = p
        .setup()
        .verify_key_transform(p.anchor(), evidence.key)
        .unwrap();
    let second_basis = bfv_basis_convolution::verify_scoped(
        setup,
        &second_key,
        &expected.bases()[0].expected,
        evidence.bases[0][0],
    )
    .unwrap();
    let mut mixed = bases.each_ref();
    mixed[0] = &second_basis;
    assert!(
        bfv_ciphertext_formation::verify_scoped(setup, expected, mixed, evidence.formations[0])
            .is_err()
    );
    let wrong_setup = [0x94; 32];
    let repaired = rebind_formation(evidence.formations[0], wrong_setup, expected);
    assert!(
        bfv_ciphertext_formation::verify_scoped(wrong_setup, expected, bases.each_ref(), &repaired)
            .is_err()
    );

    let mut corrupt_formation = evidence.formations[0].to_vec();
    *corrupt_formation.last_mut().unwrap() ^= 1;
    assert!(
        bfv_ciphertext_formation::verify_scoped(
            setup,
            expected,
            bases.each_ref(),
            &corrupt_formation
        )
        .is_err()
    );
    drop(bases);
    let mut corrupt_basis = evidence.bases[0][0].to_vec();
    *corrupt_basis.last_mut().unwrap() ^= 1;
    let mut changed = f.frames.each_ref().map(Vec::as_slice);
    changed[3] = &corrupt_basis;
    let corrupt = InputEvidence::from_frames(changed).unwrap();
    assert_eq!(p.verify_inputs(&corrupt), Err(Error::InputVerification));
    // A prior success or failure cannot bless a later invocation's proof bytes.
    assert_eq!(p.verify_inputs(&corrupt), Err(Error::InputVerification));
}
