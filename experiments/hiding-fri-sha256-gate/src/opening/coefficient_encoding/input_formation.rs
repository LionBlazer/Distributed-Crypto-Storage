//! PUBLIC NONSECRET fixtures. Real input provenance, still no proved FHE output or SQL grant.
use super::{
    Statement, compiler::CompiledPrivatePredicate, fixture, prove_child_with_factory,
    require_complete,
};
use crate::backend::Backend;
use bfv_ciphertext_formation::{EncodedCommitment, Expected as FormationExpected, Prerequisites};
use bfv_query_core::{
    CoefficientRow, Geometry, KeyScope, Operand, OperandInput, Owner, PeerEvaluator, PublicSetup,
    QueryContext, TwoOperandStage,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{
    admission::CanonicalSource,
    coefficient_encoding::{statement::BfvBinding, wire},
};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

struct PublicFiles {
    path: PathBuf,
    parent: PathBuf,
    name: String,
}
impl PublicFiles {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("dcs-input-formation-public-{}-{stamp}", std::process::id());
        let path = parent.join(&name);
        fs::create_dir(&path).unwrap();
        let checked = fs::canonicalize(&path).unwrap();
        assert_eq!(checked, path);
        assert_eq!(checked.parent(), Some(parent.as_path()));
        assert_eq!(checked.file_name(), Some(std::ffi::OsStr::new(&name)));
        Self {
            path: checked,
            parent,
            name,
        }
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.path.join(name)).unwrap()
    }
    fn bytes(&self) -> u64 {
        fs::read_dir(&self.path)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum()
    }
}
impl Drop for PublicFiles {
    fn drop(&mut self) {
        if let Ok(path) = fs::canonicalize(&self.path)
            && path == self.path
            && path.parent() == Some(self.parent.as_path())
            && path.file_name() == Some(std::ffi::OsStr::new(&self.name))
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

/// Public labels from a complete verified statement; no private W/salt getter.
fn commitment(s: &Statement) -> EncodedCommitment {
    EncodedCommitment::new(
        s.producer_identity(),
        s.expected.encoding_context().map(|v| v.as_canonical_u64()),
        s.encoded.map(|v| v.as_canonical_u64()),
    )
    .unwrap()
}

#[test]
fn source_and_hidden_query_form_both_actual_fhe_inputs_under_one_key_and_reverify_after_private_drop()
 {
    let full = Instant::now();
    let files = PublicFiles::new();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let setup_bytes = setup.to_bytes().unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: [0x44; 16],
                bfv_key_domain: [0x71; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let anchor = handle.public_anchor().clone();
    let mut scope = handle.two_operand_scope(&setup).unwrap();
    let started = Instant::now();
    files.write("key", scope.prove_key().unwrap().as_bytes());
    let key_ms = started.elapsed().as_secs_f64() * 1000.;
    let key = setup
        .verify_key_transform(&anchor, scope.key_evidence().unwrap().as_bytes())
        .unwrap()
        .statement()
        .clone();
    let key_size = scope.key_evidence().unwrap().as_bytes().len();
    let binding = BfvBinding::new(anchor.full_setup_id(), key.clone());
    // This mask EXCLUDES both age255 originals. No selected-row fixture is encrypted.
    let sql = "SELECT age, amount FROM records WHERE age IN (0, 128)";
    let f = fixture::prepare(sql, [0xB1; 32], [0xA1; 32], binding.clone(), fixture::DATA).unwrap();
    let q = f.source_statement.request;
    let expected = [f.source.clone(), f.query.clone()];
    let started = Instant::now();
    let source_proof = {
        let b = Backend::new(&f.source_statement).unwrap();
        let p = b
            .prove_with_trace(&f.source_statement, || {
                f.source_witness.trace(&f.source_statement)
            })
            .unwrap();
        b.verify(&f.source_statement, &p).unwrap();
        p
    };
    let source_ms = started.elapsed().as_secs_f64() * 1000.;
    let source_bytes = wire::encode_source(&f.source_statement, &source_proof).unwrap();
    let source_size = source_bytes.len();
    let mut statements = Vec::new();
    let mut encoding_ms = [0.; 2];
    let mut pair_sizes = [0; 2];
    for (index, (e, w)) in [
        (&f.source, &f.source_encoding),
        (&f.query, &f.query_encoding),
    ]
    .into_iter()
    .enumerate()
    {
        let started = Instant::now();
        let s = w.statement(e);
        let proof = prove_child_with_factory(e, &s, Some(&source_proof), || w.trace(&s)).unwrap();
        let bytes = wire::encode_with_source(e, &s, &source_bytes, &proof).unwrap();
        drop(proof);
        let checked = wire::verify(e, &bytes).unwrap().statement().clone();
        require_complete(&s, &checked).unwrap();
        pair_sizes[index] = bytes.len();
        files.write(&format!("{index}-encoding-pair"), &bytes);
        statements.push(checked);
        encoding_ms[index] = started.elapsed().as_secs_f64() * 1000.;
    }
    drop(source_proof);
    drop(source_bytes);
    // Recompile only the SQL predicate, never rows. Independently check its complete binding.
    let compiled =
        CompiledPrivatePredicate::compile(sql, Zeroizing::new([0xB1; 32]), [0xA1; 32]).unwrap();
    let checked_source = CanonicalSource::checked_claim(&f.source_statement).unwrap();
    let (source_expected, query_expected, mask) = compiled
        .bind(
            &checked_source,
            binding,
            [crate::backend::Val::from_u8(23); 4],
        )
        .unwrap();
    expected[0].require_same(&source_expected).unwrap();
    expected[1].require_same(&query_expected).unwrap();
    let rows = core::array::from_fn::<_, 4, _>(|i| CoefficientRow {
        age: fixture::DATA[3 * i],
        amount: u16::from_le_bytes([fixture::DATA[3 * i + 1], fixture::DATA[3 * i + 2]]),
    });
    let source_ct = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows)
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            QueryContext::new(
                q[..16].try_into().unwrap(),
                f.source_statement.heads[0],
                f.source_statement.heads[1],
            ),
            q,
            &source_ct,
            &mask,
        )
        .unwrap();
    drop(mask);
    drop(compiled);
    drop(checked_source);
    drop(source_expected);
    drop(query_expected);
    let operands = prepared.operand_ciphertexts().unwrap();
    assert_eq!(operands[0], source_ct);
    let ciphertexts = operands.map(<[u8]>::to_vec);
    let statements: [Statement; 2] = statements.try_into().ok().unwrap();
    let metadata = statements.each_ref().map(commitment);
    scope
        .bind_operands(
            q,
            core::array::from_fn(|i| OperandInput {
                ciphertext: &ciphertexts[i],
                encoding: metadata[i].clone(),
            }),
        )
        .unwrap();
    let mut basis_sizes = [[0; 5]; 2];
    let mut basis_ms = [[0.; 5]; 2];
    let mut formation_sizes = [0; 2];
    let mut formation_ms = [0.; 2];
    for (index, operand) in [Operand::Input0, Operand::Input1].into_iter().enumerate() {
        let mut basis_statements = Vec::new();
        for basis in 0..5 {
            assert_eq!(scope.stage(), TwoOperandStage::Basis { operand, basis });
            let started = Instant::now();
            let evidence = scope.prove_next_basis().unwrap();
            let checked = setup
                .verify_basis_convolution(
                    &anchor,
                    q,
                    &ciphertexts[index],
                    basis,
                    scope.key_evidence().unwrap().as_bytes(),
                    evidence.as_bytes(),
                )
                .unwrap();
            assert_eq!(
                checked.statement().expected.key().public_values(),
                key.public_values()
            );
            basis_statements.push(checked.statement().clone());
            basis_sizes[index][basis] = evidence.as_bytes().len();
            files.write(&format!("{index}-basis-{basis}"), evidence.as_bytes());
            basis_ms[index][basis] = started.elapsed().as_secs_f64() * 1000.;
        }
        let formation = FormationExpected::new(
            metadata[index].clone(),
            basis_statements.try_into().ok().unwrap(),
        )
        .unwrap();
        // Correct proof under the other semantic role cannot replace this opening.
        let wrong = if index == 0 {
            &f.query_encoding
        } else {
            &f.source_encoding
        };
        assert!(
            scope
                .begin_formation(wrong.formation_opening(&statements[1 - index]).unwrap())
                .is_err()
        );
        assert_eq!(scope.stage(), TwoOperandStage::AwaitingFormation(operand));
        let witness = if index == 0 {
            &f.source_encoding
        } else {
            &f.query_encoding
        };
        scope
            .begin_formation(witness.formation_opening(&statements[index]).unwrap())
            .unwrap();
        let frames: [Vec<u8>; 5] =
            core::array::from_fn(|i| files.read(&format!("{index}-basis-{i}")));
        let started = Instant::now();
        let proof = scope
            .prove_formation(&formation, frames.each_ref().map(Vec::as_slice))
            .unwrap();
        formation_sizes[index] = proof.as_bytes().len();
        files.write(&format!("{index}-formation"), proof.as_bytes());
        formation_ms[index] = started.elapsed().as_secs_f64() * 1000.;
    }
    assert_eq!(scope.stage(), TwoOperandStage::Complete);
    // Real FHE on the SAME Prepared bytes. Decryption is a test oracle, not output verification.
    let evaluated = PeerEvaluator::from_public_setup(&setup)
        .unwrap()
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    assert_eq!(evaluated.ct_ct_multiplications, 1);
    let answer = owner
        .decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            &evaluated.output,
        )
        .unwrap();
    assert_eq!(
        answer.rows.iter().map(|r| r.present).collect::<Vec<_>>(),
        [false, true, false, true]
    );
    for (i, r) in answer.rows.iter().enumerate() {
        assert_eq!(r.ordinal, i as u8);
        assert_eq!(r.age, if r.present { rows[i].age } else { 0 });
        assert_eq!(r.amount, if r.present { rows[i].amount } else { 0 });
    }
    drop(evaluated);
    drop(statements);
    drop(f);
    drop(scope);
    drop(handle);
    drop(owner);
    drop(setup);
    // Fresh public verification constructs NEW Formation expectations from verified parents.
    let started = Instant::now();
    let fresh = PublicSetup::from_bytes(&setup_bytes).unwrap();
    let key_frame = files.read("key");
    let checked_key = fresh.verify_key_transform(&anchor, &key_frame).unwrap();
    assert_eq!(checked_key.statement().public_values(), key.public_values());
    let mut fresh_statements = Vec::new();
    for (index, e) in expected.iter().enumerate() {
        assert_eq!(e.bfv().full_setup(), anchor.full_setup_id());
        assert_eq!(
            e.bfv().key().public_values(),
            checked_key.statement().public_values()
        );
        let bytes = files.read(&format!("{index}-encoding-pair"));
        assert!(wire::verify(&expected[1 - index], &bytes).is_err());
        fresh_statements.push(wire::verify(e, &bytes).unwrap().statement().clone());
    }
    for index in 0..2 {
        let frames: [Vec<u8>; 5] =
            core::array::from_fn(|i| files.read(&format!("{index}-basis-{i}")));
        let bases = core::array::from_fn(|i| {
            fresh
                .verify_basis_convolution(
                    &anchor,
                    q,
                    &ciphertexts[index],
                    i,
                    &key_frame,
                    &frames[i],
                )
                .unwrap()
                .statement()
                .clone()
        });
        let formation =
            FormationExpected::new(commitment(&fresh_statements[index]), bases).unwrap();
        let proof = files.read(&format!("{index}-formation"));
        let parents = Prerequisites {
            key: &key_frame,
            bases: frames.each_ref().map(Vec::as_slice),
        };
        fresh
            .verify_ciphertext_formation(&anchor, &formation, &parents, &proof)
            .unwrap();
        let substituted = FormationExpected::new(
            commitment(&fresh_statements[1 - index]),
            formation.bases().clone(),
        )
        .unwrap();
        assert!(
            fresh
                .verify_ciphertext_formation(&anchor, &substituted, &parents, &proof)
                .is_err()
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "stage":"actual_source_query_two_input_formation", "primary_unique_proofs":16,
            "key_ms":key_ms,"source_prove_verify_ms":source_ms,"encoding_prove_pair_verify_ms":encoding_ms,
            "basis_prove_verify_ms":basis_ms,"formation_prove_ms":formation_ms,
            "fresh_public_verify_ms":started.elapsed().as_secs_f64()*1000.,"through_fresh_verify_ms":full.elapsed().as_secs_f64()*1000.,
            "key_bytes":key_size,"source_bytes":source_size,"encoding_pair_bytes":pair_sizes,
            "basis_bytes":basis_sizes,"formation_bytes":formation_sizes,"public_spool_bytes_with_duplicate_source":files.bytes(),
            "one_transport_frame":false,"output_mul_relin_proven":false,"fresh_agreed_head":false,"sql_grant":false,"composed_128_claim":false
        })
    );
}
