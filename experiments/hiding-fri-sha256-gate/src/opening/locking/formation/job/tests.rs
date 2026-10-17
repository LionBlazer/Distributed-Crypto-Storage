//! Owning examples: real prerequisite proofs, complete ciphertext arithmetic and TLS.
use super::{
    fixture::{Fixture, PublicPeer, SQL, plan_opening},
    *,
};
use crate::backend::{Backend, Val};
use crate::opening::{
    commitment,
    locking::{self, sql::CompiledLockPlan},
};
use p3_field::PrimeCharacteristicRing;
use std::cell::Cell;

fn compiled() -> CompiledLockPlan {
    CompiledLockPlan::compile(SQL, [0x81; 32]).unwrap()
}
fn expected(f: &Fixture, binding: Binding) -> Result<Expected> {
    f.expected_with_binding(binding)
}
fn no_job(
    f: &Fixture,
    parent: Option<returned::Evidence<'_, '_>>,
    p: &Prerequisites,
    proof: &Proof<Config>,
) {
    let handed_to_worker = Cell::new(false);
    let attempt = (|| {
        let job = prepare(&f.expected, parent, p, proof)?;
        handed_to_worker.set(true);
        Ok::<_, Error>(job)
    })();
    assert!(attempt.is_err());
    assert!(!handed_to_worker.get());
}
fn check_plain(f: &Fixture, checked: &VerifiedEncryptedProjection) {
    let decoded = f
        .client
        .decrypt_product_unverified(checked.canonical_output())
        .unwrap();
    let mut golden = vec![0u64; super::super::N];
    // The returned original is ordinal3. OFFSET-owned ordinal2 is NOT an answer.
    assert_eq!(
        f.formed.encoded.original(),
        [128, 0, 0, 0, 255, 0, 0, 0, 1, 0, 0, 0]
    );
    golden[4096] = 255;
    golden[512] = 1;
    assert_eq!(decoded, golden); // ALL8192 slots, including omitted age and zero tail.
    assert_eq!(
        checked.checked().operation(),
        Operation::PublicPolynomialProduct
    );
    assert_eq!(checked.identity(), f.expected.identity());
    assert!(!checked.encrypted_response().is_empty());
}

#[test]
fn compiler_binding_opens_the_existing144_fields_and_rejects_each_changed_client_field() {
    let c = compiled();
    let f = returned::fixture_for_compiled(&c).unwrap();
    let opening = plan_opening(&f);
    let plan = c.plan(opening.table, 0).unwrap();
    assert_eq!(
        locking::statement::plan_fields(&f.expected, &f.lock),
        locking::statement::plan_fields_opening(&f.expected, &plan, &opening)
    );
    let fields = locking::statement::plan_fields_opening(&f.expected, &plan, &opening);
    assert_eq!(fields.len(), 144);
    assert_eq!(fields[121], Val::from_u32(opening.transaction));
    assert_eq!(fields[130], Val::from_u32(opening.sequence));
    assert_eq!(fields[131], Val::from_u32(opening.revision));
    assert_eq!(
        &fields[132..137],
        &[
            Val::from_u8(4),
            Val::from_u8(2),
            Val::ONE,
            Val::ONE,
            Val::from_u8(2)
        ]
    );
    assert_eq!(&fields[137..141], &opening.salt);
    assert_eq!(&fields[141..], &[Val::ZERO; 3]);
    let bound = c.bind_returned(&f.encoding_expected, &opening).unwrap();
    assert_eq!(bound.request(), c.request());
    assert!(matches!(bound.projection(), RowProjection::Amount));
    for field in 0..6 {
        let mut changed = plan_opening(&f);
        match field {
            0 => changed.table[31] ^= 1,
            1 => changed.transaction += 1,
            2 => changed.controller[31] ^= 1,
            3 => changed.sequence += 1,
            4 => changed.revision += 1,
            _ => changed.salt[3] += Val::ONE,
        }
        assert!(
            c.bind_returned(&f.encoding_expected, &changed).is_err(),
            "field {field}"
        );
    }
    for sql in [
        SQL.replace("amount", "age"),
        SQL.replace("OFFSET 1", "OFFSET 0"),
        SQL.replace("LIMIT 1", "LIMIT 2"),
        SQL.replace("age>=128", "age>=255"),
        SQL.replace("FOR UPDATE", "FOR SHARE"),
        SQL.replace("SKIP LOCKED", "NOWAIT"),
    ] {
        let different = CompiledLockPlan::compile(&sql, [0x81; 32]).unwrap();
        assert!(
            different
                .bind_returned(&f.encoding_expected, &opening)
                .is_err()
        );
    }
    let mut invalid = plan_opening(&f);
    invalid.sequence = u32::MAX;
    assert!(c.bind_returned(&f.encoding_expected, &invalid).is_err());
}

#[test]
fn genuinely_valid_foreign_projection_plan_with_same_request_cannot_be_compiler_bound() {
    let c = compiled();
    let mut f = returned::fixture_for_compiled(&c).unwrap();
    let original_request = *f.expected.request();
    f.lock.plan.projection = 3; // Same request, a DIFFERENT valid private plan root.
    f.expected.plan = commitment::digest(&locking::statement::plan_fields(&f.expected, &f.lock));
    let (statement, proof) = locking::prove_composite(&f.expected, &f.source, &f.lock).unwrap();
    locking::verify_composite(&f.expected, &statement, &proof).unwrap();
    assert_eq!(*f.expected.request(), original_request);
    let producer = returned::statement::Expected::canonical(&f.expected, &statement).unwrap();
    assert!(c.bind_returned(&producer, &plan_opening(&f)).is_err());
    // An arbitrary supplied C_plan is not compiler provenance even with a genuine proof.
}

#[test]
fn independent_job_expectations_reject_full_request_parent_heads_setup_and_descriptor_mismatches() {
    let f = Fixture::new().unwrap();
    for field in 0..5 {
        let mut binding = f.expected.binding.clone();
        match field {
            0 => binding.request[31] ^= 1, // Upper16 changes; QueryId16 stays IDENTICAL.
            1 => binding.parent[31] ^= 1,
            2 => binding.setup_id[31] ^= 1,
            3 => binding.parameters.push(0),
            _ => {
                let t = &binding.target;
                binding.target = peer_runtime::TargetVersion::new(
                    [7; 32],
                    t.index_head().clone(),
                    t.data_head().clone(),
                )
                .unwrap();
            }
        }
        assert!(expected(&f, binding).is_err(), "binding field {field}");
    }
    let mut trailing_setup = f.expected.setup_bytes.clone();
    trailing_setup.push(0);
    let mut binding = f.expected.binding.clone();
    binding.setup_id = Sha256::digest(&trailing_setup).into();
    let query = compiled()
        .bind_returned(&f.source.encoding_expected, &plan_opening(&f.source))
        .unwrap();
    assert!(
        Expected::new(
            f.formed.statement.expected.clone(),
            f.formed.statement.clone(),
            binding,
            query,
            &trailing_setup
        )
        .is_err()
    );
    // Full opaque setup bytes define keyset identity; the parameter digest alone is not that ID.
    assert_ne!(
        f.expected.binding.setup_id,
        f.formed.statement.expected.bases[0]
            .expected
            .key()
            .expected
            .descriptor
            .public_setup_digest
    );
    assert_eq!(f.client.setup().to_bytes().unwrap(), f.expected.setup_bytes);
    assert_eq!(
        f.client
            .setup()
            .update_parameters()
            .unwrap()
            .to_bytes()
            .unwrap(),
        f.expected.binding.parameters
    );
}

#[test]
fn genuine_prerequisites_must_all_verify_before_any_ciphertext_job_is_handed_off() {
    let f = Fixture::new().unwrap();
    let (parent, mut p, proof) = f.prove().unwrap();
    no_job(&f, None, &p, &proof);
    let encoding = p.encoding.take();
    no_job(&f, Some(returned::Evidence::Canonical(&parent)), &p, &proof);
    p.encoding = encoding;
    let key = p.key.take();
    no_job(&f, Some(returned::Evidence::Canonical(&parent)), &p, &proof);
    p.key = key;
    let last = p.bases.pop().unwrap();
    no_job(&f, Some(returned::Evidence::Canonical(&parent)), &p, &proof);
    p.bases.push(last);
    p.bases.swap(0, 4);
    no_job(&f, Some(returned::Evidence::Canonical(&parent)), &p, &proof);
    p.bases.swap(0, 4);
    // A real independently valid foreign Key proof cannot replace the fixed anchor.
    let mut descriptor = f.formed.statement.expected.bases[0]
        .expected
        .key()
        .expected
        .descriptor
        .clone();
    descriptor.key_domain[15] ^= 1;
    let foreign = f.formed.key.statement(descriptor);
    let b = Backend::new(&foreign).unwrap();
    let foreign_proof = b
        .prove_with_trace(&foreign, || f.formed.key.trace(&foreign))
        .unwrap();
    b.verify(&foreign, &foreign_proof).unwrap();
    drop(b);
    let original = p.key.replace(foreign_proof);
    no_job(&f, Some(returned::Evidence::Canonical(&parent)), &p, &proof);
    p.key = original;
    let mut changed_statement = f.formed.statement.clone();
    changed_statement.noise[3] += Val::ONE;
    let query = compiled()
        .bind_returned(&f.source.encoding_expected, &plan_opening(&f.source))
        .unwrap();
    let changed = Expected::new(
        f.formed.statement.expected.clone(),
        changed_statement,
        f.expected.binding.clone(),
        query,
        &f.expected.setup_bytes,
    )
    .unwrap();
    assert!(
        prepare(
            &changed,
            Some(returned::Evidence::Canonical(&parent)),
            &p,
            &proof
        )
        .is_err()
    );
    // Restoring every genuine prerequisite permits a ciphertext-only worker.
    let job = prepare(
        &f.expected,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
        &proof,
    )
    .unwrap();
    let reply = execute_public(&job.parameters, &job.request).unwrap();
    let checked = job.finish(&f.expected, reply).unwrap();
    check_plain(&f, &checked);
}

#[test]
fn actual_tls_peer_uses_only_certified_ciphertext_and_rejects_replays_tampering_and_corrupt_custody()
 {
    let f = Fixture::new().unwrap();
    let (parent, p, proof) = f.prove().unwrap();
    let prepare_job = || {
        prepare(
            &f.expected,
            Some(returned::Evidence::Canonical(&parent)),
            &p,
            &proof,
        )
        .unwrap()
    };
    let job = prepare_job();
    // Real TLS starts ONLY after complete formation admission, with no client key/witness argument.
    let peer = PublicPeer::start(&f.bundle).unwrap();
    let checked = job.run_remote(&f.expected, &peer.remote).unwrap();
    check_plain(&f, &checked);
    let traces = peer.traces.lock().unwrap().clone();
    assert_eq!(
        traces
            .iter()
            .map(|t| t.operation.as_str())
            .collect::<Vec<_>>(),
        ["store", "public-setup", "fhe-proof"]
    );
    assert!(
        traces
            .iter()
            .all(|t| t.succeeded && t.request_bytes > 0 && t.response_bytes > 0)
    );
    assert!(traces.windows(2).all(|w| w[0].request_id < w[1].request_id));
    assert_eq!(
        peer.last_request_id().unwrap(),
        traces.last().unwrap().request_id
    );
    let count = traces.len();
    // Outer job identity includes transport-independent QueryId and nonce-derived ObjectID.
    for field in 0..2 {
        let mut binding = f.expected.binding.clone();
        if field == 0 {
            binding.query_id[15] ^= 1;
        } else {
            let t = &binding.target;
            binding.target = peer_runtime::TargetVersion::new(
                [9; 32],
                t.data_head().clone(),
                t.index_head().clone(),
            )
            .unwrap();
        }
        let different = expected(&f, binding).unwrap();
        assert!(prepare_job().run_remote(&different, &peer.remote).is_err());
        assert_eq!(peer.traces.lock().unwrap().len(), count); // No InstallSetup/Prove after mismatch.
    }
    let job = prepare_job();
    let evaluator = PublicUpdateEvaluator::from_parameters(&job.parameters).unwrap();
    let context = QueryContext::new(
        f.expected.binding.query_id,
        f.expected.binding.target.data_head().encode(),
        f.expected.binding.target.index_head().encode(),
    );
    let foreign_request = evaluator
        .encode_public_select(
            context,
            RowProjection::AgeAmount,
            f.formed.statement.expected.bases[0]
                .expected
                .ciphertext()
                .bytes(),
        )
        .unwrap();
    assert_ne!(foreign_request, job.request);
    let genuine_foreign_arithmetic = execute_public(&job.parameters, &foreign_request).unwrap();
    let foreign_canonical = evaluator.select_circuit_request(&foreign_request).unwrap();
    bfv_query_proof::verify(
        &foreign_canonical,
        &genuine_foreign_arithmetic.output,
        &genuine_foreign_arithmetic.proof,
    )
    .unwrap();
    // This proof is genuine, but for a different exact BFV wire/public operation.
    assert!(job.finish(&f.expected, genuine_foreign_arithmetic).is_err());
    // Independently valid public arithmetic on a genuinely fresh upstream CT
    // cannot replace the exact full CT certified by the formation chain either.
    let job = prepare_job();
    let (foreign, _, _) = crate::opening::basis_convolution::public_fixture_from_original(
        crate::opening::basis_convolution::PublicFixtureInput {
            original: f.formed.encoded.original(),
            descriptor: f.formed.statement.expected.bases[0]
                .expected
                .key()
                .expected
                .descriptor
                .clone(),
            request: f.expected.binding.request,
            caller_noise_seed: [0x46; 32],
        },
        [Val::ZERO; 4],
        [[Val::ONE; 4]; 2],
        0,
    )
    .unwrap();
    assert_ne!(
        foreign.expected.ciphertext().bytes(),
        f.formed.statement.expected.bases[0]
            .expected
            .ciphertext()
            .bytes()
    );
    let foreign_request = evaluator
        .encode_public_select(
            QueryContext::new(
                f.expected.binding.query_id,
                f.expected.binding.target.data_head().encode(),
                f.expected.binding.target.index_head().encode(),
            ),
            RowProjection::Amount,
            foreign.expected.ciphertext().bytes(),
        )
        .unwrap();
    let reply = execute_public(&job.parameters, &foreign_request).unwrap();
    let canonical = evaluator.select_circuit_request(&foreign_request).unwrap();
    bfv_query_proof::verify(&canonical, &reply.output, &reply.proof).unwrap();
    assert!(job.finish(&f.expected, reply).is_err());
    let job = prepare_job();
    let mut reply = execute_public(&job.parameters, &job.request).unwrap();
    bfv_query_proof::verify(&job.canonical, &reply.output, &reply.proof).unwrap();
    let last = reply.output.len() - 8;
    let value = u64::from_le_bytes(reply.output[last..].try_into().unwrap());
    let q = bfv_product_circuit::MODULI[4];
    reply.output[last..].copy_from_slice(&((value + 1) % q).to_le_bytes());
    assert!(job.finish(&f.expected, reply).is_err());
    let job = prepare_job();
    assert!(
        job.finish(
            &f.expected,
            ProofReply {
                output: job_output_echo(&f),
                proof: vec![]
            }
        )
        .is_err()
    );
    // No cached root/earlier successful job bypasses either complete physical image audit.
    peer.corrupt_index_tail(*f.expected.binding.target.object())
        .unwrap();
    assert!(prepare_job().run_remote(&f.expected, &peer.remote).is_err());
    assert!(!peer.traces.lock().unwrap().last().unwrap().succeeded);
}
fn job_output_echo(f: &Fixture) -> Vec<u8> {
    f.formed.statement.expected.bases[0]
        .expected
        .ciphertext()
        .bytes()
        .to_vec()
}
