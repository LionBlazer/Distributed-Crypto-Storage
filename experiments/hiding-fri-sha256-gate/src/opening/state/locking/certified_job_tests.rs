//! Actual certified producer through the NEW compiler capability and ciphertext job.
use super::*;
use crate::opening::locking::{
    encoding as returned,
    formation::{self, job},
    sql::CompiledLockPlan,
};
use crate::opening::selection::encoding::trace::Witness as EW;
use p3_field::PrimeCharacteristicRing;

#[test]
fn actual_state_lease_and_fresh_compiled_plan_reach_checked_ciphertext_projection() {
    let (state, source_proof, plain, salt) = {
        let (state, cold, plain, salt) = super::super::fixture().unwrap();
        let b = Backend::new(&state).unwrap();
        let proof = b
            .prove_with_trace(&state, || cold.trace(state.source()))
            .unwrap();
        (state, proof, plain, salt)
    };
    let mut cache = CertificateCache::new(super::super::CACHE_BYTES).unwrap();
    cache
        .admit(
            &state,
            Candidate::new(state.clone(), Some(source_proof)).unwrap(),
        )
        .unwrap();
    let charged = cache.owned_bytes();
    let lease = cache.lease(&state).unwrap();
    let compiled = CompiledLockPlan::compile(
        "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
        [0x82; 32],
    )
    .unwrap();
    let (mut expected, mut w) = sql_fixture(&state, plain, salt, &compiled, [0xB1; 32]).unwrap();
    w.old.tx[1].held[0] = 4;
    pin(&mut expected, &w);
    let lock = Statement::proposed(&expected, &w).unwrap();
    assert_ne!(*lock.source().expected.request(), state.source().request);
    assert_eq!(*lock.source().expected.request(), compiled.request());
    let lp = lease.prove_lock(&expected, &lock, &w).unwrap();
    let producer = returned::statement::Expected::certified(&expected, &lock).unwrap();
    let actor = &w.old.tx[usize::from(w.plan.actor)];
    let opening = locked::PlanOpening {
        table: w.plan.table,
        transaction: actor.id,
        controller: actor.controller,
        sequence: actor.sequence,
        revision: w.old.revision,
        salt: w.salts[2],
    };
    let bound = compiled.bind_returned(&producer, &opening).unwrap();
    assert_eq!(bound.request(), compiled.request());
    let ew = EW::from_lock(
        &returned::statement::Statement::new(producer.clone(), [Val::ZERO; 4]),
        &w,
        [Val::from_u8(0x62); 4],
    )
    .unwrap();
    assert_eq!(ew.original(), [128, 0, 0, 0, 255, 0, 0, 0, 1, 0, 0, 0]);
    let es = ew.returned_statement(producer.clone());
    let ep = returned::prove_with_trace(
        &producer,
        &es,
        Some(returned::Evidence::Certified {
            lease: &lease,
            proof: &lp,
        }),
        || ew.trace_returned(&es),
    )
    .unwrap();
    let (f, client) = job::fixture::form_returned_fixture(producer, es, ew).unwrap();
    let p = formation::prove_bases(&f, ep).unwrap();
    let s = &f.statement;
    let proof = formation::prove_with_trace(
        &s.expected,
        s,
        Some(returned::Evidence::Certified {
            lease: &lease,
            proof: &lp,
        }),
        &p,
        || f.local.trace_returned(s),
    )
    .unwrap();
    let raw = state.source();
    let image: [Vec<u8>; 2] = core::array::from_fn(|i| {
        raw.heads[i]
            .iter()
            .chain(&raw.packets[i])
            .copied()
            .collect()
    });
    let data =
        compact_store::EncryptedSnapshot::decode(&image[0], crate::opening::statement::limits())
            .unwrap();
    let index =
        compact_store::EncryptedSnapshot::decode(&image[1], crate::opening::statement::limits())
            .unwrap();
    let target = peer_runtime::RawBundle::from_snapshots(&data, &index)
        .unwrap()
        .target_version()
        .unwrap();
    let setup = client.setup().to_bytes().unwrap();
    let binding = job::Binding {
        request: compiled.request(),
        query_id: [0x22; 16],
        parent: lock.source().expected.parent,
        target,
        setup_id: Sha256::digest(&setup).into(),
        parameters: client
            .setup()
            .update_parameters()
            .unwrap()
            .to_bytes()
            .unwrap(),
    };
    let e = job::Expected::new(s.expected.clone(), s.clone(), binding, bound, &setup).unwrap();
    let prepared = job::prepare(
        &e,
        Some(returned::Evidence::Certified {
            lease: &lease,
            proof: &lp,
        }),
        &p,
        &proof,
    )
    .unwrap();
    // Worker receives only public descriptor/request through the same sealed job;
    // finish verifies the real arithmetic proof before client decryption.
    let verified = job::execute_prepared_public(prepared, &e).unwrap();
    let actual = client
        .decrypt_product_unverified(verified.canonical_output())
        .unwrap();
    let mut golden = vec![0u64; 8192];
    golden[4096] = 255;
    golden[512] = 1;
    assert_eq!(actual, golden);
    assert_eq!(
        verified.checked().operation(),
        bfv_query_proof::Operation::PublicPolynomialProduct
    );
    assert_eq!(cache.owned_bytes(), charged);
}
