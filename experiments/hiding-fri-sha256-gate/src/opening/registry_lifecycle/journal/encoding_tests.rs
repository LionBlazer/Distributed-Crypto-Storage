//! Consumer integration: actual owner-signed accepted history, not a fixture authority token.
use super::super::{
    encoding,
    model::{Command, Operation},
    statement as lifecycle, wire,
};
use super::{
    fixture::{self, Fixture},
    owner::PrivateState,
    request::Request,
};
use crate::backend::Val;
use p3_field::PrimeCharacteristicRing;
use version_journal::{Body, Journal};

#[test]
fn accepted_signed_bootstrap_begin_acquire_binds_journal_intent_to_exact_sql_and_encoding() {
    let f = Fixture::new().unwrap();
    let verifier = f.verifier().unwrap();
    let mut journal = Journal::new(f.genesis.clone()).unwrap();
    let parent = journal.genesis_head();
    let boot = f.bootstrap(&journal, parent, [0xE1; 32]).unwrap();
    fixture::append(&mut journal, &verifier, parent.block, &boot.body, 1001).unwrap();
    let private = boot.private;
    drop(boot.body);
    let parent = journal.best_validated();
    let begin = f
        .transition(
            &journal,
            parent,
            &private,
            Command::control(Operation::Begin, 1, 1, 0),
            [0xE2; 32],
        )
        .unwrap();
    fixture::append(&mut journal, &verifier, parent.block, &begin.body, 1002).unwrap();
    let PrivateState { registry, salt } = begin.private;
    drop(begin.body);
    let mut c = Command::control(Operation::Acquire, 1, 1, 1);
    c.mask = [255; 32];
    c.mode = 4;
    c.wait = 2;
    c.limit = 1;
    c.projection = 2;
    let parent = journal.best_validated();
    let prepared = f
        .prepare(
            &journal,
            parent,
            &PrivateState { registry, salt },
            c,
            [0xE3; 32],
        )
        .unwrap();
    // Independently retained owner context BEFORE proof production and Journal admission.
    let (e, w) = prepared.encoding_inputs();
    let e = e.clone();
    let w = w.clone();
    let produced = prepared.prove(&f.genesis, &Fixture::owner()).unwrap();
    let Body::Transition(t) = &produced.body else {
        unreachable!()
    };
    let request = Request::decode(&t.request).unwrap();
    assert_eq!(request.query, e.source.request);
    let lifecycle::Phase::Transition { command, .. } = e.phase else {
        unreachable!()
    };
    assert_eq!(request.command, lifecycle::encoded(command));
    // The real Journal verifies owner signature, exact one-CAS transition and both real proofs.
    let header =
        fixture::append(&mut journal, &verifier, parent.block, &produced.body, 1003).unwrap();
    assert_eq!(journal.best_validated().block, header.id());
    let (s, pair) = wire::decode_and_verify(&e, &t.proof).unwrap();
    let compiled = encoding::CompiledQuery::compile(
        "SELECT amount FROM records WHERE age>=0 LIMIT 1 FOR UPDATE SKIP LOCKED",
        [0xE4; 32],
        request.query,
    )
    .unwrap();
    let bound = compiled
        .bind(
            &e,
            &s,
            encoding::CommandOpening {
                transaction: 1,
                principal: 1,
                controller: w.controllers[0],
                revision: w.old.revision,
                sequence: 1,
                salt: w.salts[3],
            },
        )
        .unwrap();
    let evidence = encoding::prove_and_encode(&bound, &w, &pair, [Val::from_u8(12); 4]).unwrap();
    drop(pair);
    drop(w);
    drop(produced);
    drop(journal);
    let _ = encoding::decode_and_verify(&bound, &evidence).unwrap();
    // This establishes local validated lineage only. No Freshness/global finality/SQL grant.
}
