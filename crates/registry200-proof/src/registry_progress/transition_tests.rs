//! Genuine math proofs and explicit PUBLIC NONSECRET inputs. No FHE/SQL/finality.
use super::super::{
    transition_fields::{self, Fields},
    transition_layout::*,
};
use super::*;
use crate::{
    coefficient_encoding::{
        self as enc,
        statement::{BfvBinding, Expected as QueryExpected},
    },
    lifecycle::circuit::model::{Command, Operation, Registry, Savepoint, Transaction},
    registry_progress::{
        self as progress,
        bootstrap::tests::{Fixture, expected as bootstrap_expected, fixture},
        circuit::{State, StatementOpening, Status},
    },
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroizing;
const CONTROLLERS: [[u8; 32]; 2] = [[0x41; 32], [0x42; 32]];
fn binding() -> BfvBinding {
    // Public mathematical Key33/setup labels. Actual Key/Formation/full FHE and
    // setup custody remain independent application prerequisites, not simulated.
    let witness =
        bfv_key_transform::ProverWitness::new(Zeroizing::new(vec![0; 8192]), [11; 4], [12; 4])
            .unwrap();
    BfvBinding::new(
        [0x53; 32],
        witness.statement(bfv_key_transform::SetupDescriptor {
            database: [0x42; 16],
            key_domain: [0x71; 16],
            public_setup_digest: [0x95; 32],
            key_epoch: 1,
        }),
    )
}
fn query(
    source: &CanonicalSource,
    source_bytes: &[u8],
    mask: [u8; 32],
    id: u8,
    nonce: u8,
    salt: u64,
) -> (enc::statement::Statement, Vec<u8>) {
    let binding = binding();
    let draft =
        QueryExpected::private_mask(source, binding.clone(), [id; 32], [nonce; 32], [0; 32])
            .unwrap();
    let cmask = enc::commitment::command_digest(&enc::commitment::command_fields(
        &draft,
        mask,
        [Val::from_u64(salt); 4],
    ));
    let expected = QueryExpected::private_mask(
        source,
        binding,
        [id; 32],
        [nonce; 32],
        source::statement::encode_digest(cmask),
    )
    .unwrap();
    let w =
        enc::circuit::Witness::private_mask(&expected, Zeroizing::new(mask), [salt; 4], [71; 4])
            .unwrap();
    let proof = enc::prove(&expected, &w, source_bytes).unwrap();
    let (s, bytes) = proof.into_parts();
    drop(w);
    // The typed producer self-verifies; the new role freshly verifies this
    // exact pair at its own independent proof boundary below.
    (s, bytes)
}
fn fresh_source(f: &Fixture, q: u8, salt: u64) -> (CanonicalSource, Vec<u8>) {
    let mut claim = f.source.claim().clone();
    claim.request = [q; 32];
    claim.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
        &claim,
        [Val::from_u64(salt); 4],
        &f.plain,
    ));
    let source = CanonicalSource::checked_claim(&claim).unwrap();
    let w = source::circuit::Witness::new(
        [0x71; 32],
        [Val::ONE; 4],
        [Val::from_u64(salt); 4],
        [0, 1, 128, 255],
    );
    let bytes = source::prove(&source, &w).unwrap().into_bytes();
    (source, bytes)
}
fn control_expected(
    f: &Fixture,
    source: &CanonicalSource,
    state: &State,
    c: &Command,
    parent: u8,
    old_salt: u64,
    cmd_salt: u64,
) -> Expected {
    let boot = bootstrap_expected(f);
    let draft = Expected::control(
        source,
        boot.genesis(),
        [parent; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let old = source::statement::encode_digest(
        state
            .root(
                draft.registry_context(),
                &f.plain,
                &CONTROLLERS,
                [old_salt; 4],
            )
            .unwrap(),
    );
    let mut e = Expected::control(
        source,
        boot.genesis(),
        [parent; 32],
        source::statement::encode_digest(boot.enrollment()),
        old,
        [0; 32],
    )
    .unwrap();
    e.command = source::statement::decode_digest(
        command_commitment(&e, c, state.registry.revision, &CONTROLLERS, [cmd_salt; 4]).unwrap(),
    )
    .unwrap();
    e
}
#[expect(
    clippy::too_many_arguments,
    reason = "Keep independent public Source and each private commitment salt visible in the owning proof fixture."
)]
fn control(
    f: &Fixture,
    source: &CanonicalSource,
    source_bytes: &[u8],
    state: &State,
    c: Command,
    parent: u8,
    old_salt: u64,
    new_salt: u64,
    source_salt: u64,
) -> (State, Statement) {
    let independent_command = c.clone();
    let e = control_expected(f, source, state, &c, parent, old_salt, 41);
    let next = state.control(&c, [parent; 32]).unwrap();
    let w = Witness::control(
        &e,
        Zeroizing::new(f.plain),
        Zeroizing::new(CONTROLLERS),
        Zeroizing::new(state.clone()),
        Zeroizing::new(c),
        Zeroizing::new([
            [source_salt; 4],
            [3; 4],
            [old_salt; 4],
            [41; 4],
            [new_salt; 4],
            [42; 4],
        ]),
    )
    .unwrap();
    let p = Prerequisites {
        source: source_bytes,
        query: None,
    };
    let evidence = prove(&e, &w, &p).unwrap();
    let (s, bytes) = evidence.into_parts();
    let verified = verify(&e, &s, &p, &bytes).unwrap();
    assert_eq!(verified.statement().values(), s.values());
    let previous = state
        .registry
        .transactions
        .iter()
        .position(|tx| tx.id == independent_command.transaction)
        .and_then(|actor| state.progress[actor].as_ref());
    let context = progress::control_result_opening::ControlOpeningContext::new(
        &e,
        &independent_command,
        state.registry.revision,
        &CONTROLLERS,
        &[41; 4],
        previous,
    )
    .unwrap();
    let opened = progress::control_result_opening::ControlResultOpening::open(
        &verified,
        w.result_opening_fields().unwrap(),
        &context,
    )
    .unwrap();
    assert_eq!(opened.operation(), independent_command.operation);
    assert_eq!(opened.transaction(), independent_command.transaction);
    assert_eq!(
        opened.old_registry_root(),
        source::statement::encode_digest(e.old)
    );
    assert_eq!(opened.next_registry_root(), s.next());
    assert_eq!(
        opened.previous_progress_root(),
        previous.map_or([0; 32], |p| source::statement::encode_digest(
            p.root().unwrap()
        ))
    );
    assert_eq!(opened.next_progress_root(), [0; 32]);
    let aborted = independent_command.operation == Operation::End
        && (independent_command.abort
            || state
                .registry
                .transactions
                .iter()
                .any(|tx| tx.id == independent_command.transaction && tx.failed));
    assert_eq!(
        opened.status(),
        if aborted {
            progress::control_result_opening::ControlStatus::Aborted
        } else {
            progress::control_result_opening::ControlStatus::Applied
        }
    );
    if independent_command.operation == Operation::Begin && independent_command.transaction == 1 {
        assert_control_result_corruptions(&verified, &w, &context);
        for kind in 0..4 {
            let mut wrong = independent_command.clone();
            match kind {
                0 => wrong.transaction += 1,
                1 => wrong.principal = 3 - wrong.principal,
                2 => wrong.sequence += 1,
                _ => wrong.abort = true,
            }
            assert!(
                progress::control_result_opening::ControlOpeningContext::new(
                    &e,
                    &wrong,
                    state.registry.revision,
                    &CONTROLLERS,
                    &[41; 4],
                    None,
                )
                .is_err()
            );
        }
        assert!(
            progress::control_result_opening::ControlOpeningContext::new(
                &e,
                &independent_command,
                state.registry.revision + 1,
                &CONTROLLERS,
                &[41; 4],
                None,
            )
            .is_err()
        );
        assert!(
            progress::control_result_opening::ControlOpeningContext::new(
                &e,
                &independent_command,
                state.registry.revision,
                &CONTROLLERS,
                &[40; 4],
                None,
            )
            .is_err()
        );
        let mut foreign_controllers = CONTROLLERS;
        foreign_controllers[usize::from(independent_command.principal - 1)][0] ^= 1;
        assert!(
            progress::control_result_opening::ControlOpeningContext::new(
                &e,
                &independent_command,
                state.registry.revision,
                &foreign_controllers,
                &[41; 4],
                None,
            )
            .is_err()
        );
        let mut foreign = e.clone();
        foreign.base.parent[0] ^= 1;
        foreign.command = super::super::fields::digest(
            &super::super::transition_trace::command_fields(
                &foreign,
                &independent_command,
                state.registry.revision,
                &CONTROLLERS,
                [Val::from_u8(41); 4],
            )
            .unwrap(),
        );
        let foreign_context = progress::control_result_opening::ControlOpeningContext::new(
            &foreign,
            &independent_command,
            state.registry.revision,
            &CONTROLLERS,
            &[41; 4],
            None,
        )
        .unwrap();
        assert!(
            progress::control_result_opening::ControlResultOpening::open(
                &verified,
                w.result_opening_fields().unwrap(),
                &foreign_context,
            )
            .is_err()
        );
    }
    if let Some(previous) = previous {
        let mut foreign = previous.clone();
        foreign.statement.invocation[0] ^= 1;
        let foreign_context = progress::control_result_opening::ControlOpeningContext::new(
            &e,
            &independent_command,
            state.registry.revision,
            &CONTROLLERS,
            &[41; 4],
            Some(&foreign),
        )
        .unwrap();
        assert!(
            progress::control_result_opening::ControlResultOpening::open(
                &verified,
                w.result_opening_fields().unwrap(),
                &foreign_context,
            )
            .is_err()
        );
        let absent = progress::control_result_opening::ControlOpeningContext::new(
            &e,
            &independent_command,
            state.registry.revision,
            &CONTROLLERS,
            &[41; 4],
            None,
        )
        .unwrap();
        assert!(
            progress::control_result_opening::ControlResultOpening::open(
                &verified,
                w.result_opening_fields().unwrap(),
                &absent,
            )
            .is_err()
        );
    }
    // An actual verified Control proof and its genuine Result160 preimage cannot
    // enter the predicate-only API. The unrelated placeholder opens no claim.
    let unrelated = StatementOpening {
        scope: e.statement_scope(),
        enrollment: e.base.enrollment.map(|v| v.as_canonical_u64()),
        client: [1; 32],
        call: 1,
        transaction: 1,
        principal: 1,
        controller: CONTROLLERS[0],
        invocation: [1; 32],
        sql_identity: [1; 32],
        snapshot: [1; 32],
        mask: [0; 32],
        mode: 4,
        wait: 0,
        offset: 0,
        limit: 4,
        projection: 1,
        salt: [73; 4],
    };
    assert!(matches!(
        progress::result_opening::ResultOpening::open(
            &verified,
            w.result_opening_fields().unwrap(),
            &unrelated,
            None,
            None,
        ),
        Err(Error::Shape)
    ));
    drop(w);
    assert_eq!(
        s.next,
        next.root(e.registry_context(), &f.plain, &CONTROLLERS, [new_salt; 4])
            .unwrap()
    );
    (next, s)
}
fn hidden(
    e: &Expected,
    state: &State,
    id: u64,
    mask: [u8; 32],
    wait: u8,
    offset: u8,
    limit: u8,
) -> StatementOpening {
    let tx = state
        .registry
        .transactions
        .iter()
        .find(|t| t.id == id)
        .unwrap();
    StatementOpening {
        scope: e.statement_scope(),
        enrollment: e.base.enrollment.map(|v| v.as_canonical_u64()),
        client: [id as u8; 32],
        call: 1,
        transaction: id,
        principal: tx.principal,
        controller: CONTROLLERS[usize::from(tx.principal - 1)],
        invocation: [0x91; 32],
        sql_identity: e.query().unwrap().expected.sql_identity(),
        snapshot: tx.snapshot,
        mask,
        mode: 4,
        wait,
        offset,
        limit,
        projection: 1,
        salt: [73; 4],
    }
}
fn predicate_expected(
    f: &Fixture,
    query: &enc::statement::Statement,
    state: &State,
    s: &StatementOpening,
    parent: u8,
    old_salt: u64,
) -> Expected {
    let boot = bootstrap_expected(f);
    let draft = Expected::predicate(
        query,
        boot.genesis(),
        [parent; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let old = source::statement::encode_digest(
        state
            .root(
                draft.registry_context(),
                &f.plain,
                &CONTROLLERS,
                [old_salt; 4],
            )
            .unwrap(),
    );
    let mut e = Expected::predicate(
        query,
        boot.genesis(),
        [parent; 32],
        source::statement::encode_digest(boot.enrollment()),
        old,
        [0; 32],
    )
    .unwrap();
    let actor = state
        .registry
        .transactions
        .iter()
        .find(|t| t.id == s.transaction)
        .unwrap();
    let mut c = Command::control(
        Operation::Acquire,
        s.transaction,
        s.principal,
        actor.sequence,
    );
    c.mask = s.mask;
    c.mode = s.mode;
    c.wait = s.wait;
    c.offset = s.offset;
    c.limit = s.limit;
    c.projection = s.projection;
    e.command = source::statement::decode_digest(
        command_commitment(&e, &c, state.registry.revision, &CONTROLLERS, [41; 4]).unwrap(),
    )
    .unwrap();
    e
}
#[expect(
    clippy::too_many_arguments,
    reason = "Keep independent Source, registry and Encoding salts explicit at this owning proof boundary."
)]
fn predicate_witness(
    f: &Fixture,
    e: &Expected,
    state: &State,
    s: StatementOpening,
    old_salt: u64,
    new_salt: u64,
    source_salt: u64,
    mask_salt: u64,
) -> Witness {
    Witness::predicate(
        e,
        Zeroizing::new(f.plain),
        Zeroizing::new(CONTROLLERS),
        Zeroizing::new(state.clone()),
        Zeroizing::new(s),
        Zeroizing::new([
            [source_salt; 4],
            [3; 4],
            [old_salt; 4],
            [41; 4],
            [new_salt; 4],
            [42; 4],
            [74; 4],
            [mask_salt; 4],
        ]),
    )
    .unwrap()
}
fn accept(e: &Expected, w: &Witness, source: &[u8], query: &[u8]) -> Statement {
    accept_with_result_checks(e, w, source, query, false)
}
fn accept_with_result_checks(
    e: &Expected,
    w: &Witness,
    source: &[u8],
    query: &[u8],
    corruptions: bool,
) -> Statement {
    let p = Prerequisites {
        source,
        query: Some(query),
    };
    let evidence = prove(e, w, &p).unwrap();
    let (s, bytes) = evidence.into_parts();
    let verified = verify(e, &s, &p, &bytes).unwrap();
    assert_eq!(verified.statement().values(), s.values());
    assert_private_result_opening(&verified, w, corruptions);
    s
}
// All corruptions reuse one actual Control proof and its exact producer builder.
fn assert_control_result_corruptions(
    verified: &VerifiedStep,
    witness: &Witness,
    context: &progress::control_result_opening::ControlOpeningContext<'_>,
) {
    let fields = witness.result_opening_fields().unwrap();
    for at in 0..progress::RESULT_FIELDS {
        let mut changed = Zeroizing::new(*fields);
        changed[at] = (changed[at] + 1) % Val::ORDER_U64;
        assert!(
            progress::control_result_opening::ControlResultOpening::open(
                verified, changed, context,
            )
            .is_err(),
            "modified Control field {at}"
        );
        let mut alias = Zeroizing::new(*fields);
        alias[at] = Val::ORDER_U64;
        assert!(
            matches!(
                progress::control_result_opening::ControlResultOpening::open(
                    verified, alias, context,
                ),
                Err(Error::Encoding)
            ),
            "noncanonical Control field {at}"
        );
    }
}
fn assert_predicate_rejects_control_opening(verified: &VerifiedStep, witness: &Witness) {
    let current = verified.statement().expected();
    let source = CanonicalSource::checked_claim(current.source()).unwrap();
    let mut expected = Expected::control(
        &source,
        current.base.genesis,
        current.base.parent,
        source::statement::encode_digest(current.base.enrollment),
        source::statement::encode_digest(current.old),
        [0; 32],
    )
    .unwrap();
    let command = Command::control(Operation::Begin, 1, 1, 0);
    expected.command = super::super::fields::digest(
        &super::super::transition_trace::command_fields(
            &expected,
            &command,
            0,
            &CONTROLLERS,
            [Val::from_u8(41); 4],
        )
        .unwrap(),
    );
    let context = progress::control_result_opening::ControlOpeningContext::new(
        &expected,
        &command,
        0,
        &CONTROLLERS,
        &[41; 4],
        None,
    )
    .unwrap();
    assert!(matches!(
        progress::control_result_opening::ControlResultOpening::open(
            verified,
            witness.result_opening_fields().unwrap(),
            &context,
        ),
        Err(Error::Shape)
    ));
}
// Reuse the SAME actual verified proof and captured private witness. These
// checks add no proving, fixture setup, product simulation, or SQL acceptance.
fn assert_private_result_opening(verified: &VerifiedStep, w: &Witness, corruptions: bool) {
    assert_predicate_rejects_control_opening(verified, w);
    use progress::result_opening::ResultOpening;
    let inputs = w.result_opening_inputs_for_test().unwrap();
    let raw = w.result_opening_fields().unwrap();
    let opened = ResultOpening::open(
        verified,
        Zeroizing::new(*raw),
        inputs.original,
        inputs.previous,
        inputs.parked,
    )
    .unwrap();
    let step = inputs.step;
    assert!(opened.status() == step.status);
    assert_eq!(opened.resumed(), step.resumed);
    assert_eq!(opened.transaction(), inputs.original.transaction);
    assert_eq!(opened.call(), inputs.original.call);
    assert_eq!(opened.microstep(), step.microstep);
    assert_eq!(opened.old_cursor(), step.old_cursor);
    assert_eq!(opened.cursor(), step.cursor);
    assert_eq!(opened.visited(), step.visited);
    assert_eq!(opened.selected(), step.selected);
    assert_eq!(
        opened.old_registry_root(),
        source::statement::encode_digest(verified.statement().expected.old)
    );
    assert_eq!(opened.next_registry_root(), verified.statement().next());
    assert_eq!(
        opened.statement_root(),
        source::statement::encode_digest(inputs.original.root().unwrap())
    );
    assert_eq!(
        opened.previous_progress_root(),
        inputs
            .previous
            .map(|p| source::statement::encode_digest(p.root().unwrap()))
    );
    assert_eq!(
        opened.parked_progress_root(),
        inputs
            .parked
            .map(|p| source::statement::encode_digest(p.root().unwrap()))
    );
    match opened.blocked() {
        Some(blocked) => {
            assert_eq!(blocked.ordinal(), step.cursor);
            assert_eq!(blocked.transaction(), step.holder);
            assert_eq!(blocked.mode(), step.holder_mode);
        }
        None => assert_eq!(step.block, [false; 4]),
    }
    if let Some(previous) = inputs.previous {
        assert!(
            ResultOpening::open(
                verified,
                Zeroizing::new(*raw),
                inputs.original,
                None,
                inputs.parked
            )
            .is_err()
        );
        let mut changed = previous.clone();
        changed.salt[0] ^= 1;
        assert!(
            ResultOpening::open(
                verified,
                Zeroizing::new(*raw),
                inputs.original,
                Some(&changed),
                inputs.parked
            )
            .is_err()
        );
    }
    if let Some(parked) = inputs.parked {
        assert!(
            ResultOpening::open(
                verified,
                Zeroizing::new(*raw),
                inputs.original,
                inputs.previous,
                None
            )
            .is_err()
        );
        let mut changed = parked.clone();
        changed.salt[0] ^= 1;
        assert!(
            ResultOpening::open(
                verified,
                Zeroizing::new(*raw),
                inputs.original,
                inputs.previous,
                Some(&changed)
            )
            .is_err()
        );
    }
    if !corruptions {
        return;
    }
    // Every canonical word, including all context/root/salt/padding words, is
    // commitment-bound. Modular aliases must fail before field conversion.
    for at in 0..160 {
        let mut changed = Zeroizing::new(*raw);
        changed[at] = u64::from(changed[at] == 0);
        assert!(
            ResultOpening::open(
                verified,
                changed,
                inputs.original,
                inputs.previous,
                inputs.parked
            )
            .is_err(),
            "unbound Result160 word {at}"
        );
        let mut alias = Zeroizing::new(*raw);
        alias[at] = Val::ORDER_U64;
        assert!(
            matches!(
                ResultOpening::open(
                    verified,
                    alias,
                    inputs.original,
                    inputs.previous,
                    inputs.parked
                ),
                Err(Error::Encoding)
            ),
            "field alias {at}"
        );
    }
    for at in [119, 120, 143, 144, 146, 147, 148, 149] {
        let mut changed = Zeroizing::new(*raw);
        changed[at] = 1u64 << 32;
        assert!(
            matches!(
                ResultOpening::open(
                    verified,
                    changed,
                    inputs.original,
                    inputs.previous,
                    inputs.parked
                ),
                Err(Error::Shape)
            ),
            "wide integer limb {at}"
        );
    }
    for at in [123, 127, 131] {
        let mut changed = Zeroizing::new(*raw);
        changed[at] = 2;
        assert!(
            matches!(
                ResultOpening::open(
                    verified,
                    changed,
                    inputs.original,
                    inputs.previous,
                    inputs.parked
                ),
                Err(Error::Shape)
            ),
            "nonboolean flag {at}"
        );
    }
    let mut changed = inputs.original.clone();
    changed.invocation[0] ^= 1;
    assert!(
        ResultOpening::open(
            verified,
            Zeroizing::new(*raw),
            &changed,
            inputs.previous,
            inputs.parked
        )
        .is_err()
    );
    let mut changed = inputs.original.clone();
    changed.scope[0] ^= 1;
    assert!(
        ResultOpening::open(
            verified,
            Zeroizing::new(*raw),
            &changed,
            inputs.previous,
            inputs.parked
        )
        .is_err()
    );
    let mut bad_salt = Zeroizing::new(*raw);
    bad_salt[150] ^= 1;
    assert!(matches!(
        ResultOpening::open(
            verified,
            bad_salt,
            inputs.original,
            inputs.previous,
            inputs.parked
        ),
        Err(Error::Verification)
    ));
}

#[test]
fn genuine_source_encoding_wait_prefix_end_compaction_and_fresh_blind_resume() {
    let f = fixture();
    let boot = bootstrap_expected(f);
    let boot_w = progress::BootstrapWitness::new(
        &boot,
        Zeroizing::new(f.plain),
        Zeroizing::new(CONTROLLERS),
        Zeroizing::new([[2; 4], [3; 4], [6; 4]]),
    )
    .unwrap();
    let boot_proof = progress::prove_bootstrap(&boot, &boot_w, &f.source_bytes).unwrap();
    progress::verify_bootstrap(
        &boot,
        boot_proof.statement(),
        &f.source_bytes,
        boot_proof.as_bytes(),
    )
    .unwrap();
    let (empty, a) = (
        State::default(),
        Command::control(Operation::Begin, 1, 1, 0),
    );
    let (a, begin_a) = control(f, &f.source, &f.source_bytes, &empty, a, 0xc1, 6, 7, 2);
    assert_eq!(begin_a.expected.old, boot_w.statement().next);
    let (b, begin_b) = control(
        f,
        &f.source,
        &f.source_bytes,
        &a,
        Command::control(Operation::Begin, 2, 2, 0),
        0xc2,
        7,
        8,
        2,
    );
    assert_eq!(begin_b.expected.old, begin_a.next);
    let mut mask_a = [0; 32];
    mask_a[31] = 0x80;
    let (qa, qa_bytes) = query(&f.source, &f.source_bytes, mask_a, 0xa1, 0xa2, 30);
    let draft = Expected::predicate(
        &qa,
        boot.genesis(),
        [0xc3; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let sa = hidden(&draft, &b, 1, mask_a, 2, 0, 1);
    let ea = predicate_expected(f, &qa, &b, &sa, 0xc3, 8);
    let wa = predicate_witness(f, &ea, &b, sa.clone(), 8, 9, 2, 30);
    let proof_a = accept_with_result_checks(&ea, &wa, &f.source_bytes, &qa_bytes, true);
    let after_a = b.predicate(&sa, [0, 1, 128, 255], [74; 4]).unwrap().next;
    assert_eq!(after_a.registry.transactions[0].held, [0, 0, 0, 4]);
    let mut mask_b = mask_a;
    mask_b[0] = 1;
    let (qb, qb_bytes) = query(&f.source, &f.source_bytes, mask_b, 0xb1, 0xb2, 31);
    let draft = Expected::predicate(
        &qb,
        boot.genesis(),
        [0xc4; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let sb = hidden(&draft, &after_a, 2, mask_b, 0, 1, 1);
    let eb = predicate_expected(f, &qb, &after_a, &sb, 0xc4, 9);
    assert_eq!(eb.old, proof_a.next);
    let wb = predicate_witness(f, &eb, &after_a, sb.clone(), 9, 10, 2, 31);
    let parked_proof = accept(&eb, &wb, &f.source_bytes, &qb_bytes);
    let parked = after_a.predicate(&sb, [0, 1, 128, 255], [74; 4]).unwrap();
    assert!(parked.status == Status::Parked);
    assert_eq!(parked.next.registry.transactions[1].held, [4, 0, 0, 0]);
    assert_eq!(parked.selected, [false; 4]);
    assert_eq!(parked.cursor, 3);
    let progress_root = parked.next.progress[1].as_ref().unwrap().root().unwrap();
    // One additional genuine Control proof, reusing the SAME existing Source.
    // The supported parked actor EndAbort proves status3 and its old Progress.
    // This branch does not replace the unchanged normal End/resume chain below.
    let mut abort_parked = Command::control(
        Operation::End,
        2,
        2,
        parked.next.registry.transactions[1].sequence,
    );
    abort_parked.abort = true;
    let (aborted, _) = control(
        f,
        &f.source,
        &f.source_bytes,
        &parked.next,
        abort_parked,
        0xca,
        10,
        11,
        2,
    );
    assert_eq!(aborted.registry.transactions.len(), 1);
    assert!(aborted.progress.iter().all(Option::is_none));
    let ended_id = parked.next.registry.transactions[0].id;
    let ended_seq = parked.next.registry.transactions[0].sequence;
    let (carried, end_proof) = control(
        f,
        &f.source,
        &f.source_bytes,
        &parked.next,
        Command::control(Operation::End, ended_id, 1, ended_seq),
        0xc5,
        10,
        11,
        2,
    );
    assert_eq!(end_proof.expected.old, parked_proof.next);
    assert_eq!(carried.registry.transactions[0].id, 2);
    assert_eq!(
        carried.progress[0].as_ref().unwrap().root().unwrap(),
        progress_root
    );
    let (resume_source, resume_source_bytes) = fresh_source(f, 0x85, 21);
    let (qr, qr_bytes) = query(&resume_source, &resume_source_bytes, mask_b, 0xd1, 0xd2, 32);
    assert_ne!(qr.expected.sql_identity(), qb.expected.sql_identity());
    assert_ne!(qr.expected.public_nonce(), qb.expected.public_nonce());
    assert_ne!(
        qr.expected.source_claim().request,
        qb.expected.source_claim().request
    );
    let er = predicate_expected(f, &qr, &carried, &sb, 0xc6, 11);
    assert_eq!(er.old, end_proof.next);
    assert_eq!(er.statement_scope(), eb.statement_scope());
    let wr = predicate_witness(f, &er, &carried, sb.clone(), 11, 12, 21, 32);
    let resumed = accept(&er, &wr, &resume_source_bytes, &qr_bytes);
    let done = carried.predicate(&sb, [0, 1, 128, 255], [74; 4]).unwrap();
    assert!(done.status == Status::Done);
    assert_eq!(done.selected, [false, false, false, true]);
    assert_eq!(done.next.registry.transactions[0].held, [4, 0, 0, 4]);
    assert!(done.next.progress[0].is_none());
    assert_eq!(
        resumed.next,
        done.next
            .root(er.registry_context(), &f.plain, &CONTROLLERS, [12; 4])
            .unwrap()
    );
    let missing = Prerequisites {
        source: &resume_source_bytes,
        query: None,
    };
    assert!(matches!(
        prove(&er, &wr, &missing),
        Err(Error::Prerequisite)
    ));
    let foreign = Prerequisites {
        source: &resume_source_bytes,
        query: Some(&qb_bytes),
    };
    assert!(matches!(
        prove(&er, &wr, &foreign),
        Err(Error::Prerequisite)
    ));
}

fn conditional_state() -> State {
    State {
        registry: Registry {
            revision: 2,
            allocator: 2,
            transactions: vec![
                Transaction {
                    id: 1,
                    principal: 1,
                    sequence: 1,
                    failed: false,
                    snapshot: [0xc1; 32],
                    held: [0, 0, 0, 4],
                    savepoints: vec![],
                },
                Transaction {
                    id: 2,
                    principal: 2,
                    sequence: 1,
                    failed: false,
                    snapshot: [0xc2; 32],
                    held: [0; 4],
                    savepoints: vec![],
                },
            ],
        },
        progress: [None, None],
    }
}
fn reject_raw(s: &Statement, trace: RowMajorMatrix<Val>) {
    let backend = Backend::new(s).unwrap();
    if let Ok(Ok(proof)) = catch_unwind(AssertUnwindSafe(|| backend.prove(trace))) {
        assert!(
            backend.verify(&proof).is_err(),
            "false progress AIR accepted repaired roots"
        );
    }
}
/// Rebuild all native hash gadgets, all intermediate roots and the result root.
/// Independent old-state commitments stay unchanged unless an attack explicitly
/// tests canonical opening constraints under a separately declared old claim.
fn repair(s: &mut Statement, trace: &mut RowMajorMatrix<Val>, repair_old: bool) {
    for _ in 0..4 {
        let fields = Fields::new(s);
        let row = &trace.values[..TRACE_WIDTH];
        if s.expected.is_predicate() {
            let stmt = super::digest(
                &(0..96)
                    .map(|f| {
                        fields.field::<Val, _>(row, transition_fields::Stream::Statement, f, f % 8)
                    })
                    .collect::<Vec<_>>(),
            );
            for row in trace.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
                row[STMT_ROOT..STMT_ROOT + 4].copy_from_slice(&stmt);
            }
        }
        let fields = Fields::new(s);
        if s.expected.is_predicate() {
            let row = &trace.values[..TRACE_WIDTH];
            let root = super::digest(
                &(0..48)
                    .map(|f| {
                        fields.field::<Val, _>(
                            row,
                            transition_fields::Stream::NewProgress,
                            f,
                            f % 8,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
            for row in trace.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
                if row[STATUS] == Val::ONE {
                    for t in 0..2 {
                        if row[ACTOR + t] == Val::ONE {
                            row[progress(NEW_PROGRESS, t) + 1..progress(NEW_PROGRESS, t) + 5]
                                .copy_from_slice(&root);
                        }
                    }
                }
            }
        }
        let fields = Fields::new(s);
        let row = &trace.values[..TRACE_WIDTH];
        s.next = super::digest(
            &(0..208)
                .map(|f| fields.field::<Val, _>(row, transition_fields::Stream::New, f, f % 8))
                .collect::<Vec<_>>(),
        );
        if repair_old {
            s.expected.old = super::digest(
                &(0..208)
                    .map(|f| fields.field::<Val, _>(row, transition_fields::Stream::Old, f, f % 8))
                    .collect::<Vec<_>>(),
            );
        }
        let fields = Fields::new(s);
        let row = &trace.values[..TRACE_WIDTH];
        s.expected.command = super::digest(
            &(0..160)
                .map(|f| fields.field::<Val, _>(row, transition_fields::Stream::Command, f, f % 8))
                .collect::<Vec<_>>(),
        );
        let fields = Fields::new(s);
        let row = &trace.values[..TRACE_WIDTH];
        s.result = super::digest(
            &(0..160)
                .map(|f| fields.field::<Val, _>(row, transition_fields::Stream::Result, f, f % 8))
                .collect::<Vec<_>>(),
        );
    }
    let fields = Fields::new(s);
    let mut cp = [Val::ZERO; 12];
    for (r, row) in trace
        .values
        .as_chunks_mut::<TRACE_WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[CP..WORDS].copy_from_slice(&cp);
        let mut input = [Val::ZERO; 12];
        if let Some((stream, block)) = transition_fields::absorb(r) {
            for (w, v) in input[..8].iter_mut().enumerate() {
                *v = fields.field(row, stream, 8 * block + w, w);
            }
            if !transition_fields::RESETS.contains(&r) {
                input[8..].copy_from_slice(&cp[8..]);
            }
        }
        let output = crate::poseidon::write(&mut row[..CP], input);
        if transition_fields::absorb(r).is_some() {
            cp = output;
        }
    }
}

#[test]
fn genuine_nowait_cause_preserves_outer_savepoint_scope_and_rejects_false_failure() {
    let f = fixture();
    let mut old = conditional_state();
    old.registry.transactions[1].held = [4, 3, 0, 0];
    old.registry.transactions[1].savepoints.push(Savepoint {
        name: [0x22; 32],
        held: [4, 0, 0, 0],
    });
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 0x80;
    let (q, qbytes) = query(&f.source, &f.source_bytes, mask, 0xe1, 0xe2, 33);
    let boot = bootstrap_expected(f);
    let draft = Expected::predicate(
        &q,
        boot.genesis(),
        [0xe3; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let s = hidden(&draft, &old, 2, mask, 1, 1, 1);
    let e = predicate_expected(f, &q, &old, &s, 0xe3, 9);
    let w = predicate_witness(f, &e, &old, s.clone(), 9, 10, 2, 33);
    let proved = accept(&e, &w, &f.source_bytes, &qbytes);
    let failed = old.predicate(&s, [0, 1, 128, 255], [74; 4]).unwrap();
    assert!(failed.status == Status::Error);
    assert!(failed.next.registry.transactions[1].failed);
    assert_eq!(failed.next.registry.transactions[1].held, [4, 0, 0, 0]);
    assert_eq!(
        proved.next,
        failed
            .next
            .root(e.registry_context(), &f.plain, &CONTROLLERS, [10; 4])
            .unwrap()
    );
    // Clear an outer lock but repair the claimed new/result roots and all hashes.
    let mut bad = w.trace().unwrap();
    for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
        row[held(slot(NEW, 1), 0, 4)] = Val::ZERO;
        row[held(slot(NEW, 1), 0, 0)] = Val::ONE;
    }
    let mut claim = w.statement().clone();
    repair(&mut claim, &mut bad, false);
    reject_raw(&claim, bad);
    // A false cause with coherent canonical old/new roots still has no genuine
    // conflict: both full-mask scan and the closed status equations reach AIR.
    let mut bad = w.trace().unwrap();
    for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
        row[held(slot(OLD, 0), 3, 4)] = Val::ZERO;
        row[held(slot(OLD, 0), 3, 0)] = Val::ONE;
        row[held(slot(NEW, 0), 3, 4)] = Val::ZERO;
        row[held(slot(NEW, 0), 3, 0)] = Val::ONE;
    }
    let mut claim = w.statement().clone();
    repair(&mut claim, &mut bad, true);
    reject_raw(&claim, bad);
}

#[test]
fn repaired_roots_reject_prefix_loss_unrelated_parked_control_and_start_identity_substitution() {
    let f = fixture();
    let old = conditional_state();
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 0x80;
    let (q, _) = query(&f.source, &f.source_bytes, mask, 0xf1, 0xf2, 34);
    let boot = bootstrap_expected(f);
    let draft = Expected::predicate(
        &q,
        boot.genesis(),
        [0xf3; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let s = hidden(&draft, &old, 2, mask, 0, 1, 1);
    let e = predicate_expected(f, &q, &old, &s, 0xf3, 9);
    let w = predicate_witness(f, &e, &old, s.clone(), 9, 10, 2, 34);
    for change in 0..3 {
        let mut bad = w.trace().unwrap();
        for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
            match change {
                0 => {
                    row[held(slot(NEW, 1), 0, 4)] = Val::ZERO;
                    row[held(slot(NEW, 1), 0, 0)] = Val::ONE;
                }
                1 => row[ORIGINAL_SQL] = Val::ONE - row[ORIGINAL_SQL],
                _ => {
                    row[NEW_CURSOR + 3] = Val::ZERO;
                    row[NEW_CURSOR] = Val::ONE;
                }
            }
        }
        let mut claim = w.statement().clone();
        repair(&mut claim, &mut bad, false);
        reject_raw(&claim, bad);
    }
    let parked = old.predicate(&s, [0, 1, 128, 255], [74; 4]).unwrap().next;
    let c = Command::control(Operation::End, 1, 1, 1);
    let ec = control_expected(f, &f.source, &parked, &c, 0xf4, 10, 41);
    let wc = Witness::control(
        &ec,
        Zeroizing::new(f.plain),
        Zeroizing::new(CONTROLLERS),
        Zeroizing::new(parked.clone()),
        Zeroizing::new(c),
        Zeroizing::new([[2; 4], [3; 4], [10; 4], [41; 4], [11; 4], [42; 4]]),
    )
    .unwrap();
    for change in 0..2 {
        let mut bad = wc.trace().unwrap();
        for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
            if change == 0 {
                row[NEW_PROGRESS] = Val::ZERO;
                row[NEW_PROGRESS + 1..NEW_PROGRESS + 5].fill(Val::ZERO);
            } else {
                row[held(slot(NEW, 0), 0, 4)] = Val::ZERO;
                row[held(slot(NEW, 0), 0, 0)] = Val::ONE;
            }
        }
        let mut claim = wc.statement().clone();
        repair(&mut claim, &mut bad, false);
        reject_raw(&claim, bad);
    }
    // Build a mathematically valid unrelated Savepoint base transition, then
    // restore exact parked presence/root. This reaches the control-lane guard.
    let mut unrelated = Command::control(
        Operation::Savepoint,
        2,
        2,
        parked.registry.transactions[1].sequence,
    );
    unrelated.name = [0x33; 32];
    let mut cleared = parked.clone();
    cleared.progress[1] = None;
    let eu = control_expected(f, &f.source, &cleared, &unrelated, 0xf5, 10, 41);
    let wu = Witness::control(
        &eu,
        Zeroizing::new(f.plain),
        Zeroizing::new(CONTROLLERS),
        Zeroizing::new(cleared),
        Zeroizing::new(unrelated),
        Zeroizing::new([[2; 4], [3; 4], [10; 4], [41; 4], [11; 4], [42; 4]]),
    )
    .unwrap();
    let mut bad = wu.trace().unwrap();
    let root = parked.progress[1].as_ref().unwrap().root().unwrap();
    for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
        for at in [OLD_PROGRESS, NEW_PROGRESS] {
            row[progress(at, 1)] = Val::ONE;
            row[progress(at, 1) + 1..progress(at, 1) + 5].copy_from_slice(&root);
        }
    }
    let mut claim = wu.statement().clone();
    repair(&mut claim, &mut bad, true);
    reject_raw(&claim, bad);
}

#[test]
fn genuine_cursor_zero_resume_allows_fresh_blind_but_never_changes_the_original_options() {
    let f = fixture();
    let mut old = conditional_state();
    old.registry.transactions[0].held = [4, 0, 0, 0];
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 0x80;
    let (q, bytes) = query(&f.source, &f.source_bytes, mask, 0x61, 0x62, 35);
    let boot = bootstrap_expected(f);
    let draft = Expected::predicate(
        &q,
        boot.genesis(),
        [0x63; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let s = hidden(&draft, &old, 2, mask, 0, 1, 1);
    let e = predicate_expected(f, &q, &old, &s, 0x63, 9);
    let w = predicate_witness(f, &e, &old, s.clone(), 9, 10, 2, 35);
    accept(&e, &w, &f.source_bytes, &bytes);
    let parked = old.predicate(&s, [0, 1, 128, 255], [74; 4]).unwrap();
    assert_eq!(parked.cursor, 0);
    assert!(!parked.resumed);
    let (q2, bytes2) = query(&f.source, &f.source_bytes, mask, 0x64, 0x65, 36);
    let e2 = predicate_expected(f, &q2, &parked.next, &s, 0x66, 10);
    let w2 = predicate_witness(f, &e2, &parked.next, s.clone(), 10, 11, 2, 36);
    accept(&e2, &w2, &f.source_bytes, &bytes2);
    let twice = parked
        .next
        .predicate(&s, [0, 1, 128, 255], [74; 4])
        .unwrap();
    assert!(twice.resumed);
    assert_eq!(twice.cursor, 0);
    assert_eq!(twice.microstep, 2);
    for change in 0..3 {
        let mut changed = s.clone();
        match change {
            0 => changed.projection = 2,
            1 => changed.offset = 0,
            _ => changed.limit = 2,
        }
        let changed_expected = predicate_expected(f, &q2, &parked.next, &changed, 0x66, 10);
        assert!(
            Witness::predicate(
                &changed_expected,
                Zeroizing::new(f.plain),
                Zeroizing::new(CONTROLLERS),
                Zeroizing::new(parked.next.clone()),
                Zeroizing::new(changed),
                Zeroizing::new([
                    [2; 4], [3; 4], [10; 4], [41; 4], [11; 4], [42; 4], [74; 4], [36; 4]
                ])
            )
            .is_err()
        );
    }
    // The foreign mask has a separately genuine Source/Encoding proof; rejection
    // is not an invalid prerequisite masquerading as the original statement.
    let mut foreign_mask = mask;
    foreign_mask[31] = 0;
    let (q3, bytes3) = query(&f.source, &f.source_bytes, foreign_mask, 0x67, 0x68, 37);
    assert_eq!(
        enc::wire::verify(&q3.expected, &bytes3)
            .unwrap()
            .statement()
            .values(),
        q3.values()
    );
    let mut changed = s.clone();
    changed.mask = foreign_mask;
    let e3 = predicate_expected(f, &q3, &parked.next, &changed, 0x69, 10);
    assert!(
        Witness::predicate(
            &e3,
            Zeroizing::new(f.plain),
            Zeroizing::new(CONTROLLERS),
            Zeroizing::new(parked.next),
            Zeroizing::new(changed),
            Zeroizing::new([
                [2; 4], [3; 4], [10; 4], [41; 4], [11; 4], [42; 4], [74; 4], [37; 4]
            ])
        )
        .is_err()
    );
}

fn all_four_ages_mask() -> [u8; 32] {
    let mut mask = [0; 32];
    mask[0] = 3; // Ages 0 and 1.
    mask[16] = 1; // Age 128.
    mask[31] = 0x80; // Age 255.
    mask
}

/// Repair unsigned prefix comparisons as well as all roots below. A malformed
/// counter is not a substitute for testing the actual closed walk equations.
fn repair_walk_comparisons(trace: &mut RowMajorMatrix<Val>, offset: u8, limit: u8) {
    for row in trace.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
        for i in 0..4 {
            for (at, prefix, bound) in [
                (
                    OLD_OFFSET_CMP + 4 * i,
                    row[OLD_VISITED..OLD_VISITED + i]
                        .iter()
                        .filter(|v| **v == Val::ONE)
                        .count(),
                    offset,
                ),
                (
                    LIMIT_CMP + 4 * i,
                    row[NEW_SELECTED..NEW_SELECTED + i]
                        .iter()
                        .filter(|v| **v == Val::ONE)
                        .count(),
                    limit,
                ),
                (
                    OFFSET_CMP + 4 * i,
                    row[NEW_VISITED..NEW_VISITED + i]
                        .iter()
                        .filter(|v| **v == Val::ONE)
                        .count(),
                    offset,
                ),
            ] {
                let difference = prefix as u8 + 8 - bound;
                for bit in 0..3 {
                    row[at + bit] = Val::from_bool((difference >> bit) & 1 != 0);
                }
                row[at + 3] = Val::from_bool(difference >= 8);
            }
        }
    }
}

#[test]
fn genuine_skip_locked_skips_conflicts_before_offset_and_locks_only_window() {
    // Arrange one conflicting first row and three unlocked matching rows. The
    // same genuine Source fixture is bounded and shared with the owning suite.
    let f = fixture();
    let mut old = conditional_state();
    old.registry.transactions[0].held = [4, 0, 0, 0];
    let mask = all_four_ages_mask();
    let (q, qbytes) = query(&f.source, &f.source_bytes, mask, 0x81, 0x82, 38);
    let boot = bootstrap_expected(f);
    let draft = Expected::predicate(
        &q,
        boot.genesis(),
        [0x83; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let s = hidden(&draft, &old, 2, mask, 2, 1, 1);
    let e = predicate_expected(f, &q, &old, &s, 0x83, 9);
    let w = predicate_witness(f, &e, &old, s.clone(), 9, 10, 2, 38);

    // Act: genuinely prove/self-verify and independently verify the actual new
    // Predicate AIR after the complete Source/Encoding prerequisites.
    let proved = accept(&e, &w, &f.source_bytes, &qbytes);

    // Assert: the skipped conflict consumes no OFFSET. Row1 consumes OFFSET and
    // is held; row2 is returned and held; LIMIT stops before unlocked row3.
    let next = old.predicate(&s, [0, 1, 128, 255], [74; 4]).unwrap();
    assert!(next.status == Status::Done);
    assert_eq!(next.skipped, [true, false, false, false]);
    assert_eq!(next.visited, [false, true, true, false]);
    assert_eq!(next.selected, [false, false, true, false]);
    assert_eq!(next.block, [false; 4]);
    assert_eq!(next.cursor, 3);
    assert_eq!(
        next.next.registry.transactions[0],
        old.registry.transactions[0]
    );
    assert_eq!(next.next.registry.transactions[1].held, [0, 4, 4, 0]);
    assert!(!next.next.registry.transactions[1].failed);
    assert!(next.next.progress.iter().all(Option::is_none));
    assert_eq!(
        proved.next,
        next.next
            .root(e.registry_context(), &f.plain, &CONTROLLERS, [10; 4])
            .unwrap()
    );

    // Each attack retains the genuine full-mask prerequisite and repairs all
    // state/result/command roots, Poseidon gadgets and comparison counters.
    for attack in 0..3 {
        let mut bad = w.trace().unwrap();
        for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
            match attack {
                // Count the skipped row against OFFSET, return row1 too early,
                // and stop before row2 despite coherent shortened lock effects.
                0 => {
                    for at in [SEARCH, ATTEMPT, VISIT, NEW_VISITED] {
                        row[at + 2] = Val::ZERO;
                    }
                    row[RETURN + 1] = Val::ONE;
                    row[RETURN + 2] = Val::ZERO;
                    row[NEW_SELECTED + 1] = Val::ONE;
                    row[NEW_SELECTED + 2] = Val::ZERO;
                    row[held(slot(NEW, 1), 2, 4)] = Val::ZERO;
                    row[held(slot(NEW, 1), 2, 0)] = Val::ONE;
                    row[NEW_CURSOR + 3] = Val::ZERO;
                    row[NEW_CURSOR + 2] = Val::ONE;
                }
                // Omit unlocked matching row1 as if it were locked. The genuine
                // immutable other-actor bank still proves no conflict there.
                1 => {
                    row[VISIT + 1] = Val::ZERO;
                    row[SKIP + 1] = Val::ONE;
                    row[NEW_VISITED + 1] = Val::ZERO;
                    row[RETURN + 2] = Val::ZERO;
                    row[NEW_SELECTED + 2] = Val::ZERO;
                    for at in [SEARCH, ATTEMPT, VISIT, RETURN, NEW_VISITED, NEW_SELECTED] {
                        row[at + 3] = Val::ONE;
                    }
                    row[held(slot(NEW, 1), 1, 4)] = Val::ZERO;
                    row[held(slot(NEW, 1), 1, 0)] = Val::ONE;
                    row[held(slot(NEW, 1), 3, 0)] = Val::ZERO;
                    row[held(slot(NEW, 1), 3, 4)] = Val::ONE;
                    row[NEW_CURSOR + 3] = Val::ZERO;
                    row[NEW_CURSOR + 4] = Val::ONE;
                }
                // Add a held row outside the actual stopped LIMIT window while
                // leaving every legitimate visit/return untouched.
                _ => {
                    row[held(slot(NEW, 1), 3, 0)] = Val::ZERO;
                    row[held(slot(NEW, 1), 3, 4)] = Val::ONE;
                }
            }
        }
        repair_walk_comparisons(&mut bad, s.offset, s.limit);
        let mut claim = w.statement().clone();
        repair(&mut claim, &mut bad, false);
        reject_raw(&claim, bad);
    }
}

#[test]
fn genuine_skip_locked_limit_zero_never_searches_or_changes_held_rows() {
    let f = fixture();
    let mut old = conditional_state();
    old.registry.transactions[0].held = [4, 0, 0, 0];
    old.registry.transactions[1].held = [0, 0, 0, 3];
    let mask = all_four_ages_mask();
    let (q, qbytes) = query(&f.source, &f.source_bytes, mask, 0x84, 0x85, 39);
    let boot = bootstrap_expected(f);
    let draft = Expected::predicate(
        &q,
        boot.genesis(),
        [0x86; 32],
        source::statement::encode_digest(boot.enrollment()),
        [0; 32],
        [0; 32],
    )
    .unwrap();
    let s = hidden(&draft, &old, 2, mask, 2, 1, 0);
    let e = predicate_expected(f, &q, &old, &s, 0x86, 9);
    let w = predicate_witness(f, &e, &old, s.clone(), 9, 10, 2, 39);

    let proved = accept(&e, &w, &f.source_bytes, &qbytes);

    let next = old.predicate(&s, [0, 1, 128, 255], [74; 4]).unwrap();
    assert!(next.status == Status::Done);
    assert_eq!(next.cursor, 0);
    assert_eq!(next.skipped, [false; 4]);
    assert_eq!(next.visited, [false; 4]);
    assert_eq!(next.selected, [false; 4]);
    assert_eq!(next.block, [false; 4]);
    assert_eq!(
        next.next.registry.transactions[0],
        old.registry.transactions[0]
    );
    assert_eq!(
        next.next.registry.transactions[1].held,
        old.registry.transactions[1].held
    );
    assert!(!next.next.registry.transactions[1].failed);
    assert!(next.next.progress.iter().all(Option::is_none));
    assert_eq!(
        proved.next,
        next.next
            .root(e.registry_context(), &f.plain, &CONTROLLERS, [10; 4])
            .unwrap()
    );

    // Attempt a conflict skip and then acquire an OFFSET-only row despite LIMIT0.
    // Actual comparison and root repair reaches the no-search relation itself.
    let mut bad = w.trace().unwrap();
    for row in bad.values.as_chunks_mut::<TRACE_WIDTH>().0.iter_mut() {
        for i in 0..2 {
            row[SEARCH + i] = Val::ONE;
            row[ATTEMPT + i] = Val::ONE;
        }
        row[SKIP] = Val::ONE;
        row[VISIT + 1] = Val::ONE;
        row[NEW_VISITED + 1] = Val::ONE;
        row[held(slot(NEW, 1), 1, 0)] = Val::ZERO;
        row[held(slot(NEW, 1), 1, 4)] = Val::ONE;
        row[NEW_CURSOR] = Val::ZERO;
        row[NEW_CURSOR + 2] = Val::ONE;
    }
    repair_walk_comparisons(&mut bad, s.offset, s.limit);
    let mut claim = w.statement().clone();
    repair(&mut claim, &mut bad, false);
    reject_raw(&claim, bad);
}
