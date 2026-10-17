//! Actual public-nonsecret proof/Journal tests. No cache grants verification authority.
use super::super::{
    model::{Command, Operation as CommandOperation, Registry, Transaction},
    statement as lifecycle, wire,
};
use super::fixture::{CONTROL_ID, Fixture, OwnedDirectory, SOURCE_ID};
use super::owner::{Inputs, PrivateState, ValidatedParent};
use super::*;
use crate::backend::Val;
use p3_field::PrimeCharacteristicRing;
use std::{cell::Cell, sync::OnceLock};
use version_journal::{
    AuthorizedTransition, Body, DurableJournal, Freshness, Header, Journal, ShardUpdate,
    TransitionVerifier,
};
mod lifecycle_tests;

struct Stored {
    header: Header,
    body: Vec<u8>,
}
struct Prefix {
    genesis: Genesis,
    blocks: [Stored; 2],
}
fn prefix() -> &'static Prefix {
    static PREFIX: OnceLock<Prefix> = OnceLock::new();
    PREFIX.get_or_init(|| {
        let f = Fixture::new().unwrap();
        let verifier = f.verifier().unwrap();
        let mut journal = Journal::new(f.genesis.clone()).unwrap();
        let parent = journal.genesis_head();
        let boot = f.bootstrap(&journal, parent, [0xB1; 32]).unwrap();
        let boot_bytes = boot.body.encode(journal.profile()).unwrap();
        let h1 = fixture::append(&mut journal, &verifier, parent.block, &boot.body, 1001).unwrap();
        let parent = journal.best_validated();
        let begin = f
            .transition(
                &journal,
                parent,
                &boot.private,
                Command::control(CommandOperation::Begin, 1, 1, 0),
                [0xB2; 32],
            )
            .unwrap();
        let begin_bytes = begin.body.encode(journal.profile()).unwrap();
        let h2 = fixture::append(&mut journal, &verifier, parent.block, &begin.body, 1002).unwrap();
        // Only two canonical PUBLIC bodies (~52MiB), not a long chain/private witness/Backend.
        Prefix {
            genesis: f.genesis,
            blocks: [
                Stored {
                    header: h1,
                    body: boot_bytes,
                },
                Stored {
                    header: h2,
                    body: begin_bytes,
                },
            ],
        }
    })
}
fn journal(count: usize) -> Journal {
    let p = prefix();
    let f = Fixture::new().unwrap();
    assert_eq!(f.genesis, p.genesis);
    let mut journal = Journal::new(f.genesis.clone()).unwrap();
    let verifier = f.verifier().unwrap();
    for block in &p.blocks[..count] {
        journal
            .import_block(block.header.clone(), &block.body, 10000, &verifier)
            .unwrap();
    }
    journal
}
fn transition(index: usize) -> AuthorizedTransition {
    let Body::Transition(t) =
        Body::decode(&prefix().blocks[index].body, &prefix().genesis.profile).unwrap()
    else {
        panic!("real transition")
    };
    t
}
fn after_begin(f: &Fixture) -> PrivateState {
    // Explicit PUBLIC NONSECRET owner fixture. Preparation still checks it against actual Cold.
    PrivateState {
        registry: Registry {
            revision: 1,
            allocator: 1,
            transactions: vec![Transaction {
                id: 1,
                principal: 1,
                sequence: 1,
                failed: false,
                snapshot: prefix().blocks[0].header.id(),
                held: [0; 4],
                savepoints: vec![],
            }],
        },
        salt: f.source.witness.salts[4],
    }
}
struct CountVerifier<'a> {
    inner: &'a PrivateVerifier,
    calls: Cell<usize>,
}
impl TransitionVerifier for CountVerifier<'_> {
    fn verify(&self, s: version_journal::TransitionStatement<'_>) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.verify(s)
    }
}
fn changed(root: Hash) -> Hash {
    let mut v = crate::opening::statement::decode_digest(root).unwrap();
    v[0] += Val::ONE;
    lifecycle::encoded(v)
}
fn sign(f: &Fixture, mut t: AuthorizedTransition) -> Body {
    t.sign(f.genesis.id().unwrap(), &Fixture::owner());
    let body = Body::Transition(t);
    body.encode(&f.genesis.profile).unwrap();
    body
}
fn import(j: &mut Journal, v: &impl TransitionVerifier, body: &Body, stamp: u64) -> Result<Header> {
    let Body::Transition(t) = body else {
        unreachable!()
    };
    fixture::append(j, v, t.parent, body, stamp)
}
fn control(j: &Journal, f: &Fixture) -> Control {
    let head = f
        .application
        .control(j.validated_shards(j.best_validated()).unwrap())
        .unwrap();
    Control::decode(&f.application, head).unwrap()
}
fn command(state: &PrivateState, operation: CommandOperation, id: u64, principal: u8) -> Command {
    let sequence = if operation == CommandOperation::Begin {
        0
    } else {
        state
            .registry
            .transactions
            .iter()
            .find(|t| t.id == id)
            .unwrap()
            .sequence
    };
    Command::control(operation, id, principal, sequence)
}
fn apply(
    f: &Fixture,
    j: &mut Journal,
    state: &mut PrivateState,
    command: Command,
    ordinal: u8,
) -> owner::Produced {
    let parent = j.best_validated();
    let produced = f
        .transition(j, parent, state, command, [ordinal; 32])
        .unwrap();
    assert!(produced.outcome == 0 || produced.outcome == 3);
    import(
        j,
        &f.verifier().unwrap(),
        &produced.body,
        1100 + u64::from(ordinal),
    )
    .unwrap();
    *state = produced.private.clone();
    produced
}

#[test]
fn request200_is_exact_canonical_and_pending_active_domains_are_distinct() {
    let f = Fixture::new().unwrap();
    for index in 0..2 {
        let t = transition(index);
        assert_eq!(t.request.len(), request::REQUEST_BYTES);
        assert_eq!(request::REQUEST_BYTES, 2716);
        let r = Request::decode(&t.request).unwrap();
        assert_eq!(r.encode().unwrap(), t.request);
        assert_eq!(
            r.query,
            request::intent_query(
                &f.application,
                r.genesis,
                r.parent,
                r.nonce,
                r.enrollment,
                r.operation
            )
        );
        for bad in [
            &t.request[..2715],
            &[t.request.as_slice(), &[0]].concat(),
            &[0; 2716],
        ] {
            assert!(Request::decode(bad).is_err());
        }
        for byte in [0, 8, 9, 15] {
            let mut bad = t.request.clone();
            bad[byte] = 255;
            assert!(Request::decode(&bad).is_err());
        }
        for field in [5, 6, 7] {
            let mut bad = t.request.clone();
            bad[16 + field * 32..24 + field * 32].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(Request::decode(&bad).is_err());
        }
        let source = r.source(&f.application).unwrap();
        assert_eq!(
            source.heads,
            [f.application.source.data, f.application.source.index]
        );
        assert_eq!(lifecycle::encoded(source.key_commitment), f.application.key);
    }
    let boot = Request::decode(&transition(0).request).unwrap();
    let begin = Request::decode(&transition(1).request).unwrap();
    assert_eq!(boot.packets, begin.packets);
    assert_ne!(boot.query, begin.query);
    assert_ne!(boot.opening, begin.opening);
    assert_eq!(boot.enrollment, begin.enrollment);
    let pending = Control::Pending.heads(&f.application);
    let active = Control::Active {
        enrollment: begin.enrollment,
        registry: changed([0; 32]),
    }
    .heads(&f.application);
    assert_ne!(pending, active);
    for field in [0, 24, 25, 26, 32, 96, 111] {
        let mut bad = active;
        bad.data[field] ^= 1;
        assert!(Control::decode(&f.application, bad).is_err());
    }
    let mut old112 = active;
    old112.data[..8].copy_from_slice(b"DCSPCH01");
    assert!(Control::decode(&f.application, old112).is_err());
}

#[test]
fn owner_preparation_matches_external_validated_cold_before_command_or_proof() {
    let f = Fixture::new().unwrap();
    let j = journal(2);
    let state = after_begin(&f);
    let parent = j.best_validated();
    let cmd = command(&state, CommandOperation::Savepoint, 1, 1);
    assert!(
        f.prepare(&j, parent, &state, cmd.clone(), [0xC1; 32])
            .is_ok()
    );
    for field in 0..4 {
        let mut wrong = state.clone();
        match field {
            0 => wrong.salt[0] += Val::ONE,
            1 => wrong.registry.revision += 1,
            2 => wrong.registry.transactions[0].snapshot[31] ^= 1,
            _ => wrong.registry.transactions[0].held[3] = 1,
        }
        assert!(matches!(
            f.prepare(&j, parent, &wrong, cmd.clone(), [0xC1; 32]),
            Err(Error::InvalidTransition)
        ));
    }
    let accepted = ValidatedParent::read(&f.application, &j, parent).unwrap();
    let foreign = Application::new([0xAD; 32], SOURCE_ID, CONTROL_ID, &f.source.source).unwrap();
    let inputs = Inputs {
        app: &foreign,
        source: &f.source.source,
        source_witness: &f.source.source_witness,
        opening: &f.source.witness,
    };
    assert!(
        inputs
            .transition(&accepted, &state, cmd.clone(), [0xC1; 32])
            .is_err()
    );
    let mut opening = f.source.witness.clone();
    opening.controllers[0][31] ^= 1;
    let inputs = Inputs {
        app: &f.application,
        source: &f.source.source,
        source_witness: &f.source.source_witness,
        opening: &opening,
    };
    assert!(matches!(
        inputs.transition(&accepted, &state, cmd, [0xC1; 32]),
        Err(Error::InvalidTransition)
    ));
}

#[test]
fn real_owner_signature_precedes_callback_for_request_proof_update_and_wrong_owner() {
    let f = Fixture::new().unwrap();
    let verifier = f.verifier().unwrap();
    let counted = CountVerifier {
        inner: &verifier,
        calls: Cell::new(0),
    };
    for field in 0..4 {
        let mut j = journal(1);
        let mut t = transition(1);
        match field {
            0 => t.request[2715] ^= 1,
            1 => t.proof[200] ^= 1,
            2 => t.updates[0].new.data[111] ^= 1,
            _ => t.sign(
                f.genesis.id().unwrap(),
                &ed25519_dalek::SigningKey::from_bytes(&[0x69; 32]),
            ),
        }
        let before = j.best_validated();
        assert_eq!(
            import(&mut j, &counted, &Body::Transition(t), 1200),
            Err(Error::Unauthorized)
        );
        assert_eq!(j.best_validated(), before);
    }
    assert_eq!(counted.calls.get(), 0);
}

#[test]
fn resigned_foreign_request_command_enrollment_packets_and_roots_cannot_reuse_proofs() {
    let f = Fixture::new().unwrap();
    let verifier = f.verifier().unwrap();
    let counted = CountVerifier {
        inner: &verifier,
        calls: Cell::new(0),
    };
    for field in 0..12 {
        let mut j = journal(1);
        let mut t = transition(1);
        let mut r = Request::decode(&t.request).unwrap();
        match field {
            0 => r.query[31] ^= 1,
            1 => r.opening = changed(r.opening),
            2 => r.command = changed(r.command),
            3 => r.enrollment = changed(r.enrollment),
            4 => r.packets[0][59] ^= 1,
            5 => r.packets[1][2383] ^= 1,
            6 => r.application[31] ^= 1,
            7 => r.genesis[31] ^= 1,
            8 => r.parent[31] ^= 1,
            9 => r.nonce[31] ^= 1,
            10 => {
                let Control::Active {
                    enrollment,
                    registry,
                } = Control::decode(&f.application, t.updates[0].new).unwrap()
                else {
                    unreachable!()
                };
                t.updates[0].new = Control::Active {
                    enrollment,
                    registry: changed(registry),
                }
                .heads(&f.application);
            }
            _ => t.proof[200] ^= 1,
        }
        t.request = r.encode().unwrap();
        let before = j.best_validated();
        assert!(
            import(&mut j, &counted, &sign(&f, t), 1201).is_err(),
            "field {field}"
        );
        assert_eq!(j.best_validated(), before);
    }
    assert_eq!(counted.calls.get(), 12);
}

#[test]
fn signed_source_or_extra_updates_fail_the_exact_two_shard_control_contract() {
    let f = Fixture::new().unwrap();
    let verifier = f.verifier().unwrap();
    let counted = CountVerifier {
        inner: &verifier,
        calls: Cell::new(0),
    };
    for extra in [false, true] {
        let mut j = journal(1);
        let mut t = transition(1);
        let mut new = f.application.source;
        new.data[80] ^= 1;
        let source = ShardUpdate {
            id: SOURCE_ID,
            old: f.application.source,
            new,
        };
        if extra {
            t.updates.push(source);
            t.updates.sort_unstable_by_key(|u| u.id);
        } else {
            t.updates = vec![source];
        }
        let before = j.best_validated();
        assert!(import(&mut j, &counted, &sign(&f, t), 1202).is_err());
        assert_eq!(j.best_validated(), before);
        assert_eq!(
            j.validated_shards(before)
                .unwrap()
                .iter()
                .find(|s| s.id == SOURCE_ID)
                .unwrap()
                .heads,
            f.application.source
        );
    }
    assert_eq!(counted.calls.get(), 2);
}

#[test]
fn active_phase_cannot_bootstrap_again_or_replace_pending_genesis() {
    let f = Fixture::new().unwrap();
    let mut j = journal(1);
    let active = control(&j, &f);
    let mut t = transition(0);
    t.parent = j.best_validated().block;
    t.updates[0].old = active.heads(&f.application);
    let Control::Active {
        enrollment,
        registry,
    } = active
    else {
        unreachable!()
    };
    t.updates[0].new = Control::Active {
        enrollment,
        registry: changed(registry),
    }
    .heads(&f.application);
    let mut r = Request::decode(&t.request).unwrap();
    r.parent = t.parent;
    r.query = request::intent_query(
        &f.application,
        r.genesis,
        r.parent,
        r.nonce,
        r.enrollment,
        r.operation,
    );
    t.request = r.encode().unwrap();
    assert_eq!(
        import(&mut j, &f.verifier().unwrap(), &sign(&f, t), 1203),
        Err(Error::InvalidTransition)
    );
    let mut g = f.genesis.clone();
    g.initial_shards
        .iter_mut()
        .find(|s| s.id == CONTROL_ID)
        .unwrap()
        .heads = active.heads(&f.application);
    assert!(matches!(
        PrivateVerifier::new(f.application.clone(), &g),
        Err(Error::WrongDomain)
    ));
}

#[test]
fn missing_proof_and_canonical_body_caps_fail_closed_at_the_real_boundary() {
    let f = Fixture::new().unwrap();
    let mut j = journal(1);
    let mut t = transition(1);
    t.proof.clear();
    t.sign(f.genesis.id().unwrap(), &Fixture::owner());
    let missing = Body::Transition(t);
    assert_eq!(
        missing.encode(j.profile()),
        Err(Error::MissingComputationProof)
    );
    let before = j.best_validated();
    assert_eq!(
        import(&mut j, &f.verifier().unwrap(), &missing, 1204),
        Err(Error::MissingComputationProof)
    );
    assert_eq!(j.best_validated(), before);
    let t = transition(1);
    let body = Body::Transition(t.clone());
    let bytes = body.encode(j.profile()).unwrap();
    assert_eq!(
        bytes.len(),
        117 + request::REQUEST_BYTES + 456 + t.proof.len()
    );
    assert!(bytes.len() <= version_journal::MAX_BODY_BYTES);
    assert_eq!(
        Body::decode(&bytes, j.profile())
            .unwrap()
            .encode(j.profile())
            .unwrap(),
        bytes
    );
    let mut p = j.profile().clone();
    p.max_body_bytes = bytes.len() as u32;
    p.max_proof_bytes = t.proof.len() as u32;
    assert!(p.validate().is_ok());
    assert!(body.encode(&p).is_ok());
    p.max_body_bytes -= 1;
    assert!(p.validate().is_ok());
    assert_eq!(body.encode(&p), Err(Error::ResourceLimit));
    assert_eq!(Body::decode(&bytes, &p), Err(Error::ResourceLimit));
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(Body::decode(&bad, j.profile()).is_err());
}

#[test]
fn stale_cas_cannot_rebind_old_parent_control_and_validated_context_is_not_freshness() {
    let f = Fixture::new().unwrap();
    let mut j = journal(2);
    let old_parent = j.best_validated();
    assert_eq!(
        j.resolve(Freshness::Exact(old_parent)),
        Err(Error::Unconfirmed)
    );
    let mut t = transition(1);
    t.parent = old_parent.block;
    let mut r = Request::decode(&t.request).unwrap();
    r.parent = t.parent;
    r.query = request::intent_query(
        &f.application,
        r.genesis,
        r.parent,
        r.nonce,
        r.enrollment,
        r.operation,
    );
    t.request = r.encode().unwrap();
    assert_eq!(
        import(&mut j, &f.verifier().unwrap(), &sign(&f, t), 1205),
        Err(Error::InvalidTransition)
    );
    assert_eq!(j.best_validated(), old_parent);
    // Reading an exact validated protocol parent is deliberately not a client fresh-head token.
    assert!(ValidatedParent::read(&f.application, &j, old_parent).is_ok());
}
