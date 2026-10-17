//! Actual owner-signed Journal integration. Every fixture is PUBLIC NONSECRET.
use super::fixture::{CONTROL_ID, Fixture, LockQuery, RegistryInput, SOURCE_ID};
use super::*;
use crate::backend::Val;
use crate::opening::{locking, statement as source};
use p3_field::PrimeCharacteristicRing;
use std::{cell::Cell, path::PathBuf, sync::OnceLock};
use version_journal::{
    AuthorizedTransition, Body, DurableJournal, Freshness, Header, Journal, ShardUpdate,
};

struct PublicBlock {
    header: Header,
    body: Vec<u8>,
}
struct PublicChain {
    application: Application,
    genesis: Genesis,
    blocks: [PublicBlock; 3],
}
fn chain() -> &'static PublicChain {
    static CHAIN: OnceLock<PublicChain> = OnceLock::new();
    CHAIN.get_or_init(|| {
        let f = Fixture::new().unwrap();
        let verifier = f.verifier().unwrap();
        let mut journal = Journal::new(f.genesis.clone()).unwrap();
        let boot = f.bootstrap(journal.genesis_head()).unwrap();
        let boot_wire = boot.body.encode(journal.profile()).unwrap();
        let h1 = fixture::append(
            &mut journal,
            &verifier,
            journal_id(&f),
            &boot.body,
            1001
        ).unwrap();
        let first = f.acquire(
            &journal,
            journal.best_validated(),
            RegistryInput {
                state: &boot.next,
                salt: boot.salt
            },
            LockQuery {
                actor: 0,
                sql: "SELECT age, amount FROM records WHERE age >= 0 LIMIT 2 FOR UPDATE",
                nonce: [0xB2; 32]
            }
        ).unwrap();
        assert_eq!(first.returned, [true, true, false, false]);
        assert_eq!(first.next.revision, 3);
        let first_wire = first.body.encode(journal.profile()).unwrap();
        let h2 = fixture::append(
            &mut journal,
            &verifier,
            h1.id(),
            &first.body,
            1002
        ).unwrap();
        let skip = f.acquire(
            &journal,
            journal.best_validated(),
            RegistryInput {
                state: &first.next,
                salt: first.salt
            },
            LockQuery {
                actor: 1,
                sql: "SELECT age, amount FROM records WHERE age >= 0 LIMIT 2 FOR UPDATE SKIP LOCKED",
                nonce: [0xB3; 32]
            }
        ).unwrap();
        assert_eq!(skip.skipped, [true, true, false, false]);
        assert_eq!(skip.returned, [false, false, true, true]);
        assert_eq!(skip.next.revision, 4);
        assert_eq!(skip.next.tx[0].held, [4, 4, 0, 0]);
        assert_eq!(skip.next.tx[1].held, [0, 0, 4, 4]);
        let skip_wire = skip.body.encode(journal.profile()).unwrap();
        let h3 = fixture::append(
            &mut journal,
            &verifier,
            h2.id(),
            &skip.body,
            1003
        ).unwrap();
        // Cache only canonical PUBLIC bytes/headers and pinned context, never a proof object,
        // Backend, private witness, secret key, accepted grant or cache authority.
        PublicChain {
            application: f.application,
            genesis: f.genesis,
            blocks: [
                PublicBlock { header: h1, body: boot_wire },
                PublicBlock { header: h2, body: first_wire },
                PublicBlock { header: h3, body: skip_wire }
            ]
        }
    })
}
fn journal_id(f: &Fixture) -> Hash {
    f.genesis.id().unwrap()
}
impl PublicChain {
    fn verifier(&self) -> PrivateVerifier {
        PrivateVerifier::new(self.application.clone(), &self.genesis).unwrap()
    }
    fn journal(&self, count: usize) -> Journal {
        let mut j = Journal::new(self.genesis.clone()).unwrap();
        let v = self.verifier();
        for block in &self.blocks[..count] {
            j.import_block(block.header.clone(), &block.body, 10_000, &v)
                .unwrap();
        }
        j
    }
    fn transition(&self, index: usize) -> AuthorizedTransition {
        let Body::Transition(t) =
            Body::decode(&self.blocks[index].body, &self.genesis.profile).unwrap()
        else {
            panic!("genuine transition")
        };
        t
    }
}
struct CountVerifier<'a> {
    inner: &'a PrivateVerifier,
    calls: Cell<usize>,
}
impl TransitionVerifier for CountVerifier<'_> {
    fn verify(&self, s: TransitionStatement<'_>) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.inner.verify(s)
    }
}
fn canonical_changed_root(root: Hash) -> Hash {
    let mut fields = source::decode_digest(root).unwrap();
    fields[0] += Val::ONE;
    locking::statement::encoded(fields)
}
fn signed_body(c: &PublicChain, mut t: AuthorizedTransition) -> Body {
    t.sign(c.genesis.id().unwrap(), &Fixture::owner());
    bounded_body(&c.genesis.profile, t).unwrap()
}
fn import_candidate(j: &mut Journal, v: &impl TransitionVerifier, body: &Body) -> Result<()> {
    let Body::Transition(t) = body else {
        unreachable!()
    };
    let mut h = j.candidate(t.parent, body, 1020)?;
    h.mine(1024)?;
    j.import_block(h, &body.encode(j.profile())?, 10_000, v)
        .map(|_| ())
}

#[test]
fn pending_genesis_to_owner_signed_bootstrap_acquire_and_skip_uses_real_proofs() {
    let c = chain();
    let mut journal = c.journal(3);
    let v = c.verifier();
    let initial = c
        .genesis
        .initial_shards
        .iter()
        .find(|s| s.id == CONTROL_ID)
        .unwrap();
    assert_eq!(
        Control::decode(&c.application, initial.heads).unwrap(),
        Control::Pending
    );
    let before = journal.best_validated();
    fixture::append(&mut journal, &v, before.block, &Body::Empty, 1004).unwrap();
    let accepted = journal.resolve(Freshness::LatestConfirmed).unwrap();
    assert_eq!(accepted.block, c.blocks[2].header.id());
    let shards = journal
        .shards(accepted, Freshness::Exact(accepted))
        .unwrap();
    assert_eq!(
        shards.iter().find(|s| s.id == SOURCE_ID).unwrap().heads,
        c.application.source
    );
    assert!(matches!(
        Control::decode(
            &c.application,
            shards.iter().find(|s| s.id == CONTROL_ID).unwrap().heads
        ),
        Ok(Control::Active { .. })
    ));
}

#[test]
fn commands_rebind_request_and_copen_without_reencrypting_source_or_changing_ckey() {
    let c = chain();
    let requests: Vec<_> = (0..3)
        .map(|i| Request::decode(&c.transition(i).request).unwrap())
        .collect();
    for pair in requests.windows(2) {
        assert_eq!(pair[0].packets, pair[1].packets);
        assert_ne!(pair[0].query, pair[1].query);
        assert_ne!(pair[0].opening, pair[1].opening);
        assert_eq!(pair[0].enrollment, pair[1].enrollment);
    }
    for request in &requests {
        let s = request.source(&c.application).unwrap();
        assert_eq!(
            s.heads,
            [c.application.source.data, c.application.source.index]
        );
        assert_eq!(
            locking::statement::encoded(s.key_commitment),
            c.application.key
        );
    }
    let boot = &requests[0];
    assert_eq!(
        boot.query,
        request::bootstrap_query(
            &c.application,
            boot.genesis,
            boot.parent,
            boot.nonce,
            boot.enrollment
        )
    );
}

#[test]
fn owner_signature_rejects_changed_request_update_or_proof_before_callback() {
    let c = chain();
    let v = c.verifier();
    let counted = CountVerifier {
        inner: &v,
        calls: Cell::new(0),
    };
    for field in 0..3 {
        let mut journal = c.journal(1);
        let mut t = c.transition(1);
        match field {
            0 => t.request[16 + 4 * 32] ^= 1,
            1 => t.proof[100] ^= 1,
            _ => t.updates[0].new.data[96] ^= 1,
        }
        let body = Body::Transition(t);
        let before = journal.best_validated();
        assert_eq!(
            import_candidate(&mut journal, &counted, &body),
            Err(Error::Unauthorized)
        );
        assert_eq!(journal.best_validated(), before);
    }
    assert_eq!(counted.calls.get(), 0);
}

#[test]
fn owner_signed_foreign_request_opening_plan_enrollment_roots_or_source_cannot_reuse_proofs() {
    let c = chain();
    let v = c.verifier();
    for field in 0..9 {
        let mut journal = c.journal(1);
        let mut t = c.transition(1);
        let mut r = Request::decode(&t.request).unwrap();
        match field {
            0 => r.query[0] ^= 1,
            1 => r.opening = canonical_changed_root(r.opening),
            2 => r.plan = canonical_changed_root(r.plan),
            3 => r.enrollment = canonical_changed_root(r.enrollment),
            4 => r.packets[1][2383] ^= 1,
            5 => r.application[0] ^= 1,
            6 => r.genesis[0] ^= 1,
            7 => r.parent[0] ^= 1,
            _ => {
                let old = Control::decode(&c.application, t.updates[0].new).unwrap();
                let Control::Active {
                    enrollment,
                    registry,
                } = old
                else {
                    unreachable!()
                };
                t.updates[0].new = Control::Active {
                    enrollment,
                    registry: canonical_changed_root(registry),
                }
                .heads(&c.application);
            }
        }
        t.request = r.encode().unwrap();
        let body = signed_body(c, t);
        let before = journal.best_validated();
        assert!(
            import_candidate(&mut journal, &v, &body).is_err(),
            "field {field}"
        );
        assert_eq!(journal.best_validated(), before);
    }
}

#[test]
fn active_registry_cannot_be_bootstrapped_again_or_installed_as_unproved_genesis() {
    let c = chain();
    let mut journal = c.journal(1);
    let v = c.verifier();
    let mut t = c.transition(0);
    let active = journal
        .validated_shards(journal.best_validated())
        .unwrap()
        .iter()
        .find(|s| s.id == CONTROL_ID)
        .unwrap()
        .heads;
    t.parent = journal.best_validated().block;
    t.updates[0].old = active;
    let mut r = Request::decode(&t.request).unwrap();
    r.parent = t.parent;
    r.query = request::bootstrap_query(&c.application, r.genesis, r.parent, r.nonce, r.enrollment);
    t.request = r.encode().unwrap();
    // Make a changed canonical control head so generic Journal CAS reaches the phase guard.
    let Control::Active {
        enrollment,
        registry,
    } = Control::decode(&c.application, active).unwrap()
    else {
        unreachable!()
    };
    t.updates[0].new = Control::Active {
        enrollment,
        registry: canonical_changed_root(registry),
    }
    .heads(&c.application);
    assert!(import_candidate(&mut journal, &v, &signed_body(c, t)).is_err());
    let mut forged = c.genesis.clone();
    forged
        .initial_shards
        .iter_mut()
        .find(|s| s.id == CONTROL_ID)
        .unwrap()
        .heads = active;
    assert!(PrivateVerifier::new(c.application.clone(), &forged).is_err());
}

#[test]
fn genuine_blocked_and_nowait_evidence_has_no_appendable_transition_or_grant() {
    let c = chain();
    let f = Fixture::new().unwrap();
    assert_eq!(f.genesis, c.genesis);
    let mut journal = c.journal(2);
    let parent = journal.best_validated();
    let private_old = private_registry_after_first();
    for (wait, expected, nonce) in [("", 1, [0xC1; 32]), (" NOWAIT", 2, [0xC2; 32])] {
        let sql = format!("SELECT age FROM records LIMIT 1 FOR UPDATE{wait}");
        let step = f
            .acquire(
                &journal,
                parent,
                RegistryInput {
                    state: &private_old,
                    salt: [Val::from_u8(19); 4],
                },
                LockQuery {
                    actor: 1,
                    sql: &sql,
                    nonce,
                },
            )
            .unwrap();
        assert_eq!(step.outcome, expected);
        let Body::Transition(t) = &step.body else {
            unreachable!()
        };
        let r = Request::decode(&t.request).unwrap();
        let s = r.source(&c.application).unwrap();
        let Control::Active { registry, .. } =
            Control::decode(&c.application, t.updates[0].old).unwrap()
        else {
            unreachable!()
        };
        let e = locking::statement::Expected::checked(&s, r.genesis, r.parent, registry, r.plan)
            .unwrap();
        let verified = locking::wire::verify(&e, &t.proof).unwrap();
        assert_eq!(locking::statement::encoded(verified.next), registry);
        assert_eq!(t.updates[0].old, t.updates[0].new);
        let before = journal.best_validated();
        assert_eq!(
            import_candidate(&mut journal, &c.verifier(), &step.body),
            Err(Error::InvalidTransition)
        );
        assert_eq!(journal.best_validated(), before);
    }
}
fn private_registry_after_first() -> locking::trace::Registry {
    // Private PUBLIC NONSECRET prover fixture only. Journal never accepts this image.
    locking::trace::Registry {
        revision: 3,
        tx: core::array::from_fn(|t| locking::trace::Transaction {
            id: t as u32 + 1,
            controller: [0x41 + t as u8; 32],
            sequence: if t == 0 { 2 } else { 1 },
            failed: false,
            held: if t == 0 { [4, 4, 0, 0] } else { [0; 4] },
        }),
    }
}

#[test]
fn genuine_limit_zero_advances_counters_without_inventing_returned_rows() {
    let c = chain();
    let f = Fixture::new().unwrap();
    let mut j = c.journal(2);
    let parent = j.best_validated();
    let step = f
        .acquire(
            &j,
            parent,
            RegistryInput {
                state: &private_registry_after_first(),
                salt: [Val::from_u8(19); 4],
            },
            LockQuery {
                actor: 1,
                sql: "SELECT age FROM records LIMIT 0 FOR UPDATE",
                nonce: [0xC3; 32],
            },
        )
        .unwrap();
    assert_eq!(step.outcome, 0);
    assert_eq!(step.returned, [false; 4]);
    assert_eq!(step.next.revision, 4);
    assert_eq!(step.next.tx[1].sequence, 2);
    assert_eq!(step.next.tx[1].held, [0; 4]);
    let Body::Transition(t) = &step.body else {
        unreachable!()
    };
    assert_ne!(t.updates[0].old, t.updates[0].new);
    fixture::append(&mut j, &c.verifier(), parent.block, &step.body, 1003).unwrap();
    assert_eq!(j.best_validated().height, 3);
}

#[test]
fn canonical_request_and_entire_body_budgets_reject_before_proof_callback() {
    let c = chain();
    let t = c.transition(1);
    assert_eq!(t.request.len(), request::REQUEST_BYTES);
    assert_eq!(
        Request::decode(&t.request).unwrap().encode().unwrap(),
        t.request
    );
    for bytes in [
        &t.request[..t.request.len() - 1],
        &[t.request.as_slice(), &[0]].concat(),
        &[0; request::REQUEST_BYTES],
    ] {
        assert!(Request::decode(bytes).is_err());
    }
    let mut wrong = t.request.clone();
    wrong[9] = 1;
    assert!(Request::decode(&wrong).is_err());
    let size = body_size(t.request.len(), t.updates.len(), t.proof.len()).unwrap();
    assert_eq!(size, c.blocks[1].body.len());
    let mut p = c.genesis.profile.clone();
    p.max_body_bytes = size as u32;
    p.max_proof_bytes = t.proof.len() as u32;
    assert_eq!(
        bounded_body(&p, t.clone())
            .unwrap()
            .encode(&p)
            .unwrap()
            .len(),
        size
    );
    p.max_body_bytes -= 1;
    assert!(matches!(bounded_body(&p, t), Err(Error::ResourceLimit)));
    assert_eq!(body_size(usize::MAX, 1, 1), Err(Error::ResourceLimit));
    assert_eq!(body_size(1, usize::MAX, 1), Err(Error::ResourceLimit));
    assert_eq!(body_size(1, 1, usize::MAX), Err(Error::ResourceLimit));
}

#[test]
fn owner_signed_data_or_extra_updates_are_rejected_without_changing_source() {
    let c = chain();
    let v = c.verifier();
    let counted = CountVerifier {
        inner: &v,
        calls: Cell::new(0),
    };
    for extra in [false, true] {
        let mut journal = c.journal(1);
        let mut t = c.transition(1);
        let mut new = c.application.source;
        new.data[80] ^= 1;
        let data = ShardUpdate {
            id: SOURCE_ID,
            old: c.application.source,
            new,
        };
        if extra {
            t.updates.push(data);
            t.updates.sort_unstable_by_key(|u| u.id);
        } else {
            t.updates = vec![data];
        }
        assert!(import_candidate(&mut journal, &counted, &signed_body(c, t)).is_err());
        assert_eq!(
            journal
                .validated_shards(journal.best_validated())
                .unwrap()
                .iter()
                .find(|s| s.id == SOURCE_ID)
                .unwrap()
                .heads,
            c.application.source
        );
    }
    assert_eq!(counted.calls.get(), 2); // Signature is valid; the private adapter rejects both.
}

#[test]
fn stale_compare_and_swap_cannot_rebind_a_valid_old_query_to_current_parent() {
    let c = chain();
    let mut journal = c.journal(2);
    let mut t = c.transition(1);
    t.parent = journal.best_validated().block;
    let mut r = Request::decode(&t.request).unwrap();
    r.parent = t.parent;
    t.request = r.encode().unwrap();
    let before = journal.best_validated();
    assert_eq!(
        import_candidate(&mut journal, &c.verifier(), &signed_body(c, t)),
        Err(Error::InvalidTransition)
    );
    assert_eq!(journal.best_validated(), before);
}

struct OwnedDirectory {
    path: PathBuf,
}
impl OwnedDirectory {
    fn new() -> Self {
        for attempt in 0..100u32 {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dcs-private-journal-{}-{stamp}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    return Self {
                        path: path.canonicalize().unwrap(),
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("owned fixture directory: {e}"),
            }
        }
        panic!("unique owned directory")
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path.join("journal"));
        let _ = std::fs::remove_dir(&self.path);
    }
}
#[test]
fn durable_reopen_reverifies_real_proofs_and_lost_ack_resubmission_is_idempotent() {
    let c = chain();
    let directory = OwnedDirectory::new();
    let path = directory.path.join("journal");
    let namespace = [0xD1; 32];
    let v = c.verifier();
    let mut durable = DurableJournal::create(&path, c.genesis.clone(), namespace).unwrap();
    for b in &c.blocks {
        durable
            .append_block(b.header.clone(), &b.body, 10_000, &v)
            .unwrap();
    }
    let before = durable.disk_bytes();
    let tip = durable.journal().best_validated();
    let last = &c.blocks[2];
    durable
        .append_block(last.header.clone(), &last.body, 10_000, &v)
        .unwrap();
    assert_eq!(durable.disk_bytes(), before);
    assert_eq!(durable.journal().best_validated(), tip);
    drop(durable);
    let counted = CountVerifier {
        inner: &v,
        calls: Cell::new(0),
    };
    let reopened =
        DurableJournal::open(&path, c.genesis.clone(), namespace, 10_000, &counted).unwrap();
    assert_eq!(counted.calls.get(), 3);
    assert_eq!(reopened.journal().best_validated(), tip);
    drop(reopened);
    let mut wrong = c.genesis.clone();
    wrong.application_commitment[0] ^= 1;
    assert!(DurableJournal::open(&path, wrong, namespace, 10_000, &v).is_err());
}

#[test]
fn valid_detached_branch_is_not_a_fresh_head_and_its_proof_cannot_be_reparented() {
    let c = chain();
    let mut journal = c.journal(3);
    let v = c.verifier();
    let detached = journal.best_validated();
    fixture::append(&mut journal, &v, detached.block, &Body::Empty, 1004).unwrap();
    assert_eq!(
        journal.resolve(Freshness::AtLeast(detached)).unwrap(),
        detached
    );
    // Same genuine Acquire body is valid under its ORIGINAL Bootstrap parent on a fork.
    let body = Body::decode(&c.blocks[1].body, journal.profile()).unwrap();
    let fork = fixture::append(&mut journal, &v, c.blocks[0].header.id(), &body, 1010).unwrap();
    let mut parent = fork.id();
    for stamp in 1011..=1013 {
        parent = fixture::append(&mut journal, &v, parent, &Body::Empty, stamp)
            .unwrap()
            .id();
    }
    assert_eq!(journal.best_validated().block, parent);
    assert_eq!(
        journal.resolve(Freshness::AtLeast(detached)),
        Err(Error::Reorganized)
    );
    let mut t = c.transition(2);
    t.parent = parent;
    let mut r = Request::decode(&t.request).unwrap();
    r.parent = parent;
    t.request = r.encode().unwrap();
    let before = journal.best_validated();
    assert!(import_candidate(&mut journal, &v, &signed_body(c, t)).is_err());
    assert_eq!(journal.best_validated(), before);
}
