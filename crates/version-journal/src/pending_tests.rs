//! PUBLIC, NON-SECRET mechanical import fixtures. Empty blocks require no SQL
//! proof. Unproved Transition fixtures are rejection controls only; this module
//! contains no accepting application callback or purported FHE proof.
use super::*;
use crate::{
    AuthorizedTransition, DurableJournal, HeadPair, RejectUnprovedTransitions, ShardUpdate,
};
use ed25519_dalek::SigningKey;
use std::{
    cell::Cell,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn genesis() -> Genesis {
    Genesis {
        network_id: [1; 32],
        database: [2; 16],
        owner: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
        application_commitment: [4; 32],
        timestamp: 1000,
        profile: ProtocolProfile {
            initial_target: Target([255; 32]),
            pow_limit: Target([255; 32]),
            block_spacing_secs: 10,
            retarget_interval: 100,
            max_future_secs: 60,
            confirmation_depth: 1,
            max_headers: 32,
            max_shards: 2,
            max_updates: 1,
            max_body_bytes: 4096,
            max_request_bytes: 256,
            max_proof_bytes: 1024,
            max_journal_bytes: 1024 * 1024,
        },
        initial_shards: vec![ShardState {
            id: 7,
            heads: HeadPair {
                data: [5; 112],
                index: [6; 112],
            },
        }],
    }
}
pub(crate) fn empty(j: &Journal, parent: Hash, time: u64) -> (Header, Vec<u8>) {
    let body = Body::Empty;
    let wire = body.encode(j.profile()).unwrap();
    let mut header = j.candidate(parent, &body, time).unwrap();
    header.mine(1000).unwrap();
    (header, wire)
}
fn unproved(j: &Journal) -> (Header, Vec<u8>) {
    let mut transition = AuthorizedTransition {
        parent: j.genesis_id(),
        request: b"PUBLIC unproved request".to_vec(),
        updates: vec![ShardUpdate {
            id: 7,
            old: j.genesis().initial_shards[0].heads,
            new: HeadPair {
                data: [8; 112],
                index: [9; 112],
            },
        }],
        proof: b"PUBLIC invalid proof; rejection control only".to_vec(),
        owner_signature: [0; 64],
    };
    transition.sign(j.genesis_id(), &SigningKey::from_bytes(&[3; 32]));
    let body = Body::Transition(transition);
    let mut header = j.candidate(j.genesis_id(), &body, 1001).unwrap();
    header.mine(1000).unwrap();
    (header, body.encode(j.profile()).unwrap())
}
struct Reject(Cell<usize>);
impl TransitionVerifier for Reject {
    fn verify(&self, _: TransitionStatement<'_>) -> Result<()> {
        self.0.set(self.0.get() + 1);
        Err(Error::RejectedComputationProof)
    }
}

pub(crate) struct PublicFile {
    directory: PathBuf,
    file: PathBuf,
}
impl PublicFile {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..64 {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = parent.join(format!(
                "dcs-public-pending-journal-{}-{time}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    return Self {
                        file: directory.join("journal.bin"),
                        directory,
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create PUBLIC owned journal directory: {e}"),
            }
        }
        panic!("bounded PUBLIC journal directory allocation failed")
    }
    pub(crate) fn path(&self) -> &Path {
        &self.file
    }
}
impl Drop for PublicFile {
    fn drop(&mut self) {
        if self.directory.canonicalize().ok().as_ref() != Some(&self.directory) {
            return;
        }
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir(&self.directory); // no recursion or unknown files
    }
}

#[test]
fn fresh_import_drop_keeps_the_exact_head_floor_and_accounting() {
    let mut j = Journal::new(genesis()).unwrap();
    let root = j.genesis_head();
    let before = j.accounted_bytes();
    let (header, body) = empty(&j, root.block, 1001);
    drop(
        j.prepare_import(header.clone(), &body, 2000, &RejectUnprovedTransitions)
            .unwrap(),
    );
    assert_eq!(j.best_header(), root.block);
    assert_eq!(j.best_validated(), root);
    assert_eq!(j.ancestry_floor(), root);
    assert_eq!(j.header_count(), 0);
    assert_eq!(j.accounted_bytes(), before);
    assert!(j.header(header.id()).is_none());
    assert!(j.body(header.id()).is_none());

    let outcome = j
        .prepare_import(header.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap()
        .commit();
    assert_eq!(outcome.block, header.id());
    assert_eq!(j.best_validated().block, header.id());
    assert_eq!(j.body(header.id()), Some(body.as_slice()));
    assert_eq!(
        j.validated_shards(j.best_validated()).unwrap(),
        j.genesis().initial_shards
    );
}

#[test]
fn fresh_import_never_treats_a_cached_state_as_an_application_receipt() {
    let mut j = Journal::new(genesis()).unwrap();
    let (header, wire) = unproved(&j);
    let id = header.id();
    // Deliberately seed a private UNPROVED cache fixture. This does not pass any
    // accepting verifier, publish a SQL result or assert that this proof is valid.
    // The negative specifically reaches the known-complete-node branch.
    let Body::Transition(body) = Body::decode(&wire, j.profile()).unwrap() else {
        unreachable!()
    };
    let state = j
        .apply_changes(
            header.parent,
            &j.genesis.initial_shards,
            &Body::Transition(body),
        )
        .unwrap();
    let prepared = j
        .prepare_new_block(id, header.clone(), &wire, state)
        .unwrap();
    j.publish(prepared);
    let before_head = j.best_validated();
    let before_bytes = j.accounted_bytes();
    let reject = Reject(Cell::new(0));

    assert!(matches!(
        j.prepare_import(header.clone(), &wire, 2000, &reject),
        Err(Error::RejectedComputationProof)
    ));
    assert_eq!(reject.0.get(), 1);
    assert_eq!(j.best_validated(), before_head);
    assert_eq!(j.accounted_bytes(), before_bytes);
    assert_eq!(j.body(id), Some(wire.as_slice()));

    j.nodes.get_mut(&id).unwrap().invalid = true;
    assert!(matches!(
        j.prepare_import(header, &wire, 2000, &reject),
        Err(Error::InvalidAncestor)
    ));
    assert_eq!(reject.0.get(), 1);
}

#[test]
fn fresh_import_rejects_owner_and_application_before_publication() {
    let mut j = Journal::new(genesis()).unwrap();
    let root = j.genesis_head();
    let before_bytes = j.accounted_bytes();
    let (signed_header, signed) = unproved(&j);
    let Body::Transition(mut body) = Body::decode(&signed, j.profile()).unwrap() else {
        unreachable!()
    };
    body.owner_signature[0] ^= 1;
    let body = Body::Transition(body);
    let mut wrong_header = j.candidate(j.genesis_id(), &body, 1001).unwrap();
    wrong_header.mine(1000).unwrap();
    let wrong = body.encode(j.profile()).unwrap();
    let reject = Reject(Cell::new(0));
    assert!(matches!(
        j.prepare_import(wrong_header, &wrong, 2000, &reject),
        Err(Error::Unauthorized)
    ));
    assert_eq!(reject.0.get(), 0);
    assert!(matches!(
        j.prepare_import(signed_header, &signed, 2000, &reject),
        Err(Error::RejectedComputationProof)
    ));
    assert_eq!(reject.0.get(), 1);
    assert_eq!(j.best_validated(), root);
    assert_eq!(j.header_count(), 0);
    assert_eq!(j.accounted_bytes(), before_bytes);
}

#[test]
fn fresh_known_import_rejects_a_cached_state_different_from_the_checked_successor() {
    let mut j = Journal::new(genesis()).unwrap();
    let (header, body) = empty(&j, j.genesis_id(), 1001);
    let id = header.id();
    j.import_block(header.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    // Private hostile-cache control only: the genuine Empty successor is still
    // exactly the parent's unchanged state, independently fixed by the header.
    j.nodes.get_mut(&id).unwrap().state.as_mut().unwrap()[0]
        .heads
        .data[0] ^= 1;
    let bytes = j.accounted_bytes();
    assert!(matches!(
        j.prepare_import(header, &body, 2000, &RejectUnprovedTransitions),
        Err(Error::InvalidTransition)
    ));
    assert_eq!(j.accounted_bytes(), bytes);
    assert_eq!(j.header_count(), 1);
}

#[test]
fn fresh_import_preserves_header_only_capacity_and_historical_floor_rules() {
    let mut pinned = genesis();
    pinned.profile.max_headers = 2;
    let mut j = Journal::new(pinned).unwrap();
    let root = j.genesis_id();
    let (first, body) = empty(&j, root, 1001);
    j.import_header(first.clone(), 2000).unwrap();
    let header_only_bytes = j.accounted_bytes();
    drop(
        j.prepare_import(first.clone(), &body, 2000, &RejectUnprovedTransitions)
            .unwrap(),
    );
    assert_eq!(j.header_count(), 1);
    assert_eq!(j.accounted_bytes(), header_only_bytes);
    assert!(j.body(first.id()).is_none());
    j.prepare_import(first.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap()
        .commit();
    assert_eq!(j.header_count(), 1);
    let (second, _) = empty(&j, first.id(), 1002);
    j.prepare_import(second.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap()
        .commit();
    let floor = j.best_validated();
    j.restrict_ancestry_floor(floor).unwrap();
    let before_bytes = j.accounted_bytes();
    let (third, _) = empty(&j, second.id(), 1003);
    assert!(matches!(
        j.prepare_import(third, &body, 2000, &RejectUnprovedTransitions),
        Err(Error::ResourceLimit)
    ));
    // A known ancestor can be freshly checked, but cannot become a competing tip.
    j.prepare_import(first, &body, 2000, &RejectUnprovedTransitions)
        .unwrap()
        .commit();
    assert_eq!(j.best_validated(), floor);
    assert_eq!(j.ancestry_floor(), floor);
    assert_eq!(j.accounted_bytes(), before_bytes);
    assert_eq!(j.header_count(), 2);
    let (sibling, _) = empty(&Journal::new(j.genesis().clone()).unwrap(), root, 1004);
    assert!(matches!(
        j.prepare_import(sibling, &body, 2000, &RejectUnprovedTransitions),
        Err(Error::Reorganized)
    ));
}

#[test]
fn pending_append_drop_and_commit_keep_exact_legacy_record_bytes_and_reopen() {
    let path = PublicFile::new();
    let legacy_path = PublicFile::new();
    let pinned = genesis();
    let mut durable = DurableJournal::create(path.path(), pinned.clone(), [71; 32]).unwrap();
    let root = durable.journal().genesis_head();
    let before_disk = durable.disk_bytes();
    let before_ram = durable.journal().accounted_bytes();
    let (header, body) = empty(durable.journal(), root.block, 1001);
    let expected_disk = before_disk + 4 + HEADER_BYTES as u64 + body.len() as u64 + 32;
    let pending = durable
        .prepare_append(header.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    assert_eq!(pending.next_disk_bytes(), expected_disk);
    drop(pending);
    assert_eq!(durable.disk_bytes(), before_disk);
    assert_eq!(fs::metadata(path.path()).unwrap().len(), before_disk);
    assert_eq!(durable.journal().best_validated(), root);
    assert_eq!(durable.journal().accounted_bytes(), before_ram);
    durable
        .prepare_append(header.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap()
        .commit()
        .unwrap();
    let head = durable.journal().best_validated();
    let ram = durable.journal().accounted_bytes();
    let retry = durable
        .prepare_append(header.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    assert_eq!(retry.next_disk_bytes(), expected_disk);
    retry.commit().unwrap();
    assert_eq!(durable.journal().accounted_bytes(), ram);
    assert_eq!(durable.disk_bytes(), expected_disk);
    drop(durable);
    let exact = fs::read(path.path()).unwrap();
    let mut legacy = DurableJournal::create(legacy_path.path(), pinned.clone(), [71; 32]).unwrap();
    legacy
        .append_block(header, &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    drop(legacy);
    assert_eq!(exact, fs::read(legacy_path.path()).unwrap());
    let reopened = DurableJournal::open(
        path.path(),
        pinned,
        [71; 32],
        2000,
        &RejectUnprovedTransitions,
    )
    .unwrap();
    assert_eq!(reopened.journal().best_validated(), head);
    assert_eq!(reopened.disk_bytes(), expected_disk);
    assert_eq!(reopened.journal().accounted_bytes(), ram);
    drop(reopened);
    assert_eq!(fs::read(path.path()).unwrap(), exact);
}

#[test]
fn pending_append_rejects_unproved_mutation_without_file_or_head_changes() {
    let path = PublicFile::new();
    let mut durable = DurableJournal::create(path.path(), genesis(), [71; 32]).unwrap();
    let before_disk = durable.disk_bytes();
    let before_ram = durable.journal().accounted_bytes();
    let root = durable.journal().genesis_head();
    let (header, body) = unproved(durable.journal());
    let reject = Reject(Cell::new(0));
    assert!(matches!(
        durable.prepare_append(header, &body, 2000, &reject),
        Err(Error::RejectedComputationProof)
    ));
    assert_eq!(reject.0.get(), 1);
    assert_eq!(durable.disk_bytes(), before_disk);
    assert_eq!(fs::metadata(path.path()).unwrap().len(), before_disk);
    assert_eq!(durable.journal().accounted_bytes(), before_ram);
    assert_eq!(durable.journal().best_validated(), root);
}
