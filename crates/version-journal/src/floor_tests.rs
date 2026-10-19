//! Mechanical floor tests use genuine Empty blocks, not an accepting fake
//! application verifier. They confer no quorum-certificate authority.
use crate::*;
use std::cell::Cell;

fn genesis() -> Genesis {
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
fn empty(j: &Journal, parent: Hash, timestamp: u64) -> (Header, Vec<u8>) {
    let b = Body::Empty.encode(j.profile()).unwrap();
    let mut h = j.candidate(parent, &Body::Empty, timestamp).unwrap();
    h.mine(1000).unwrap();
    (h, b)
}
fn head(j: &Journal, h: &Header) -> HeadRef {
    HeadRef {
        genesis: j.genesis_id(),
        database: j.genesis().database,
        block: h.id(),
        height: h.height,
        state_root: h.state_root,
    }
}

#[test]
fn ancestry_floor_filters_both_cached_tips_and_every_new_adoption_path() {
    let mut j = Journal::new(genesis()).unwrap();
    let root = j.genesis_id();
    let (a, body) = empty(&j, root, 1001);
    j.import_block(a.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    let (b, _) = empty(&j, root, 1002);
    j.import_block(b.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    let (b2, _) = empty(&j, b.id(), 1003);
    j.import_block(b2.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    let (b3, _) = empty(&j, b2.id(), 1004);
    j.import_header(b3.clone(), 2000).unwrap();
    assert_eq!(j.best_header(), b3.id());
    assert_eq!(j.best_validated().block, b2.id());
    let floor = head(&j, &a);
    j.restrict_ancestry_floor(floor).unwrap();
    assert_eq!(j.ancestry_floor(), floor);
    assert_eq!(j.best_header(), a.id());
    assert_eq!(j.best_validated(), floor);
    assert_eq!(j.resolve(Freshness::LatestConfirmed).unwrap(), floor);
    assert_eq!(
        j.resolve(Freshness::Exact(j.genesis_head())),
        Err(Error::StaleHead)
    );
    assert_eq!(j.import_header(b3.clone(), 2000), Err(Error::Reorganized));
    assert_eq!(
        j.import_body(b3.id(), &body, &RejectUnprovedTransitions),
        Err(Error::Reorganized)
    );
    assert_eq!(
        j.import_block(b2, &body, 2000, &RejectUnprovedTransitions),
        Err(Error::Reorganized)
    );
    assert_eq!(
        j.candidate(root, &Body::Empty, 1010),
        Err(Error::Reorganized)
    );
    assert_eq!(
        j.restrict_ancestry_floor(j.genesis_head()),
        Err(Error::Reorganized)
    );
    assert_eq!(
        j.restrict_ancestry_floor(head(&j, &b)),
        Err(Error::Reorganized)
    );
    // A pure historical proof recheck is allowed; it cannot adopt the old branch.
    j.reverify_block(&b, &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    assert_eq!(j.best_validated(), floor);
    let (a2, _) = empty(&j, a.id(), 1005);
    j.import_block(a2.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    j.restrict_ancestry_floor(head(&j, &a2)).unwrap();
    j.import_block(a, &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    assert_eq!(j.best_validated().block, a2.id());
}

#[test]
fn explicit_reverification_never_uses_cached_body_or_skips_owner_before_application() {
    struct Reject(Cell<usize>);
    impl TransitionVerifier for Reject {
        fn verify(&self, _: TransitionStatement<'_>) -> Result<()> {
            self.0.set(self.0.get() + 1);
            Err(Error::RejectedComputationProof)
        }
    }
    let mut j = Journal::new(genesis()).unwrap();
    let (h, body) = empty(&j, j.genesis_id(), 1001);
    j.import_block(h.clone(), &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    j.reverify_block(&h, &body, 2000, &RejectUnprovedTransitions)
        .unwrap();
    let mut changed = body.clone();
    changed.push(0);
    assert!(
        j.reverify_block(&h, &changed, 2000, &RejectUnprovedTransitions)
            .is_err()
    );
    let mut transition = AuthorizedTransition {
        parent: h.id(),
        request: vec![0],
        proof: vec![0],
        updates: vec![ShardUpdate {
            id: 7,
            old: j.genesis().initial_shards[0].heads,
            new: HeadPair {
                data: [7; 112],
                index: [8; 112],
            },
        }],
        owner_signature: [0; 64],
    };
    let v = Reject(Cell::new(0));
    let mut header = j
        .candidate(h.id(), &Body::Transition(transition.clone()), 1002)
        .unwrap();
    header.mine(1000).unwrap();
    assert_eq!(
        j.reverify_block(
            &header,
            &Body::Transition(transition.clone())
                .encode(j.profile())
                .unwrap(),
            2000,
            &v
        ),
        Err(Error::Unauthorized)
    );
    assert_eq!(v.0.get(), 0);
    transition.sign(j.genesis_id(), &SigningKey::from_bytes(&[3; 32]));
    let body = Body::Transition(transition).encode(j.profile()).unwrap();
    header.body_hash = hash(&body);
    header.nonce = 0;
    header.mine(1000).unwrap();
    assert_eq!(
        j.reverify_block(&header, &body, 2000, &v),
        Err(Error::RejectedComputationProof)
    );
    assert_eq!(v.0.get(), 1);
    assert_eq!(j.best_validated().block, h.id());
}
