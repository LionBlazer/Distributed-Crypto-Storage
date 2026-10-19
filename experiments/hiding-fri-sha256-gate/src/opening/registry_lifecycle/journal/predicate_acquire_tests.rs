//! PUBLIC NONSECRET witness fixtures; real signed history and actual SDK proofs.
//! No live peer, SQL answer, lock grant or finality is substituted by this consumer.
use super::super::{
    model::{Command, Operation},
    statement as lifecycle,
    trace::Witness as LifecycleWitness,
};
use super::fixture::{self, Fixture};
use crate::{
    backend::{Backend, Config, Val},
    opening::{fixture as source_fixture, proof_codec},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::Proof;
use registry200_proof::{
    admission::CanonicalSource,
    coefficient_encoding::{
        self as query,
        circuit::Witness as QueryWitness,
        statement::{BfvBinding, Expected as QueryExpected, Statement as Query},
    },
    predicate_acquire::{
        self as link, Expected,
        circuit::{Opening, Witness},
        wire::{self, Prerequisites},
    },
};
use std::sync::OnceLock;
use version_journal::{Body, Journal};
use zeroize::Zeroizing;

fn mask(ages: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    for age in ages {
        out[usize::from(*age) / 8] |= 1 << (*age % 8);
    }
    out
}
fn source_fixture() -> Fixture {
    let mut f = Fixture::new().unwrap();
    let data = [7, 1, 0, 18, 255, 0, 42, 0, 1, 255, 255, 255];
    let ages = [7u8, 18, 42, 255];
    let mut suffix = source_fixture::canonical_suffix();
    // Keep the independently reviewed Table/RowIds, rebuild this fixture's
    // exact counts, offsets, four one-byte postings and zero padding.
    suffix[32..2096].fill(0);
    for age in 0..256 {
        let count = ages.iter().filter(|v| usize::from(**v) == age).count() as u32;
        let before = ages.iter().filter(|v| usize::from(**v) < age).count() as u32;
        suffix[32 + 4 * age..36 + 4 * age].copy_from_slice(&count.to_le_bytes());
        suffix[1056 + 4 * age..1060 + 4 * age].copy_from_slice(&before.to_le_bytes());
    }
    suffix[2080..2084].copy_from_slice(&4u32.to_le_bytes());
    suffix[2084..2088].copy_from_slice(&[0, 1, 2, 3]);
    let (source, source_witness) = source_fixture::from_suffix(
        registry200_proof::source::Relation::CanonicalIndex,
        [0x71; 32],
        ([Val::ONE; 4], [Val::TWO; 4]),
        [0x83; 32],
        data,
        &suffix,
    )
    .unwrap();
    f.source.witness.plain[..12].copy_from_slice(&data);
    f.source.witness.plain[12..124].copy_from_slice(&source.heads[0]);
    f.source.witness.plain[124..].copy_from_slice(&suffix);
    f.source.source = source;
    f.source.source_witness = source_witness;
    f.application = super::Application::new(
        [0xAC; 32],
        fixture::SOURCE_ID,
        fixture::CONTROL_ID,
        &f.source.source,
    )
    .unwrap();
    f.genesis.database = f.application.database;
    f.genesis.application_commitment = f.application.id();
    f.genesis.initial_shards = f.application.initial_shards();
    f.application.require_genesis(&f.genesis).unwrap();
    f
}
fn actual_binding(database: [u8; 16]) -> BfvBinding {
    use bfv_query_core::{Geometry, KeyScope, Owner};
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let anchor = owner
        .key_anchor(
            &setup,
            KeyScope {
                database,
                bfv_key_domain: [0x71; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let proof = anchor.prove().unwrap();
    let checked = setup
        .verify_key_transform(anchor.public_anchor(), proof.as_bytes())
        .unwrap();
    BfvBinding::new(
        anchor.public_anchor().full_setup_id(),
        checked.statement().clone(),
    )
}
fn make_query(
    source: &registry200_proof::source::Statement,
    binding: BfvBinding,
    mask: [u8; 32],
    label: u8,
    source_bytes: &[u8],
) -> (Query, Vec<u8>) {
    let source = CanonicalSource::checked_claim(source).unwrap();
    // Independent, privately pinned query-only mask fixture. This does not claim
    // the current plain-SELECT compiler accepts locking SQL or parses SQL in AIR.
    let draft =
        QueryExpected::private_mask(&source, binding.clone(), [label; 32], [0xE8; 32], [0; 32])
            .unwrap();
    let command = query::commitment::command_digest(&query::commitment::command_fields(
        &draft,
        mask,
        [Val::from_u8(17); 4],
    ));
    let e = QueryExpected::private_mask(
        &source,
        binding,
        [label; 32],
        [0xE8; 32],
        lifecycle::encoded(command),
    )
    .unwrap();
    let witness = QueryWitness::private_mask(&e, Zeroizing::new(mask), [17; 4], [29; 4]).unwrap();
    let evidence = query::prove(&e, &witness, source_bytes).unwrap();
    let checked = query::wire::verify(&e, evidence.as_bytes()).unwrap();
    assert_eq!(checked.statement().values(), evidence.statement().values());
    evidence.into_parts()
}
fn opening(w: &LifecycleWitness, e: &lifecycle::Expected) -> Opening {
    let c = w.command.as_ref().unwrap();
    let step = w.old.step(c, e.parent, w.ages()).unwrap();
    Opening {
        mask: c.mask,
        transaction: c.transaction,
        principal: c.principal,
        controller: w.controllers[usize::from(c.principal - 1)],
        revision: w.old.revision,
        sequence: c.sequence,
        mode: c.mode,
        wait: c.wait,
        offset: c.offset,
        limit: c.limit,
        projection: c.projection,
        flags: [step.returned, step.skipped, step.visit],
        salts: [
            [17; 4],
            w.salts[3].map(|v| v.as_canonical_u64()),
            w.salts[5].map(|v| v.as_canonical_u64()),
        ],
    }
}
struct Published {
    witness: LifecycleWitness,
    expected: Expected,
    queries: [Query; 2],
    query_frames: [Vec<u8>; 2],
    lifecycle: Vec<u8>,
    link: Vec<u8>,
}
fn published() -> &'static Published {
    static PUBLIC: OnceLock<Published> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let f = source_fixture();
        let verifier = f.verifier().unwrap();
        let mut journal = Journal::new(f.genesis.clone()).unwrap();
        let parent = journal.genesis_head();
        let boot = f.bootstrap(&journal, parent, [0xA1; 32]).unwrap();
        fixture::append(&mut journal, &verifier, parent.block, &boot.body, 1001).unwrap();
        let mut state = boot.private;
        for (index, command) in [
            Command::control(Operation::Begin, 1, 1, 0),
            Command::control(Operation::Begin, 2, 2, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let parent = journal.best_validated();
            let produced = f
                .transition(&journal, parent, &state, command, [0xA2 + index as u8; 32])
                .unwrap();
            fixture::append(
                &mut journal,
                &verifier,
                parent.block,
                &produced.body,
                1002 + index as u64,
            )
            .unwrap();
            state = produced.private;
        }
        let mut other = Command::control(Operation::Acquire, 2, 2, 1);
        other.mask = mask(&[42]);
        other.mode = 4;
        other.wait = 2;
        other.limit = 4;
        other.projection = 3;
        let parent = journal.best_validated();
        let produced = f
            .transition(&journal, parent, &state, other, [0xA4; 32])
            .unwrap();
        fixture::append(&mut journal, &verifier, parent.block, &produced.body, 1004).unwrap();
        state = produced.private;
        assert_eq!(state.registry.transactions[1].held, [0, 0, 4, 0]);
        let mut command = Command::control(Operation::Acquire, 1, 1, 1);
        command.mask = mask(&[7, 42, 255]);
        command.mode = 4;
        command.wait = 2;
        command.offset = 1;
        command.limit = 1;
        command.projection = 3;
        let parent = journal.best_validated();
        let prepared = f
            .prepare(&journal, parent, &state, command, [0xA5; 32])
            .unwrap();
        let (e, w) = prepared.encoding_inputs();
        let e = e.clone();
        let w = w.clone();
        let produced = prepared.prove(&f.genesis, &Fixture::owner()).unwrap();
        assert_eq!(produced.outcome, 0);
        assert_eq!(produced.returned, [false, false, false, true]);
        assert_eq!(produced.skipped, [false, false, true, false]);
        assert_eq!(produced.private.registry.transactions[0].held, [4, 0, 0, 4]);
        let Body::Transition(t) = &produced.body else {
            unreachable!()
        };
        let frame = t.proof.clone();
        fixture::append(&mut journal, &verifier, parent.block, &produced.body, 1005).unwrap();
        let l = registry200_proof::wire::verify_claim(&e, &frame).unwrap();
        let parsed = registry200_proof::wire::frame::Frame::parse(
            registry200_proof::wire::frame::Role::Transition,
            &frame,
        )
        .unwrap();
        let binding = actual_binding(e.source.heads[0][8..24].try_into().unwrap());
        let (a, qa) = make_query(
            &e.source,
            binding.clone(),
            mask(&[7, 42, 255]),
            0xC1,
            parsed.source,
        );
        let (b, qb) = make_query(&e.source, binding, mask(&[7, 42]), 0xC1, parsed.source);
        // Isolate the private mask: both genuine parents retain the same public
        // SQL identity, nonce, full Source and complete BFV key context.
        assert_eq!(a.expected.sql_identity(), b.expected.sql_identity());
        assert_eq!(a.expected.public_nonce(), b.expected.public_nonce());
        assert_eq!(
            a.expected.source_claim().values(),
            b.expected.source_claim().values()
        );
        assert_eq!(a.expected.bfv().full_setup(), b.expected.bfv().full_setup());
        assert_eq!(
            a.expected.bfv().key().public_values(),
            b.expected.bfv().key().public_values()
        );
        assert_ne!(a.expected.command(), b.expected.command());
        assert_ne!(a.encoded, b.encoded);
        assert_eq!(
            a.expected.source_claim().request,
            b.expected.source_claim().request
        );
        let expected = Expected::new(&a, &l).unwrap();
        let wlink = Witness::new(&expected, opening(&w, &e)).unwrap();
        let parents = Prerequisites {
            query: &qa,
            lifecycle: &frame,
        };
        let evidence = link::prove(&expected, &wlink, &parents).unwrap();
        let link = evidence.into_parts().1;
        drop(wlink);
        drop(produced);
        drop(journal);
        drop(state);
        Published {
            witness: w,
            expected,
            queries: [a, b],
            query_frames: [qa, qb],
            lifecycle: frame,
            link,
        }
    })
}
fn source_proof(p: &Published) -> Proof<Config> {
    let frame = registry200_proof::wire::frame::Frame::parse(
        registry200_proof::wire::frame::Role::Transition,
        &p.lifecycle,
    )
    .unwrap();
    let backend = Backend::new(&p.expected.lifecycle().expected.source).unwrap();
    let shape = proof_codec::Topology::checked(11521, backend.report.quotient_chunks).unwrap();
    proof_codec::decode(frame.source, &shape, 16384, 24 * 1024 * 1024).unwrap()
}
fn own_lifecycle(p: &Published, c: Command) -> (lifecycle::Statement, Vec<u8>, LifecycleWitness) {
    let mut w = p.witness.clone();
    w.command = Some(c);
    let mut e = p.expected.lifecycle().expected.clone();
    let lifecycle::Phase::Transition { old, .. } = e.phase else {
        unreachable!()
    };
    e.phase = lifecycle::Phase::Transition {
        old,
        command: [Val::ZERO; 4],
    };
    let command = lifecycle::digest(&lifecycle::command_fields(
        &e,
        &w,
        w.command.as_ref().unwrap(),
    ));
    e.phase = lifecycle::Phase::Transition { old, command };
    let s = w.statement(&e).unwrap();
    let source = source_proof(p);
    let child = super::super::prove_child_with_trace(&e, &s, &source, || w.trace(&s)).unwrap();
    let frame = registry200_proof::wire::encode_claim(
        &e,
        &s,
        &registry200_proof::wire::CompositeProof {
            source: Some(source),
            child,
        },
    )
    .unwrap();
    assert_eq!(
        registry200_proof::wire::verify_claim(&e, &frame)
            .unwrap()
            .values(),
        s.values()
    );
    (s, frame, w)
}
fn reject_rebound(p: &Published, e: &Expected, parents: &Prerequisites<'_>) {
    let mut repaired = p.link.clone();
    repaired[48..112].copy_from_slice(&e.identity());
    assert!(wire::payload(e, &repaired).is_ok());
    let error = link::verify(e, parents, &repaired).err().unwrap();
    assert!(
        matches!(
            error,
            wire::Error::Proof(crate::backend::Error::Verification) | wire::Error::Verification
        ),
        "must reach actual link verification: {error:?}"
    );
}

#[test]
fn accepted_signed_acquire_links_the_actual_hidden_predicate_to_successful_result144() {
    let started = std::time::Instant::now();
    let p = published();
    let parents = Prerequisites {
        query: &p.query_frames[0],
        lifecycle: &p.lifecycle,
    };
    let verified = link::verify(&p.expected, &parents, &p.link).unwrap();
    assert_eq!(verified.expected().values(), p.expected.values());
    let fields = opening(&p.witness, &p.expected.lifecycle().expected);
    assert_eq!(
        fields.flags,
        [
            [false, false, false, true],
            [false, false, true, false],
            [true, false, false, true]
        ]
    );
    assert_eq!(p.expected.values().len(), 896);
    let report = link::analyze(&p.expected).unwrap();
    let query =
        query::wire::BorrowedFrame::parse(&p.queries[0].expected, &p.query_frames[0]).unwrap();
    let lifecycle = registry200_proof::wire::frame::Frame::parse(
        registry200_proof::wire::frame::Role::Transition,
        &p.lifecycle,
    )
    .unwrap();
    let payload = wire::payload(&p.expected, &p.link).unwrap();
    println!(
        "{}",
        serde_json::json!({
            "case":"private-predicate-acquire-signed-history",
            "trace_width":link::layout::WIDTH,"trace_height":512,"public_values":896,
            "unique_decoding_bits":report.unique_decoding_bits,
            "list_decoding_bits":report.list_decoding_bits,
            "constraints":report.constraints,"degree":report.degree,
            "quotient_chunks":report.quotient_chunks,"batched_functions":report.batched_functions,
            "source_proof_bytes":query.source().len(),
            "query_child_bytes":query.child().len(),"lifecycle_child_bytes":lifecycle.child.len(),
            "query_pair_bytes":p.query_frames[0].len(),"lifecycle_pair_bytes":p.lifecycle.len(),
            "link_frame_bytes":p.link.len(),
            "unique_proof_payload_bytes":query.source().len()+query.child().len()+lifecycle.child.len()+payload.len(),
            "detached_collection_bytes":p.query_frames[0].len()+p.lifecycle.len()+p.link.len(),
            "fixture_and_fresh_verify_ms":started.elapsed().as_secs_f64()*1000.,
            "returned":fields.flags[0],"skipped":fields.flags[1],"visited":fields.flags[2],
            "signed_history_bodies":5,"body_fit_proven":false,"input16_verified":false,
            "sql_grant":false,"fresh_finalized_head":false
        })
    );
    // Real validated history and proof bytes are retained, not a live SQL lease.
}

#[test]
fn individually_valid_same_q_different_masks_cannot_be_joined_by_repairing_headers() {
    let p = published();
    let b = &p.queries[1];
    let _ = query::wire::verify(&b.expected, &p.query_frames[1]).unwrap();
    let _ = registry200_proof::wire::verify_claim(&p.expected.lifecycle().expected, &p.lifecycle)
        .unwrap();
    assert_eq!(
        b.expected.source_claim().request,
        p.queries[0].expected.source_claim().request
    );
    let mixed = Expected::new(b, p.expected.lifecycle()).unwrap();
    assert!(Witness::new(&mixed, opening(&p.witness, &mixed.lifecycle().expected)).is_err());
    reject_rebound(
        p,
        &mixed,
        &Prerequisites {
            query: &p.query_frames[1],
            lifecycle: &p.lifecycle,
        },
    );
}

#[test]
fn genuine_wait_nowait_and_end_abort_proofs_are_not_successful_acquire_links() {
    let p = published();
    for wait in [0, 1, 3] {
        let mut c = p.witness.command.as_ref().unwrap().clone();
        if wait == 3 {
            c = Command::control(Operation::End, 1, 1, 1);
            c.abort = true;
        } else {
            c.wait = wait;
        }
        let (l, frame, w) = own_lifecycle(p, c);
        let step = w
            .old
            .step(w.command.as_ref().unwrap(), l.expected.parent, w.ages())
            .unwrap();
        assert_eq!(step.outcome, if wait == 3 { 3 } else { wait + 1 });
        // These are genuine mathematical attempts from the actual pre-Acquire
        // parent; no WAIT/NOWAIT unchanged-root attempt is asserted admitted.
        let e = Expected::new(&p.queries[0], &l).unwrap();
        assert!(Witness::new(&e, opening(&w, &l.expected)).is_err());
        reject_rebound(
            p,
            &e,
            &Prerequisites {
                query: &p.query_frames[0],
                lifecycle: &frame,
            },
        );
    }
}

#[test]
fn genuine_empty_all_skipped_and_limit_zero_success_links_keep_hidden_flags_complete() {
    let p = published();
    for case in 0..3 {
        let mut c = p.witness.command.as_ref().unwrap().clone();
        c.offset = 0;
        c.limit = 4;
        match case {
            0 => c.mask = [0; 32],
            1 => c.mask = mask(&[42]),
            _ => c.limit = 0,
        }
        let (l, frame, w) = own_lifecycle(p, c.clone());
        let parsed = registry200_proof::wire::frame::Frame::parse(
            registry200_proof::wire::frame::Role::Transition,
            &frame,
        )
        .unwrap();
        let (q, qframe) = make_query(
            &l.expected.source,
            p.queries[0].expected.bfv().clone(),
            c.mask,
            0xD1 + case,
            parsed.source,
        );
        let e = Expected::new(&q, &l).unwrap();
        let witness = Witness::new(&e, opening(&w, &l.expected)).unwrap();
        let parents = Prerequisites {
            query: &qframe,
            lifecycle: &frame,
        };
        let evidence = link::prove(&e, &witness, &parents).unwrap();
        drop(witness);
        let _ = link::verify(&e, &parents, evidence.as_bytes()).unwrap();
        let step = w.old.step(&c, l.expected.parent, w.ages()).unwrap();
        assert_eq!(step.outcome, 0);
        assert_eq!(step.returned, [false; 4]);
        if case == 1 {
            assert_eq!(step.skipped, [false, false, true, false]);
        } else {
            assert_eq!(step.skipped, [false; 4]);
        }
    }
}

#[test]
fn canonical_bad_source_is_rejected_before_query_or_link_child_resource_bombs() {
    let p = published();
    let mut source = source_proof(p);
    let mut roots = source.commitments.trace.roots().to_vec();
    roots[0][0] += Val::ONE;
    source.commitments.trace = p3_symmetric::MerkleCap::new(roots);
    let damaged =
        query::wire::encode_source(&p.expected.lifecycle().expected.source, &source).unwrap();
    let original =
        query::wire::BorrowedFrame::parse(&p.queries[0].expected, &p.query_frames[0]).unwrap();
    let mut q = p.query_frames[0][..query::wire::HEADER].to_vec();
    q[176..180].copy_from_slice(&(damaged.len() as u32).to_le_bytes());
    q[180..184].copy_from_slice(&9u32.to_le_bytes());
    q.extend(&damaged);
    q.extend([0xff; 9]);
    assert!(!original.child().is_empty());
    let old = registry200_proof::wire::frame::Frame::parse(
        registry200_proof::wire::frame::Role::Transition,
        &p.lifecycle,
    )
    .unwrap();
    let roots = [
        lifecycle::encoded(p.expected.lifecycle().next),
        lifecycle::encoded(p.expected.lifecycle().result),
    ];
    let l = registry200_proof::wire::frame::join(
        registry200_proof::wire::frame::Role::Transition,
        &roots,
        &damaged,
        old.child,
    )
    .unwrap();
    let mut bomb = p.link[..wire::HEADER].to_vec();
    bomb[112..116].copy_from_slice(&9u32.to_le_bytes());
    bomb.extend([0xff; 9]);
    assert!(matches!(
        link::verify(
            &p.expected,
            &Prerequisites {
                query: &q,
                lifecycle: &l
            },
            &bomb
        ),
        Err(wire::Error::Prerequisite)
    ));
}
