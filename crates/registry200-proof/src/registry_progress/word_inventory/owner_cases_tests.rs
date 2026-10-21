//! Actual full witness/native proof coverage. NONSECRET fixtures, no SQL grant.
use super::{
    air::ProgramAir,
    check, evaluate,
    expr::Node,
    owner_cases::{self, Case, Kind},
    plan::WIDTH,
    probe, probe_wire,
    public_values::Expected,
    witness::{self, PrivateTrace},
};
use bfv_hiding_stark::Val;
use p3_field::PrimeCharacteristicRing;
use std::time::Instant;
fn value(air: &ProgramAir, trace: &PrivateTrace, label: &str) -> Val {
    let id = *air
        .plan
        .pool
        .fields
        .get(label)
        .expect("actual complete semantic field");
    if let Node::Constant(x) = air.plan.pool.nodes[id] {
        return x;
    }
    let mut found = None;
    for (row, layout) in air.plan.rows.iter().enumerate() {
        for (slot, port) in layout.ports.iter().enumerate() {
            if port.provider && port.id == id {
                assert!(found.is_none(), "one provider per actual wire");
                found = Some(trace.0.values[row * WIDTH + 248 + slot]);
            }
        }
    }
    found.expect("nonhash semantic wire has one MAIN provider")
}
fn result_word(air: &ProgramAir, trace: &PrivateTrace, n: usize) -> Val {
    value(air, trace, &format!("stream/result/{n}"))
}
fn observe(c: &Case, air: &ProgramAir, trace: &PrivateTrace) {
    let o = &c.outcome;
    for i in 0..4 {
        if c.kind.predicate() {
            assert_eq!(
                value(air, trace, &format!("scan/search/{i}")),
                Val::from_bool(o.search[i]),
                "{} physical search {i}",
                c.kind.label()
            );
            assert_eq!(
                value(air, trace, &format!("scan/skipped/{i}")),
                Val::from_bool(o.skipped[i]),
                "{} physical skip {i}",
                c.kind.label()
            );
        } else {
            assert!(!o.search[i] && !o.skipped[i], "Control has no scan phase");
        }
        assert_eq!(
            result_word(air, trace, 123 + i),
            Val::from_bool(o.visited[i])
        );
        assert_eq!(
            result_word(air, trace, 127 + i),
            Val::from_bool(o.selected[i])
        );
        assert_eq!(result_word(air, trace, 131 + i), Val::from_bool(o.block[i]));
    }
    assert_eq!(result_word(air, trace, 117), Val::from_u8(o.action));
    assert_eq!(result_word(air, trace, 118), Val::from_u8(o.status));
    assert_eq!(
        result_word(air, trace, 121),
        Val::from_u8(c.input.walk.cursor)
    );
    assert_eq!(result_word(air, trace, 122), Val::from_u8(o.cursor));
    assert_eq!(result_word(air, trace, 143), Val::from_u32(o.holder as u32));
    assert_eq!(
        result_word(air, trace, 144),
        Val::from_u32((o.holder >> 32) as u32)
    );
    assert_eq!(result_word(air, trace, 145), Val::from_u8(o.holder_mode));
    assert_eq!(result_word(air, trace, 148), Val::from_u32(o.micro as u32));
    assert_eq!(
        result_word(air, trace, 149),
        Val::from_u32((o.micro >> 32) as u32)
    );
    // ALL208 words use their real semantic/hash wires, not just a reduced header.
    for bank in 0..2 {
        for i in 0..208 {
            assert_eq!(
                value(
                    air,
                    trace,
                    &format!("{}/serialized/{i}", if bank == 0 { "old" } else { "new" })
                ),
                c.input.banks[bank][i]
            );
        }
    }
    match c.kind {
        Kind::ConflictBeforeOffset => {
            assert_eq!(c.input.banks[1][194], Val::ONE);
            assert_eq!(o.visited, [false; 4]);
            assert_eq!(o.cursor, 0);
        }
        Kind::SkipBeforeOffset => {
            assert_eq!(c.next.slots[0].as_ref().unwrap().held, [0, 4, 4, 0]);
            assert_eq!(o.selected, [false, false, true, false]);
            assert_eq!(o.skipped, [true, false, false, false]);
        }
        Kind::LimitZero => {
            assert_eq!(o.search, [false; 4]);
            assert_eq!(c.next.slots[0].as_ref().unwrap().held, [0; 4]);
            assert_eq!(c.input.banks[1][194], Val::ZERO);
        }
        Kind::ResumePrefix => {
            assert!(
                c.old.slots[1].is_none(),
                "old holder may already have ended"
            );
            assert_eq!(c.input.walk.holder, 2);
            assert_eq!(c.input.walk.revision, 2);
            assert_eq!(c.old.revision, 3);
            assert_ne!(
                c.old.slots[0].as_ref().unwrap().snapshot,
                c.metadata.parent,
                "original snapshot is not rebound to current head"
            );
            assert_ne!(
                c.input.walk.call,
                c.old.slots[0].as_ref().unwrap().sequence,
                "original call is not sequence"
            );
            assert_eq!(c.next.slots[0].as_ref().unwrap().held, [4, 4, 4, 0]);
            for i in 0..4 {
                assert_eq!(result_word(air, trace, 135 + i), c.input.banks[0][195 + i]);
                assert_eq!(result_word(air, trace, 139 + i), Val::ZERO);
            }
        }
        Kind::NoWaitLatest => {
            let a = c.next.slots[0].as_ref().unwrap();
            assert!(a.failed);
            assert_eq!(a.held, [4, 0, 0, 0]);
            assert_eq!(
                a.frames[0].as_ref().unwrap().name,
                a.frames[1].as_ref().unwrap().name
            );
            assert_eq!(a.held, a.frames[1].as_ref().unwrap().saved);
            assert_ne!(a.held, a.frames[0].as_ref().unwrap().saved);
            assert_eq!(
                &c.input.banks[0][111..137],
                &c.input.banks[1][111..137],
                "both whole frames retained"
            );
            assert_eq!(o.status, 2, "prefix is Error, not returned successful rows");
        }
        Kind::EndCompact => {
            assert_eq!(
                &c.input.banks[1][84..137],
                &c.input.banks[0][137..190],
                "all53 words move by stable ID"
            );
            assert_eq!(
                &c.input.banks[1][194..199],
                &c.input.banks[0][199..204],
                "all5 progress words move with B"
            );
            assert!(c.input.banks[1][137..190].iter().all(|x| *x == Val::ZERO));
            assert!(c.input.banks[1][199..204].iter().all(|x| *x == Val::ZERO));
            assert_eq!(c.next.slots[0].as_ref().unwrap().id, 2);
            for i in 0..4 {
                assert_eq!(
                    result_word(air, trace, 139 + i),
                    Val::ZERO,
                    "ended A is not compacted B"
                );
            }
        }
    }
}
fn wrong(kind: Kind) -> Case {
    let mut c = owner_cases::case(kind);
    match kind {
        Kind::ConflictBeforeOffset => {
            c.outcome.cursor = 1;
            c.outcome.visited[0] = true;
        }
        Kind::SkipBeforeOffset => {
            c.next.slots[0].as_mut().unwrap().held[1] = 0;
        }
        Kind::LimitZero => {
            c.next.slots[0].as_mut().unwrap().held[2] = 4;
        }
        Kind::ResumePrefix => {
            c.old.slots[0].as_mut().unwrap().held[0] = 0;
            c.next.slots[0].as_mut().unwrap().held[0] = 0;
        }
        Kind::NoWaitLatest => {
            c.next.slots[0].as_mut().unwrap().failed = false;
        }
        Kind::EndCompact => {
            c.next.slots[0].as_mut().unwrap().sequence += 1;
        }
    }
    c.rebuild();
    c
}
fn equation_refusal(c: &Case) {
    Expected::checked(&c.metadata).unwrap(); // Shape succeeds; all roots rebuilt.
    match witness::prepare(&c.metadata, &c.input) {
        Err(evaluate::Error::Binding | evaluate::Error::Arithmetic) => {}
        Err(other) => panic!("nonsemantic refusal {other:?}"),
        Ok(_) => panic!("wrong repaired claim accepted"),
    }
}
#[test]
fn six_independent_owner_branches_have_real_proofs_and_repaired_claim_refusals() {
    for predicate in [true, false] {
        // OWN independent setups; release both before the other role (two-setup cap).
        let producer = probe::ProverSetup::new(predicate).unwrap();
        let receiver = probe::VerifierSetup::new(predicate).unwrap();
        for kind in Kind::ALL.into_iter().filter(|k| k.predicate() == predicate) {
            let c = owner_cases::case(kind);
            let public = Expected::checked(&c.metadata).unwrap();
            let (air, trace) =
                witness::prepare(&c.metadata, &c.input).expect("complete honest branch");
            check::all(&air, &trace, &public).unwrap();
            observe(&c, &air, &trace);
            drop(trace);
            drop(air);
            let began = Instant::now();
            let frame = producer
                .produce(&c.metadata, &c.input)
                .expect("genuine new proof for this exact branch");
            let produced = began.elapsed();
            let receive = Instant::now();
            receiver
                .verify(&c.metadata, &frame)
                .expect("own setup/current Expected/full native verification");
            let received = receive.elapsed();
            eprintln!(
                "word_owner_case case={} native_prove_ms={:.3} native_receive_ms={:.3} math_roundtrip_ms={:.3} frame_bytes={} actual_branch_proof=true Source=false DATA=false FHE=false head=false SQL=false",
                kind.label(),
                produced.as_secs_f64() * 1000.0,
                received.as_secs_f64() * 1000.0,
                (produced + received).as_secs_f64() * 1000.0,
                frame.len()
            );
            let bad = wrong(kind);
            equation_refusal(&bad);
            let bad_public = Expected::checked(&bad.metadata).unwrap();
            assert_ne!(
                public.values(),
                bad_public.values(),
                "downstream roots repaired"
            );
            // An honest proof is NOT authority for a different fully repaired next state.
            let payload = probe_wire::payload(&c.metadata, &frame).unwrap();
            let repaired = probe_wire::frame(&bad.metadata, payload).unwrap();
            assert!(probe_wire::payload(&bad.metadata, &repaired).is_ok());
            let (_, report) = probe::prescreen(&bad.metadata).unwrap();
            probe_wire::decode(
                probe_wire::payload(&bad.metadata, &repaired).unwrap(),
                &report,
            )
            .unwrap();
            assert_eq!(
                receiver.verify(&bad.metadata, &repaired),
                Err(probe::Error::Verification),
                "{} fullshape/repairedheader must fail native",
                kind.label()
            );
        }
    }
}
#[test]
fn resume_original_prefix_and_historical_holder_rules_refuse_repaired_attempts() {
    for change in 0..6 {
        let mut c = owner_cases::case(Kind::ResumePrefix);
        match change {
            0 => c.input.walk.revision = c.old.revision,
            1 => c.input.walk.revision = c.old.revision + 1,
            2 => c.input.walk.visited[0] = false,
            3 => c.input.command.wait = 1,
            4 => c.input.walk.holder = c.input.command.id,
            5 => {
                c.input.walk.sql[0] += Val::ONE;
                c.metadata.blind_sql = c.input.walk.sql;
            }
            _ => unreachable!(),
        }
        // Historical P remains fixed while Cmd/Stmt/next/Result are fully rebuilt.
        let original = c.old.slots[0].as_ref().unwrap().progress;
        c.rebuild();
        assert_eq!(c.old.slots[0].as_ref().unwrap().progress, original);
        equation_refusal(&c);
    }
}
