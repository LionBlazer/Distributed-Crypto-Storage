//! PUBLIC NONSECRET owner/Source/control fixture. Peers receive signed encrypted proof bodies only.
use super::super::model::{Command, Operation};
use super::{control::Control, fixture::Fixture, owner::PrivateState};
use crate::opening::peer_process::{Completion, ProcessPeer};
use p3_field::PrimeCharacteristicRing;
use peer_runtime::{ActivityPhase, JournalBlock, RemotePeer, Request, RequestControl, Response};
use registry200_journal::ApplicationDescriptor;
const ATTACK_CASES: usize = 15;
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use version_journal::{AuthorizedTransition, Body, Freshness, Header, Journal};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(yes: bool, why: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(std::io::Error::other(why).into())
    }
}
fn completed(peer: &Completion) -> Result<()> {
    let diagnostics: Vec<_> = peer.stderr.lines().collect();
    ensure(
        peer.code == 0
            && matches!(
                diagnostics.as_slice(),
                ["Proof backend: baseline" | "Proof backend: avx2" | "Proof backend: avx512"]
            ),
        &format!(
            "unexpected peer completion: code={} stderr={:?}",
            peer.code, peer.stderr
        ),
    )
}
fn initialize(
    peer: &RemotePeer,
    app: &registry200_journal::Application,
    genesis: &version_journal::Genesis,
) -> Result<()> {
    let application = ApplicationDescriptor::from_application(app)?.encode();
    let reply = peer.call(Request::InitRegistryJournal {
        genesis: genesis.encode()?,
        application,
    })?;
    ensure(
        matches!(reply,Response::JournalReady(id) if id==genesis.id().unwrap()),
        "wrong initialized Genesis",
    )
}
fn status(peer: &RemotePeer) -> Result<peer_runtime::Status> {
    match peer.call(Request::Status)? {
        Response::Status(s) => Ok(s),
        _ => Err("wrong status reply".into()),
    }
}
fn mine(
    peer: &RemotePeer,
    g: [u8; 32],
    parent: [u8; 32],
    body: &[u8],
    timestamp: u64,
) -> Result<JournalBlock> {
    match peer.call(Request::MineBlock {
        network: g,
        parent,
        body: body.to_vec(),
        timestamp,
        attempts: 16,
    })? {
        Response::Mined(b) => Ok(b),
        _ => Err("missing real mined block".into()),
    }
}
fn publish(peer: &RemotePeer, g: [u8; 32], b: &JournalBlock) -> Result<()> {
    let id = Header::decode(&b.header)?.id();
    ensure(
        matches!(peer.call(Request::PublishBlock{network:g,header:b.header.clone(),body:b.body.clone()})?,Response::JournalAccepted(x) if x==id),
        "wrong durable publish acknowledgement",
    )
}
fn sync_one(
    from: &RemotePeer,
    to: &RemotePeer,
    journal: &mut Journal,
    verifier: &registry200_journal::RegistryVerifier,
) -> Result<JournalBlock> {
    let mut known = vec![journal.genesis_id()];
    known.extend(journal.validated_blocks().into_iter().map(|(h, _)| h.id()));
    let Response::JournalBlocks(mut blocks) = from.call(Request::JournalBlocks {
        network: journal.genesis_id(),
        known,
    })?
    else {
        return Err("wrong sync reply".into());
    };
    ensure(
        blocks.len() == 1,
        "expected one newly validated public block",
    )?;
    let b = blocks.remove(0);
    publish(to, journal.genesis_id(), &b)?;
    journal.import_block(Header::decode(&b.header)?, &b.body, 10000, verifier)?;
    Ok(b)
}
fn resigned(mut t: AuthorizedTransition, f: &Fixture) -> Result<Vec<u8>> {
    t.sign(f.genesis.id()?, &Fixture::owner());
    Ok(Body::Transition(t).encode(&f.genesis.profile)?)
}
fn malformed_missing(t: &AuthorizedTransition, f: &Fixture) -> Result<Vec<u8>> {
    let mut absent = t.clone();
    absent.proof.clear();
    absent.sign(f.genesis.id()?, &Fixture::owner());
    ensure(
        Body::Transition(absent.clone()).encode(&f.genesis.profile)
            == Err(version_journal::Error::MissingComputationProof),
        "missing proof local hard guard",
    )?;
    // Deliberately invalid transport fixture, using the exact original public fixed-width prefix.
    let original = Body::Transition(t.clone()).encode(&f.genesis.profile)?;
    let prefix = 8 + 1 + 32 + 4 + t.request.len() + 4 + 456 * t.updates.len();
    let mut wire = original[..prefix].to_vec();
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire.extend_from_slice(&absent.owner_signature);
    Ok(wire)
}
fn cryptographic_rejection(result: std::io::Result<Response>, label: &str) -> Result<()> {
    match result {
        Err(error)
            if matches!(
                error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<peer_runtime::RemoteError>()),
                Some(peer_runtime::RemoteError::Cryptography(_))
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(std::io::Error::other(format!(
            "{label}: expected concrete Cryptography rejection, received {error}"
        ))
        .into()),
        Ok(_) => Err(std::io::Error::other(format!("{label}: malicious request succeeded")).into()),
    }
}
fn fetch_reopened(
    peer: &RemotePeer,
    genesis: &version_journal::Genesis,
    verifier: &registry200_journal::RegistryVerifier,
) -> Result<Journal> {
    let mut journal = Journal::new(genesis.clone())?;
    let mut eof = false;
    for _ in 0..=genesis.profile.max_headers {
        let mut known = vec![journal.genesis_id()];
        known.extend(journal.validated_blocks().into_iter().map(|(h, _)| h.id()));
        let Response::JournalBlocks(mut blocks) = peer.call(Request::JournalBlocks {
            network: journal.genesis_id(),
            known,
        })?
        else {
            return Err("unexpected reopened sync reply".into());
        };
        ensure(
            blocks.len() <= 1,
            "reopened peer returned aggregate history",
        )?;
        if blocks.is_empty() {
            eof = true;
            break;
        }
        let b = blocks.remove(0);
        ensure(
            b.body.len() <= genesis.profile.max_body_bytes as usize,
            "reopened body above pinned cap",
        )?;
        journal.import_block(Header::decode(&b.header)?, &b.body, 10000, verifier)?;
    }
    ensure(eof, "reopened peer history did not reach bounded EOF")?;
    Ok(journal)
}
fn reject_before_mining(
    peer: &RemotePeer,
    f: &Fixture,
    parent: [u8; 32],
    good: &Body,
) -> Result<usize> {
    let Body::Transition(t) = good else {
        return Err("transition required".into());
    };
    let before = status(peer)?.journal_bytes;
    let mut failures = 0;
    // Every changed nonempty body is honestly re-signed; authorization is not the cryptographic oracle.
    for case in 0..ATTACK_CASES {
        let bad = if case == 0 {
            malformed_missing(t, f)?
        } else {
            let mut bad = t.clone();
            match case {
                1 => {
                    let last = bad.proof.len() - 1;
                    bad.proof[last] ^= 1;
                }
                2 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    r.parent[31] ^= 1;
                    bad.request = r.encode()?;
                }
                3 => {
                    bad.updates[0].id = f.application.source_id;
                    bad.updates[0].old = f.application.source;
                    bad.updates[0].new = f.application.source;
                    bad.updates[0].new.data[111] ^= 1;
                }
                4 => {
                    bad.updates[0].old.data[64] ^= 1;
                }
                5 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    r.query[31] ^= 1;
                    bad.request = r.encode()?;
                }
                6 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    r.genesis[31] ^= 1;
                    bad.request = r.encode()?;
                }
                7 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    r.application[31] ^= 1;
                    bad.request = r.encode()?;
                }
                8 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    let mut root = crate::opening::statement::decode_digest(r.enrollment)?;
                    root[3] += crate::backend::Val::ONE;
                    r.enrollment = crate::opening::statement::encode_digest(root);
                    r.query = registry200_journal::intent_query(
                        &f.application,
                        r.genesis,
                        r.parent,
                        r.nonce,
                        r.enrollment,
                        r.operation,
                    );
                    bad.request = r.encode()?;
                }
                9 | 10 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    let bytes = if case == 9 { r.command } else { r.opening };
                    let mut root = crate::opening::statement::decode_digest(bytes)?;
                    root[3] += crate::backend::Val::ONE;
                    if case == 9 {
                        r.command = crate::opening::statement::encode_digest(root)
                    } else {
                        r.opening = crate::opening::statement::encode_digest(root)
                    };
                    bad.request = r.encode()?;
                }
                11 | 12 => {
                    let mut r = registry200_journal::Request::decode(&bad.request)?;
                    let page = case - 11;
                    let last = r.packets[page].len() - 1;
                    r.packets[page][last] ^= 1;
                    bad.request = r.encode()?;
                }
                _ => {
                    let original = &t.proof;
                    let view = registry200_proof::wire::frame::Frame::parse(
                        registry200_proof::wire::frame::Role::Transition,
                        original,
                    )
                    .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
                    let mut incomplete = original[..152].to_vec();
                    if case == 13 {
                        incomplete[80..84].copy_from_slice(&0u32.to_le_bytes());
                        incomplete.extend_from_slice(view.child)
                    } else {
                        incomplete[84..88].copy_from_slice(&0u32.to_le_bytes());
                        incomplete.extend_from_slice(view.source)
                    }
                    bad.proof = incomplete;
                }
            }
            resigned(bad, f)?
        };
        cryptographic_rejection(
            peer.call(Request::MineBlock {
                network: f.genesis.id()?,
                parent,
                body: bad,
                timestamp: 3000,
                attempts: 16,
            }),
            &format!("resigned case {case}"),
        )?;
        failures += 1;
    }
    ensure(
        status(peer)?.journal_bytes == before,
        "rejected mining mutated durable state",
    )?;
    Ok(failures)
}
fn persist_then_lose_ack(
    peer: &RemotePeer,
    g: [u8; 32],
    b: &JournalBlock,
    known: Vec<[u8; 32]>,
) -> Result<peer_runtime::Trace> {
    let persisted = Arc::new(AtomicBool::new(false));
    let observed = persisted.clone();
    let probe = peer.clone();
    let control = RequestControl::default();
    let cancellation = control.clone();
    let id = Header::decode(&b.header)?.id();
    let traces = Arc::new(Mutex::new(Vec::<peer_runtime::Trace>::new()));
    let observed_traces = traces.clone();
    let delayed = peer
        .clone()
        .with_control(control.clone())
        .with_trace(Arc::new(move |t| observed_traces.lock().unwrap().push(t)))
        .with_activity(Arc::new(move |a| {
            if a.operation == "journal-publish" && a.phase == ActivityPhase::RequestSent {
                let deadline = Instant::now() + Duration::from_secs(120);
                while Instant::now() < deadline {
                    if let Ok(Response::JournalBlocks(bs)) = probe.call(Request::JournalBlocks {
                        network: g,
                        known: known.clone(),
                    }) && bs
                        .iter()
                        .any(|b| Header::decode(&b.header).is_ok_and(|h| h.id() == id))
                    {
                        observed.store(true, Ordering::Release);
                        cancellation.cancel();
                        break;
                    }
                    std::thread::yield_now();
                }
            }
        }));
    let scope = control.begin()?;
    let result = delayed.call(Request::PublishBlock {
        network: g,
        header: b.header.clone(),
        body: b.body.clone(),
    });
    drop(scope);
    ensure(
        result
            .as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::Interrupted),
        "ACK loss was not observed cancellation",
    )?;
    ensure(
        persisted.load(Ordering::Acquire),
        "cancelled before independent durable observation",
    )?;
    let ts = traces.lock().unwrap();
    ensure(
        ts.len() == 1 && ts[0].response_bytes == 0 && !ts[0].succeeded,
        "unexpected ACK bytes observed",
    )?;
    let trace = ts[0].clone();
    drop(ts);
    let bytes = status(peer)?.journal_bytes;
    publish(peer, g, b)?;
    ensure(
        status(peer)?.journal_bytes == bytes,
        "exact retry increased disk",
    )?;
    Ok(trace)
}
pub(super) fn run(executable: &Path) -> Result<serde_json::Value> {
    let full = Instant::now();
    let f = Fixture::new()?;
    let g = f.genesis.id()?;
    let verifier = f.verifier()?;
    let mut local = Journal::new(f.genesis.clone())?;
    let mut first = ProcessPeer::spawn(executable, 512 * 1024 * 1024)?;
    let mut second = ProcessPeer::spawn(executable, 512 * 1024 * 1024)?;
    ensure(
        first.pid() != second.pid()
            && first.pid() != std::process::id()
            && second.pid() != std::process::id(),
        "distinct OS peers required",
    )?;
    let pids = [first.pid(), second.pid()];
    initialize(&first.remote, &f.application, &f.genesis)?;
    initialize(&second.remote, &f.application, &f.genesis)?;
    // Wrong descriptor cannot allocate a second application namespace.
    let before = status(&first.remote)?.journal_bytes;
    let mut wrong = ApplicationDescriptor::from_application(&f.application)?.encode();
    wrong[0] ^= 1;
    cryptographic_rejection(
        first.remote.call(Request::InitRegistryJournal {
            genesis: f.genesis.encode()?,
            application: wrong,
        }),
        "unknown descriptor",
    )?;
    ensure(
        status(&first.remote)?.journal_bytes == before,
        "unknown descriptor wrote disk",
    )?;
    let mut private: Option<PrivateState> = None;
    let mut acquired = None;
    let mut failures = 0;
    let mut bodies = Vec::new();
    let mut generation_ms = 0.;
    let mut transition_generation_calls = 0u64;
    let mut retry_generation_delta = 0;
    let mut lost_ack_trace = None;
    for step in 0..4 {
        let parent = local.best_validated();
        let started = Instant::now();
        transition_generation_calls += 1;
        let produced = if step == 0 {
            f.bootstrap(&local, parent, [0x90; 32])?
        } else {
            let mut c = Command::control(
                match step {
                    1 => Operation::Begin,
                    2 => Operation::Acquire,
                    _ => Operation::End,
                },
                1,
                1,
                (step - 1) as u64,
            );
            if step == 2 {
                c.mask = [255; 32];
                c.mode = 4;
                c.limit = 4;
            }
            f.transition(
                &local,
                parent,
                private.as_ref().unwrap(),
                c,
                [0x90 + step as u8; 32],
            )?
        };
        generation_ms += started.elapsed().as_secs_f64() * 1000.;
        let wire = produced.body.encode(&f.genesis.profile)?;
        if step == 1 {
            failures += reject_before_mining(&first.remote, &f, parent.block, &produced.body)?;
        }
        let b = mine(&first.remote, g, parent.block, &wire, 2000 + step as u64)?;
        ensure(b.body == wire, "peer changed owner signed body")?;
        if step == 3 {
            let mut known = vec![g];
            known.extend(local.validated_blocks().into_iter().map(|(h, _)| h.id()));
            let calls_before_retry = transition_generation_calls;
            lost_ack_trace = Some(persist_then_lose_ack(&first.remote, g, &b, known)?);
            retry_generation_delta = transition_generation_calls - calls_before_retry;
            ensure(
                retry_generation_delta == 0,
                "retry invoked transition producer",
            )?;
        } else {
            publish(&first.remote, g, &b)?;
        }
        let received = sync_one(&first.remote, &second.remote, &mut local, &verifier)?;
        ensure(
            received.header == b.header && received.body == b.body,
            "sync changed actual block",
        )?;
        bodies.push(wire.len());
        if step == 2 {
            acquired = Some(local.best_validated());
            ensure(
                produced.private.registry.transactions[0].held == [4; 4],
                "fixture oracle expected actual acquired locks",
            )?;
        }
        private = Some(produced.private);
    }
    let acquired = acquired.unwrap();
    let tip = local.best_validated();
    let account = local.accounted_bytes();
    let acquired_control = f.application.control(local.validated_shards(acquired)?)?;
    let ended_control = f.application.control(local.validated_shards(tip)?)?;
    ensure(
        acquired_control != ended_control,
        "End did not change actual control",
    )?;
    ensure(
        private.as_ref().unwrap().registry.transactions.is_empty(),
        "owner oracle End did not release transaction",
    )?;
    ensure(
        local.resolve(Freshness::Exact(acquired)).is_ok(),
        "confirmed historical Acquire unexpectedly disappeared",
    )?;
    // PUBLIC-only state is sufficient for fresh restart/reverify. No proof/backend retained here.
    let application = f.application.clone();
    let genesis = f.genesis.clone();
    drop(private);
    drop(f);
    let before = [
        status(&first.remote)?.journal_bytes,
        status(&second.remote)?.journal_bytes,
    ];
    let old_io = [first.observed_io()?, second.observed_io()?];
    let stopped = first.finish()?;
    completed(&stopped)?;
    let first_stopped = stopped;
    first = first.restart(executable)?;
    initialize(&first.remote, &application, &genesis)?;
    let stopped = second.finish()?;
    completed(&stopped)?;
    let second_stopped = stopped;
    second = second.restart(executable)?;
    initialize(&second.remote, &application, &genesis)?;
    let reopened_pids = [first.pid(), second.pid()];
    let all_pids = [pids[0], pids[1], reopened_pids[0], reopened_pids[1]];
    ensure(
        all_pids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 4,
        "restart must observe new distinct OS PIDs",
    )?;
    ensure(
        [
            status(&first.remote)?.journal_bytes,
            status(&second.remote)?.journal_bytes,
        ] == before,
        "reopen changed actual disk",
    )?;
    let mut fetched_counts = Vec::new();
    for peer in [&first.remote, &second.remote] {
        let reopened = fetch_reopened(peer, &genesis, &verifier)?;
        ensure(
            reopened.best_validated() == tip && reopened.accounted_bytes() == account,
            "reopened peer bytes failed exact independent replay",
        )?;
        ensure(
            application.control(reopened.validated_shards(tip)?)? == ended_control,
            "reopened peer changed exact End Source/control state",
        )?;
        fetched_counts.push(reopened.validated_blocks().len());
        drop(reopened);
    }
    // A real authorized sibling has the SAME Acquire body/root, but not the original acquired ancestry.
    let mut sibling = local
        .header(acquired.block)
        .ok_or("missing acquired header")?
        .clone();
    sibling.nonce = sibling
        .nonce
        .checked_add(1)
        .ok_or("fixture mining nonce exhausted")?;
    sibling.mine(16)?;
    ensure(
        sibling.id() != acquired.block,
        "sibling must be a distinct actual block",
    )?;
    let sibling_body = local
        .body(acquired.block)
        .ok_or("missing acquired body")?
        .to_vec();
    let sb = JournalBlock {
        header: sibling.encode().to_vec(),
        body: sibling_body,
    };
    publish(&first.remote, g, &sb)?;
    sync_one(&first.remote, &second.remote, &mut local, &verifier)?;
    let mut fork = sibling.id();
    for i in 0..2 {
        let empty = Body::Empty.encode(&genesis.profile)?;
        let b = mine(&first.remote, g, fork, &empty, 2100 + i)?;
        fork = Header::decode(&b.header)?.id();
        publish(&first.remote, g, &b)?;
        sync_one(&first.remote, &second.remote, &mut local, &verifier)?;
    }
    ensure(
        local.best_validated().block == fork,
        "real fork did not become best",
    )?;
    ensure(
        local.resolve(Freshness::AtLeast(acquired)) == Err(version_journal::Error::Reorganized),
        "expected exact acquired-ancestry Reorganized rejection",
    )?;
    let active = application.control(local.validated_shards(local.best_validated())?)?;
    ensure(
        active == acquired_control,
        "sibling must preserve EXACT original Acquire control roots",
    )?;
    ensure(
        matches!(
            Control::decode(&application, active)?,
            Control::Active { .. }
        ),
        "wrong fork control",
    )?;
    let final_disk = [
        status(&first.remote)?.journal_bytes,
        status(&second.remote)?.journal_bytes,
    ];
    let new_io = [first.observed_io()?, second.observed_io()?];
    let end1 = first.finish_on_eof()?;
    let end2 = second.finish_on_eof()?;
    completed(&end1)?;
    completed(&end2)?;
    let lost = lost_ack_trace.ok_or("missing observed lost ACK")?;
    let io = vec![
        serde_json::json!({"pid":pids[0],"request_bytes":old_io[0].0+lost.request_bytes,"response_bytes":old_io[0].1+lost.response_bytes}),
        serde_json::json!({"pid":pids[1],"request_bytes":old_io[1].0,"response_bytes":old_io[1].1}),
        serde_json::json!({"pid":reopened_pids[0],"request_bytes":new_io[0].0,"response_bytes":new_io[0].1}),
        serde_json::json!({"pid":reopened_pids[1],"request_bytes":new_io[1].0,"response_bytes":new_io[1].1}),
    ];
    let completions = [&first_stopped, &second_stopped, &end1, &end2]
        .into_iter()
        .zip(all_pids)
        .map(|(completion, pid)| {
            serde_json::json!({
                "pid": pid,
                "code": completion.code,
                "stdout": completion.stdout,
                "stderr": completion.stderr,
            })
        })
        .collect::<Vec<_>>();
    Ok(
        serde_json::json!({"stage":"verified_registry200_two_os_peer_control","peer_pids":pids,"reopened_peer_pids":reopened_pids,"all_peer_pids":all_pids,"peer_completions":completions,"observed_application_io":io,"signed_proof_bodies":4,"transition_generation_calls":transition_generation_calls,"retry_transition_generation_calls":retry_generation_delta,"body_bytes":bodies,"participant_quota_bytes":512u64*1024*1024,"peer_journal_bytes":final_disk,"resigned_rejections":failures,"source_immutable":true,"durable_reopen_reverified":true,"reopened_fetched_bodies":fetched_counts,"persisted_lost_ack_idempotent":true,"end_changed_current_control":true,"same_root_sibling_freshness_rejected":true,"eof_cleanup":true,"owner_generation_ms":generation_ms,"full_two_peer_ms":full.elapsed().as_secs_f64()*1000.,"sql_grant":false,"global_finality":false,"writer_grant":false}),
    )
}
pub(super) fn gate(
    mode: &str,
    executable: Option<&Path>,
) -> std::result::Result<(), crate::backend::Error> {
    if mode == "security" {
        let f = Fixture::new().map_err(|_| crate::backend::Error::Shape)?;
        let (e, w) = f.source.bootstrap()?;
        crate::security(&e.source, "registry200-peer-control-source")?;
        crate::security(&w.statement(&e)?, "registry200-peer-control-bootstrap")?;
        let (e, w) = f.source.begin()?;
        crate::security(&w.statement(&e)?, "registry200-peer-control-transition")?;
        return Ok(());
    }
    if mode != "prove" {
        return Err(crate::backend::Error::Shape);
    }
    let v = run(executable.ok_or(crate::backend::Error::Shape)?).map_err(|e| {
        eprintln!("{e}");
        crate::backend::Error::Verification
    })?;
    println!("{v}");
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn actual_two_os_peers_verify_sync_reopen_retry_and_reorganization() {
        let exe = std::env::var_os("DCS_PEER_EXE")
            .expect("this real-process test requires independently built DCS_PEER_EXE");
        let v = super::run(std::path::Path::new(&exe)).unwrap();
        assert_eq!(v["signed_proof_bodies"], 4);
        assert_eq!(v["resigned_rejections"], super::ATTACK_CASES);
        assert_eq!(v["persisted_lost_ack_idempotent"], true);
        assert_eq!(v["sql_grant"], false);
    }
}
