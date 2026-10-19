//! Actual random owner keys and real stored N4 data. Expected rows below are a
//! test oracle only; the peer receives ciphertexts and mathematical evidence.
use super::support::{Process, identity};
use bfv_query_core::{Geometry, KeyScope, Owner};
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use peer_runtime::{ActivityPhase, Connector, RawBundle, Request, Response};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use storage_client::private_predicate::{
    BfvContext, CompiledPrivatePredicate, FetchedSource, SourceOwner,
};
use zeroize::Zeroizing;

#[test]
#[ignore = "Runs real private Source/input16 and the complete 134-node FHE proof graph on an OS peer"]
fn stored_originals_and_hidden_where_complete_real_peer_fhe_after_private_source_drop() {
    let started = Instant::now();
    let identity = identity();
    let connector = Connector::permissionless(&identity).unwrap();
    let process = Process::start(identity.fingerprint(), 201);
    let activity = Arc::new(Mutex::new(Vec::new()));
    let observed = activity.clone();
    let remote = process
        .remote(&connector)
        .with_activity(Arc::new(move |event| observed.lock().unwrap().push(event)));
    let database = [0x41; 16];
    let mut key = Zeroizing::new([0; 32]);
    getrandom::getrandom(key.as_mut()).unwrap();
    let source_owner = SourceOwner::new(database, [0x42; 16], key).unwrap();
    let rows = [
        PlainRow { age: 7, amount: 0 },
        PlainRow {
            age: 42,
            amount: 65535,
        },
        PlainRow {
            age: 128,
            amount: 17,
        },
        PlainRow {
            age: 255,
            amount: 1,
        },
    ];
    let table = source_owner
        .seal_partition(
            &TableId::generate().unwrap(),
            &rows,
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let heads = ReadHeads::new(
        *table.table_id(),
        table.commitment(),
        table.index_commitment(),
        compact_store::Limits::default(),
    )
    .unwrap();
    let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    let object = bundle.target_version().unwrap().object().to_owned();
    assert!(matches!(
        remote.call(Request::Store(bundle)).unwrap(),
        Response::Stored(_)
    ));
    drop(table);
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        remote
            .call(Request::InstallSetup(setup.to_bytes().unwrap()))
            .unwrap(),
        Response::Setup(_)
    ));
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database,
                bfv_key_domain: [0x43; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let anchor = handle.public_anchor().clone();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    epoch.prove_key().unwrap();
    let Response::RawBundle(fetched) = remote.call(Request::Fetch { object }).unwrap() else {
        panic!("actual stored source required");
    };
    let mut blind = Zeroizing::new([0; 32]);
    getrandom::getrandom(blind.as_mut()).unwrap();
    let compiled = CompiledPrivatePredicate::compile(
        "SELECT age, amount FROM records WHERE age >= 42 AND age < 200",
        blind,
        [0x44; 32],
    )
    .unwrap();
    let prepare = Instant::now();
    let inputs = source_owner
        .produce(
            BfvContext {
                owner: &owner,
                setup: &setup,
                anchor: &anchor,
            },
            &mut epoch,
            FetchedSource {
                object,
                bundle: &fetched,
                heads: &heads,
            },
            &compiled,
            [0x45; 16],
        )
        .unwrap();
    let prepare_ms = prepare.elapsed().as_secs_f64() * 1000.;
    let (provenance, prepared, frames) = inputs.into_parts();
    let input_bytes = frames.as_input_evidence().byte_len().unwrap();
    drop(compiled);
    drop(fetched);
    drop(epoch);
    drop(handle);
    drop(source_owner);

    // Act: the independently running peer has no source key, private openings,
    // owner plaintext fixture or locally preselected answer.
    let computation = Instant::now();
    let checked = remote
        .prove_private_product(
            object,
            provenance,
            &prepared.request,
            &frames.as_input_evidence(),
        )
        .unwrap();
    let stream_ms = computation.elapsed().as_secs_f64() * 1000.;
    let output_bytes = checked.product().output_ciphertext().len();
    let answer = owner
        .decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            checked.encrypted_response(),
        )
        .unwrap();
    assert_eq!(
        answer
            .rows
            .iter()
            .map(|r| (r.ordinal, r.present, r.age, r.amount))
            .collect::<Vec<_>>(),
        vec![
            (0, false, 0, 0),
            (1, true, 42, 65535),
            (2, true, 128, 17),
            (3, false, 0, 0)
        ]
    );
    assert!(checked.product().output_sdk_security_bits() >= 144.);
    let events = activity.lock().unwrap();
    let replies = events
        .iter()
        .filter(|e| e.operation == "private-product" && e.phase == ActivityPhase::ReplyReceived)
        .collect::<Vec<_>>();
    assert_eq!(
        replies.len(),
        122,
        "Ready, output, claims, all118 records, terminal"
    );
    let requests = events
        .iter()
        .filter(|e| e.operation == "private-product" && e.phase == ActivityPhase::RequestSent)
        .collect::<Vec<_>>();
    assert_eq!(
        requests.len(),
        134,
        "Start,15 input frames,118 verified-stage demands"
    );
    println!(
        "{}",
        serde_json::json!({"case":"actual-stored-private-where-peer","peer_pid":process.pid(),"owner_pid":std::process::id(),
        "input_frames":15,"input_proofs":16,"logical_output_nodes":134,"output_records":118,"input_bytes":input_bytes,"output_ciphertext_bytes":output_bytes,
        "sent_application_bytes":requests.iter().map(|e|e.bytes).sum::<u64>(),"received_application_bytes":replies.iter().map(|e|e.bytes).sum::<u64>(),
        "prepare_ms":prepare_ms,"stream_and_full_verify_ms":stream_ms,"total_ms":started.elapsed().as_secs_f64()*1000.,
        "source_private_state_dropped_before_peer_work":true,"sql_grant":false,"fresh_finalized_head":false})
    );
    drop(events);
    process.finish(&remote);
}
