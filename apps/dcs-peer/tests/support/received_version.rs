//! Public TLS fixtures for received-frame ownership and completed RPC semantics.
//! The synthetic replies below test only the codec, never accepted SQL/proofs.
use super::*;
use bincode::Options;
use peer_runtime::{ActivityPhase, RemoteError, Trace};
use std::{
    io,
    net::TcpListener,
    sync::{Arc, Mutex},
};

fn reply_once<T>(
    authority: &Authority,
    connector: &Connector,
    reply: impl FnOnce(u64) -> Vec<u8> + Send,
    client: impl FnOnce(RemotePeer) -> T,
) -> T {
    let identity = authority.identity();
    let acceptor = peer_transport::Acceptor::new(&identity, &authority.der).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let remote = RemotePeer::new(
        Endpoint {
            address: listener.local_addr().unwrap(),
            identity: identity.fingerprint(),
        },
        connector.clone(),
    );
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "No fixture client connected");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("Fixture accept failed: {error}"),
                }
            };
            let (_, mut stream) = acceptor.accept(socket).unwrap();
            let bytes =
                peer_transport::read_frame(&mut stream, peer_transport::MAX_FRAME_BYTES).unwrap();
            let (version, id, request): (u16, u64, Request) = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .reject_trailing_bytes()
                .deserialize(&bytes)
                .unwrap();
            assert_eq!(version, 2);
            assert!(matches!(request, Request::FetchVersion { .. }));
            peer_transport::write_frame(&mut stream, &reply(id), peer_transport::MAX_FRAME_BYTES)
                .unwrap();
        });
        let result = client(remote);
        worker.join().unwrap();
        result
    })
}
fn encode_reply(id: u64, result: Result<Response, RemoteError>) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&(2u16, id, result))
        .unwrap()
}

#[test]
fn received_version_trace_keeps_known_unexpected_success_distinct_from_remote_and_decode_errors() {
    let authority = Authority::new();
    let owner = authority.identity();
    let connector = Connector::new(&owner, &authority.der).unwrap();
    for kind in 0..4 {
        let traces = Arc::new(Mutex::new(Vec::<Trace>::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = traces.clone();
        let observed = events.clone();
        reply_once(
            &authority,
            &connector,
            move |id| match kind {
                0 => encode_reply(id, Ok(Response::Done)),
                1 => encode_reply(id, Err(RemoteError::NotFound)),
                2 => encode_reply(id + 1, Ok(Response::Done)),
                _ => {
                    let mut bytes = encode_reply(id, Ok(Response::Done));
                    bytes[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
                    bytes
                }
            },
            |remote| {
                let result = remote
                    .with_trace(Arc::new(move |trace| sink.lock().unwrap().push(trace)))
                    .with_activity(Arc::new(move |event| observed.lock().unwrap().push(event)))
                    .fetch_version(&[1; 112], &[2; 112]);
                match kind {
                    0 => assert!(result.unwrap().is_none()),
                    1 => assert!(matches!(
                        result.unwrap_err().get_ref().unwrap().downcast_ref(),
                        Some(RemoteError::NotFound)
                    )),
                    2 => assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData),
                    _ => assert!(result.is_err()),
                }
            },
        );
        let traces = traces.lock().unwrap();
        let events = events.lock().unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].phase, ActivityPhase::RequestSent);
        assert_eq!(events[1].phase, ActivityPhase::ReplyReceived);
        let trace = &traces[0];
        assert_eq!(trace.operation, "fetch-version");
        assert_eq!(trace.request_id, events[0].request_id);
        assert_eq!(trace.request_id, events[1].request_id);
        assert_eq!(trace.request_bytes, events[0].bytes);
        assert_eq!(trace.response_bytes, events[1].bytes);
        assert_eq!(trace.succeeded, kind == 0);
    }
}

#[test]
fn genuine_received_version_cancellation_after_reply_reports_failure_then_next_scope_reads_exact_images()
 {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let process = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let (owner, _) = backend::Owner::generate(*b"FRAME-TEST-00001").unwrap();
    let (raw, table_id) = fixture(&owner);
    remote.call(Request::Store(raw.clone())).unwrap();
    let control = peer_transport::RequestControl::default();
    let scope = control.begin().unwrap();
    let cancel = scope.cancellation();
    let traces = Arc::new(Mutex::new(Vec::<Trace>::new()));
    let sink = traces.clone();
    let cancelled = remote
        .clone()
        .with_control(control.clone())
        .with_activity(Arc::new(move |event| {
            if event.operation == "fetch-version" && event.phase == ActivityPhase::ReplyReceived {
                cancel.cancel();
            }
        }))
        .with_trace(Arc::new(move |trace| sink.lock().unwrap().push(trace)));

    let error = cancelled
        .fetch_version(&raw.data_head, &raw.index_head)
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    let observed = traces.lock().unwrap();
    assert_eq!(observed.len(), 1);
    assert!(!observed[0].succeeded);
    assert_eq!(
        observed[0].response_bytes,
        18 + 66
            + (raw.data_head.len() + raw.index_head.len() + raw.data.len() + raw.index.len())
                as u64
    );
    drop(observed);
    drop(scope);
    let _next = control.begin().unwrap();
    let received = remote
        .with_control(control)
        .fetch_version(&raw.data_head, &raw.index_head)
        .unwrap()
        .unwrap();
    let binding = received.target_version().unwrap();
    assert!(binding == raw.target_version().unwrap());
    assert_eq!(received.encoded_images(), (&*raw.data, &*raw.index));
    owner
        .validate_table_images_for_experiment(
            received.encoded_images().0,
            received.encoded_images().1,
            &table_id,
            binding.data_head(),
            binding.index_head(),
            Limits::default(),
        )
        .unwrap();
}
