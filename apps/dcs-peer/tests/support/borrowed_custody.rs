//! Actual TLS custody replies retain full-file admission and availability rules.
use super::*;
use bincode::Options;
use peer_runtime::{
    ActivityPhase, PageAddress, PageBatchRequest, PageImage, ReadImageRequest, RemoteError,
};
use std::{
    io,
    sync::{Arc, Mutex},
};

fn pages_request(raw: &RawBundle, wrong_heads: bool) -> PageBatchRequest {
    let version = raw.target_version().unwrap();
    let (data, index) = if wrong_heads {
        (version.index_head(), version.data_head())
    } else {
        (version.data_head(), version.index_head())
    };
    PageBatchRequest::new(
        *version.object(),
        data,
        index,
        &[
            PageAddress {
                image: PageImage::Index,
                index: 0,
            },
            PageAddress {
                image: PageImage::Data,
                index: 0,
            },
        ],
    )
    .unwrap()
}
fn image_request(raw: &RawBundle, wrong_heads: bool) -> ReadImageRequest {
    let version = raw.target_version().unwrap();
    let (data, index) = if wrong_heads {
        (version.index_head(), version.data_head())
    } else {
        (version.data_head(), version.index_head())
    };
    ReadImageRequest::new(*version.object(), data, index, 1).unwrap()
}
fn request(raw: &RawBundle, image: bool, wrong_heads: bool) -> Request {
    if image {
        Request::FetchReadImage(image_request(raw, wrong_heads))
    } else {
        Request::FetchPages(pages_request(raw, wrong_heads))
    }
}
fn integrity(error: io::Error) {
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<RemoteError>()),
            Some(RemoteError::Integrity)
        ),
        "Unexpected custody error: {error}"
    );
}
fn available(remote: &RemotePeer, object: &[u8; 32]) -> bool {
    remote
        .status()
        .unwrap()
        .objects
        .iter()
        .find(|info| &info.id == object)
        .unwrap()
        .available
}

#[test]
fn borrowed_custody_replies_audit_omitted_tails_and_repair_before_request_binding() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let process = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let (owner, raw) = page_fixture();
    let object = *raw.target_version().unwrap().object();
    remote.call(Request::Store(raw.clone())).unwrap();
    let path = bundle_path(&process, &object);
    let original = fs::read(&path).unwrap();
    let data_tail =
        40 + 34 + 3 * 8 + raw.data_head.len() + raw.index_head.len() + raw.data.len() - 1;
    for image in [false, true] {
        integrity(
            remote
                .call(request(&raw, image, true))
                .err()
                .expect("Wrong heads reject"),
        );
        assert!(available(&remote, &object));
        for offset in [data_tail, original.len() - 1] {
            let mut damaged = original.clone();
            damaged[offset] ^= 1;
            fs::write(&path, damaged).unwrap();
            integrity(
                remote
                    .call(request(&raw, image, false))
                    .err()
                    .expect("Every physical byte is audited"),
            );
            assert!(!available(&remote, &object));

            fs::write(&path, &original).unwrap();
            integrity(
                remote
                    .call(request(&raw, image, true))
                    .err()
                    .expect("Repair does not fix wrong request heads"),
            );

            assert!(
                available(&remote, &object),
                "Physical repair succeeds independently of response binding"
            );
        }
    }
    let pages_request = pages_request(&raw, false);
    let pages = remote.fetch_pages(&pages_request).unwrap();
    assert_eq!(
        pages
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>(),
        pages_request.addresses()
    );
    assert_eq!(owner.decrypt(&pages[0].1).unwrap().as_bytes(), &[93; 8]);
    let reversed = PageBatchRequest::new(
        object,
        pages_request.data_head(),
        pages_request.index_head(),
        &pages_request
            .addresses()
            .iter()
            .copied()
            .rev()
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let pages = remote.fetch_pages(&reversed).unwrap();
    assert_eq!(
        pages
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>(),
        reversed.addresses()
    );
    assert_eq!(
        owner.decrypt(&pages[0].1).unwrap().as_bytes(),
        &(0u8..8).collect::<Vec<_>>()
    );
    let request = image_request(&raw, false);
    let image = remote.fetch_read_image(&request).unwrap();
    assert_eq!(image.data().encode(), raw.data);
    assert_eq!(
        owner
            .decrypt(&image.index_page(0, Limits::default()).unwrap())
            .unwrap()
            .as_bytes(),
        &[93; 8]
    );
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn malformed_custody_requests_never_clear_a_preexisting_invalid_marker() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let process = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let (_, raw) = page_fixture();
    let object = *raw.target_version().unwrap().object();
    remote.call(Request::Store(raw.clone())).unwrap();
    let path = bundle_path(&process, &object);
    let original = fs::read(&path).unwrap();
    for image in [false, true] {
        let mut corrupted = original.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupted).unwrap();
        integrity(
            remote
                .call(request(&raw, image, false))
                .err()
                .expect("Corrupt file rejects"),
        );
        assert!(!available(&remote, &object));
        fs::write(&path, &original).unwrap();
        let frame = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&(2u16, 77u64, request(&raw, image, false)))
            .unwrap();
        // Struct/tuple fixed-width fields agree; find the actual custody body
        // instead of reproducing Request enum tags in this malformed-wire test.
        let magic = if image { b"DCSRIMQ2" } else { b"DCSPAGQ2" };
        let body = frame.windows(8).position(|bytes| bytes == magic).unwrap();
        for fault in 0..4 {
            let mut malformed = frame.clone();
            match fault {
                0 => malformed[body + 8..body + 10].copy_from_slice(&3u16.to_le_bytes()),
                1 if image => {
                    malformed[body + 266..body + 270].copy_from_slice(&u32::MAX.to_le_bytes())
                }
                1 => malformed[body + 269..body + 277].copy_from_slice(&u64::MAX.to_le_bytes()),
                2 if image => {
                    malformed.pop();
                }
                2 => {
                    let first = malformed[body + 268..body + 277].to_vec();
                    malformed[body + 277..body + 286].copy_from_slice(&first);
                }
                _ => malformed.push(0),
            }
            let mut connection = connector.connect(&process.endpoint).unwrap();
            peer_transport::write_frame(
                &mut connection,
                &malformed,
                peer_transport::MAX_FRAME_BYTES,
            )
            .unwrap();
            assert!(peer_transport::read_frame(&mut connection, 65536).is_err());
            assert!(
                !available(&remote, &object),
                "No valid dispatch/audit occurred for malformed request {fault}"
            );
            assert_eq!(fs::read(&path).unwrap(), original);
        }
        integrity(
            remote
                .call(request(&raw, image, true))
                .err()
                .expect("Valid wrong heads reach the physical audit"),
        );
        assert!(available(&remote, &object));
    }
}

#[test]
fn borrowed_custody_reply_cancellation_keeps_exact_storage_and_next_scope_reads() {
    let authority = Authority::new();
    let owner_tls = authority.identity();
    let connector = Connector::new(&owner_tls, &authority.der).unwrap();
    let process = Process::start(&authority, owner_tls.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    let (_, raw) = page_fixture();
    let object = *raw.target_version().unwrap().object();
    remote.call(Request::Store(raw.clone())).unwrap();
    let path = bundle_path(&process, &object);
    let original = fs::read(&path).unwrap();
    for image in [false, true] {
        let control = peer_transport::RequestControl::default();
        let scope = control.begin().unwrap();
        let cancel = scope.cancellation();
        let traces = Arc::new(Mutex::new(Vec::new()));
        let sink = traces.clone();
        let operation = if image { "read-image" } else { "fetch-pages" };
        let cancelled = remote
            .clone()
            .with_control(control.clone())
            .with_activity(Arc::new(move |event| {
                if event.operation == operation && event.phase == ActivityPhase::ReplyReceived {
                    cancel.cancel();
                }
            }))
            .with_trace(Arc::new(move |trace| sink.lock().unwrap().push(trace)));

        let error = cancelled
            .call(request(&raw, image, false))
            .err()
            .expect("Cancellation is observed after the real reply");

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let observed = traces.lock().unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].operation, operation);
        assert!(!observed[0].succeeded);
        assert!(observed[0].response_bytes > 0);
        drop(observed);
        assert!(available(&remote, &object));
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(scope);
        let _next = control.begin().unwrap();
        remote
            .clone()
            .with_control(control)
            .call(request(&raw, image, false))
            .unwrap();
    }
}
