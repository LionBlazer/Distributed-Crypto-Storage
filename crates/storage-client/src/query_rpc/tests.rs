//! Scheduler outcome policy only; these callbacks do not execute or accept SQL.
use super::*;

fn remote() -> RemotePeer {
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["dcs-peer".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let identity = peer_runtime::Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    };
    RemotePeer::new(
        peer_runtime::Endpoint {
            address: "127.0.0.1:1".parse().unwrap(),
            identity: [1; 32],
        },
        peer_runtime::Connector::permissionless(&identity).unwrap(),
    )
}

#[test]
fn known_unexpected_success_and_remote_not_found_do_not_exclude_an_endpoint() {
    let remote = remote();
    let requests = Requests::read_query();
    for _ in 0..2 {
        assert!(
            requests
                .with_endpoint(&remote, None, || Ok::<Option<()>, io::Error>(None))
                .unwrap()
                .is_none()
        );
        let error = requests
            .with_endpoint(&remote, None, || {
                Err::<(), _>(io::Error::other(RemoteError::NotFound))
            })
            .unwrap_err();
        assert!(matches!(
            error.get_ref().unwrap().downcast_ref(),
            Some(RemoteError::NotFound)
        ));
    }
    // The returned value no longer owns the queue guard. Owner image validation
    // runs after this boundary, so its failures must not mark the endpoint down.
    let permits = requests.permits.lock().unwrap();
    assert!(permits.values().next().unwrap().try_lock().is_ok());
}

#[test]
fn malformed_transport_excludes_only_the_same_endpoint_for_this_read_query() {
    let remote = remote();
    let requests = Requests::read_query();
    assert!(
        requests
            .with_endpoint(&remote, None, || {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Malformed reply",
                ))
            })
            .is_err()
    );
    let error = requests
        .with_endpoint(&remote, None, || -> io::Result<()> {
            panic!("A remembered endpoint failure must not send another RPC")
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    Requests::read_query()
        .with_endpoint(&remote, None, || Ok(()))
        .unwrap();
}

#[test]
fn interruption_busy_and_default_mutation_policy_keep_their_existing_retry_scope() {
    let remote = remote();
    let requests = Requests::read_query();
    for error in [
        io::Error::new(io::ErrorKind::Interrupted, "Cancelled"),
        io::Error::other(RemoteError::Busy),
    ] {
        assert!(
            requests
                .with_endpoint(&remote, None, || Err::<(), _>(error))
                .is_err()
        );
        requests.with_endpoint(&remote, None, || Ok(())).unwrap();
    }
    let mutations = Requests::default();
    for _ in 0..2 {
        let error = mutations
            .with_endpoint(&remote, None, || {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Disconnected",
                ))
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "Disconnected");
    }
}

#[test]
fn missing_object_cache_does_not_block_unrelated_objects_or_head_pair_fetches() {
    let remote = remote();
    let requests = Requests::read_query();
    assert!(
        requests
            .with_endpoint(&remote, Some([3; 32]), || -> io::Result<()> {
                Err::<(), _>(io::Error::other(RemoteError::Integrity))
            })
            .is_err()
    );
    assert!(
        requests
            .with_endpoint(&remote, Some([3; 32]), || -> io::Result<()> {
                panic!("A damaged object must not be fetched again within this query")
            })
            .is_err()
    );
    requests
        .with_endpoint(&remote, Some([4; 32]), || Ok(()))
        .unwrap();
    requests.with_endpoint(&remote, None, || Ok(())).unwrap();
}
