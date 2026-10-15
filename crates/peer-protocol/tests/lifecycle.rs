use peer_protocol::{
    Envelope, MAX_NEIGHBORS, MAX_OUTSTANDING_REQUESTS, MAX_PAYLOAD_BYTES, MAX_PENDING_JOBS,
    Message, NodeId, NodeRole, ProtocolError, ProtocolEvent, ProtocolNode, REPLAY_WINDOW,
    RequestToken,
};

fn sent(event: ProtocolEvent) -> Envelope {
    match event {
        ProtocolEvent::Send(envelope) => envelope,
        _ => panic!("expected outgoing frame"),
    }
}
fn connect(a: &mut ProtocolNode, b: &mut ProtocolNode) -> [Envelope; 3] {
    let ping = sent(a.discover(b.id()).unwrap().remove(0));
    let pong = sent(b.receive(ping.clone()).unwrap().remove(0));
    let ack = sent(a.receive(pong.clone()).unwrap().remove(1));
    b.receive(ack.clone()).unwrap();
    [ping, pong, ack]
}
fn pair() -> (ProtocolNode, ProtocolNode) {
    let mut a = ProtocolNode::new(1, NodeRole::Client);
    let mut b = ProtocolNode::new(2, NodeRole::Peer);
    connect(&mut a, &mut b);
    (a, b)
}
fn accepted(events: Vec<ProtocolEvent>, from: NodeId, id: u64) -> RequestToken {
    match events.as_slice() {
        [
            ProtocolEvent::Request {
                from: actual,
                id: actual_id,
                token,
                ..
            },
        ] if *actual == from && *actual_id == id => *token,
        _ => panic!("expected exactly one accepted request"),
    }
}
fn deliver(a: &mut ProtocolNode, b: &mut ProtocolNode, id: u64) -> (Envelope, RequestToken) {
    let frame = sent(
        a.request(b.id(), id, b"opaque-ciphertext-reference".to_vec())
            .unwrap(),
    );
    let token = accepted(b.receive(frame.clone()).unwrap(), a.id(), id);
    (frame, token)
}
fn complete(a: &mut ProtocolNode, b: &mut ProtocolNode, id: u64) {
    let (_, token) = deliver(a, b, id);
    let response = sent(b.respond(a.id(), id, token).unwrap());
    assert_eq!(
        a.receive(response).unwrap(),
        vec![ProtocolEvent::Response { from: b.id(), id }]
    );
}

#[test]
fn discovery_hint_and_mismatched_pong_do_not_establish_a_route() {
    let mut client = ProtocolNode::new(1, NodeRole::Client);
    client.discover(2).unwrap();
    assert!(!client.connected(2));
    assert_eq!(
        client.request(2, 7, vec![]),
        Err(ProtocolError::NotConnected)
    );
    let forged = Envelope {
        from: 2,
        to: 1,
        message: Message::Pong {
            nonce: 999,
            challenge: 1,
        },
    };
    assert_eq!(client.receive(forged), Err(ProtocolError::InvalidEnvelope));
}

#[test]
fn matching_response_consumes_both_slots_and_duplicate_response_is_rejected() {
    let (mut client, mut peer) = pair();
    let (_, token) = deliver(&mut client, &mut peer, 7);
    assert_eq!((client.outstanding_requests(), peer.pending_jobs()), (1, 1));
    let response = sent(peer.respond(1, 7, token).unwrap());
    assert_eq!(
        peer.respond(1, 7, token),
        Err(ProtocolError::UnknownRequest)
    );
    assert_eq!(
        client.receive(response.clone()).unwrap(),
        vec![ProtocolEvent::Response { from: 2, id: 7 }]
    );
    assert_eq!(
        client.receive(response),
        Err(ProtocolError::UnexpectedResponse)
    );
    assert_eq!((client.outstanding_requests(), peer.pending_jobs()), (0, 0));
}

#[test]
fn unsolicited_and_wrong_peer_responses_do_not_consume_a_real_request() {
    let (mut client, mut peer) = pair();
    let mut other = ProtocolNode::new(3, NodeRole::Peer);
    connect(&mut client, &mut other);
    let (_, token) = deliver(&mut client, &mut peer, 7);
    assert_eq!(
        other.respond(1, 7, token),
        Err(ProtocolError::InvalidEnvelope)
    );
    let wrong_peer = Envelope {
        from: 3,
        to: 1,
        message: Message::Response { id: 7, token },
    };
    assert_eq!(
        client.receive(wrong_peer),
        Err(ProtocolError::InvalidEnvelope)
    );
    let unsolicited = Envelope {
        from: 2,
        to: 1,
        message: Message::Response { id: 99, token },
    };
    assert_eq!(
        client.receive(unsolicited),
        Err(ProtocolError::UnexpectedResponse)
    );
    assert_eq!(client.outstanding_requests(), 1);
    assert!(
        client
            .receive(sent(peer.respond(1, 7, token).unwrap()))
            .is_ok()
    );
}

#[test]
fn duplicate_requests_never_emit_a_second_job_before_or_after_completion() {
    let (mut client, mut peer) = pair();
    let (request, token) = deliver(&mut client, &mut peer, 7);
    assert_eq!(peer.receive(request.clone()), Err(ProtocolError::Replay));
    assert_eq!(
        client.request(2, 7, vec![]),
        Err(ProtocolError::DuplicateRequest)
    );
    let response = sent(peer.respond(1, 7, token).unwrap());
    client.receive(response).unwrap();
    assert_eq!(peer.receive(request), Err(ProtocolError::Replay));
}

#[test]
fn cancelled_attempt_cannot_execute_even_when_cancel_arrives_before_request() {
    let (mut client, mut peer) = pair();
    let delayed = sent(client.request(2, 7, vec![]).unwrap());
    let cancel = sent(client.cancel_request(2, 7).unwrap());
    assert!(matches!(
        peer.receive(cancel.clone()).unwrap().as_slice(),
        [ProtocolEvent::Cancelled { id: 7, .. }]
    ));
    assert_eq!(peer.receive(delayed), Err(ProtocolError::Replay));
    assert_eq!(peer.receive(cancel), Err(ProtocolError::Replay));
    assert_eq!((client.outstanding_requests(), peer.pending_jobs()), (0, 0));
    assert!(client.cancel_request(2, 7).is_none());
    complete(&mut client, &mut peer, 7);
}

#[test]
fn cancellation_and_id_reuse_reject_old_work_completion_and_old_response() {
    let (mut client, mut peer) = pair();
    let (_, old_token) = deliver(&mut client, &mut peer, 7);
    let late_response = Envelope {
        from: 2,
        to: 1,
        message: Message::Response {
            id: 7,
            token: old_token,
        },
    };
    peer.receive(sent(client.cancel_request(2, 7).unwrap()))
        .unwrap();
    let (_, new_token) = deliver(&mut client, &mut peer, 7);
    assert_ne!(old_token, new_token);
    assert_eq!(
        peer.respond(1, 7, old_token),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(
        client.receive(late_response),
        Err(ProtocolError::UnexpectedResponse)
    );
    assert_eq!((client.outstanding_requests(), peer.pending_jobs()), (1, 1));
    client
        .receive(sent(peer.respond(1, 7, new_token).unwrap()))
        .unwrap();
}

#[test]
fn same_id_on_different_peers_and_bidirectional_peer_requests_are_independent() {
    let mut a = ProtocolNode::new(1, NodeRole::Peer);
    let mut b = ProtocolNode::new(2, NodeRole::Peer);
    let mut c = ProtocolNode::new(3, NodeRole::Peer);
    connect(&mut a, &mut b);
    connect(&mut a, &mut c);
    let (_, ab) = deliver(&mut a, &mut b, 7);
    let (_, ac) = deliver(&mut a, &mut c, 7);
    let (_, ba) = deliver(&mut b, &mut a, 7);
    assert_ne!(ab, ba);
    a.receive(sent(c.respond(1, 7, ac).unwrap())).unwrap();
    assert_eq!(a.outstanding_requests(), 1);
    b.receive(sent(a.respond(2, 7, ba).unwrap())).unwrap();
    a.receive(sent(b.respond(1, 7, ab).unwrap())).unwrap();
}

#[test]
fn outbound_quota_is_bounded_and_cancellation_releases_the_local_slot_immediately() {
    let (mut client, _) = pair();
    for id in 0..MAX_OUTSTANDING_REQUESTS as u64 {
        client.request(2, id, vec![]).unwrap();
    }
    assert_eq!(
        client.request(2, 999, vec![]),
        Err(ProtocolError::ResourceLimit)
    );
    assert!(client.cancel_request(2, 0).is_some());
    assert!(client.request(2, 999, vec![]).is_ok());
    assert_eq!(client.outstanding_requests(), MAX_OUTSTANDING_REQUESTS);
    client.forget(2);
    assert_eq!(client.outstanding_requests(), 0);
}

#[test]
fn inbound_quota_is_global_and_remote_slot_releases_only_after_cancel_delivery() {
    let (mut client, mut peer) = pair();
    let mut other = ProtocolNode::new(3, NodeRole::Client);
    connect(&mut other, &mut peer);
    for id in 0..MAX_PENDING_JOBS as u64 {
        deliver(&mut client, &mut peer, id);
    }
    let retryable = sent(other.request(2, 99, vec![]).unwrap());
    assert_eq!(
        peer.receive(retryable.clone()),
        Err(ProtocolError::ResourceLimit)
    );
    let cancel = client.cancel_request(2, 0).unwrap();
    assert_eq!(peer.pending_jobs(), MAX_PENDING_JOBS);
    peer.receive(sent(cancel)).unwrap();
    assert_eq!(peer.pending_jobs(), MAX_PENDING_JOBS - 1);
    accepted(peer.receive(retryable).unwrap(), 3, 99);
    assert_eq!(peer.pending_jobs(), MAX_PENDING_JOBS);
}

#[test]
fn local_discard_releases_job_but_keeps_attempt_terminal() {
    let (mut client, mut peer) = pair();
    let (request, token) = deliver(&mut client, &mut peer, 7);
    peer.discard_request(1, 7, token).unwrap();
    assert_eq!(peer.pending_jobs(), 0);
    assert_eq!(peer.receive(request), Err(ProtocolError::Replay));
    assert_eq!(
        peer.respond(1, 7, token),
        Err(ProtocolError::UnknownRequest)
    );
}

#[test]
fn repeated_handshake_does_not_reset_replay_history() {
    let mut client = ProtocolNode::new(1, NodeRole::Client);
    let mut peer = ProtocolNode::new(2, NodeRole::Peer);
    let [ping, pong, ack] = connect(&mut client, &mut peer);
    let (old, token) = deliver(&mut client, &mut peer, 7);
    client
        .receive(sent(peer.respond(1, 7, token).unwrap()))
        .unwrap();
    assert_eq!(sent(peer.receive(ping).unwrap().remove(0)), pong.clone());
    assert_eq!(sent(client.receive(pong).unwrap().remove(0)), ack.clone());
    peer.receive(ack).unwrap();
    assert_eq!(peer.receive(old), Err(ProtocolError::Replay));
}

#[test]
fn reconnect_rejects_old_handshakes_requests_responses_and_completions() {
    let mut client = ProtocolNode::new(1, NodeRole::Client);
    let mut peer = ProtocolNode::new(2, NodeRole::Peer);
    let [old_ping, old_pong, old_ack] = connect(&mut client, &mut peer);
    let (old_request, old_token) = deliver(&mut client, &mut peer, 7);
    let old_response = sent(peer.respond(1, 7, old_token).unwrap());
    client.forget(2);
    peer.forget(1);
    assert_eq!((client.outstanding_requests(), peer.pending_jobs()), (0, 0));
    peer.receive(old_ping).unwrap(); // delayed Ping obtains a new responder challenge
    assert_eq!(peer.receive(old_ack), Err(ProtocolError::InvalidEnvelope));
    connect(&mut client, &mut peer);
    assert_eq!(
        client.receive(old_pong),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(
        peer.receive(old_request),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(
        client.receive(old_response),
        Err(ProtocolError::InvalidEnvelope)
    );
    let (_, current) = deliver(&mut client, &mut peer, 7);
    assert_eq!(
        peer.respond(1, 7, old_token),
        Err(ProtocolError::InvalidEnvelope)
    );
    client
        .receive(sent(peer.respond(1, 7, current).unwrap()))
        .unwrap();
}

#[test]
fn simultaneous_bidirectional_discovery_converges_in_either_delivery_order() {
    for reverse in [false, true] {
        let mut a = ProtocolNode::new(1, NodeRole::Peer);
        let mut b = ProtocolNode::new(2, NodeRole::Peer);
        let mut queue = vec![
            sent(a.discover(2).unwrap().remove(0)),
            sent(b.discover(1).unwrap().remove(0)),
        ];
        if reverse {
            queue.reverse();
        }
        for _ in 0..10 {
            if queue.is_empty() {
                break;
            }
            let envelope = queue.remove(0);
            let events = if envelope.to == 1 {
                a.receive(envelope)
            } else {
                b.receive(envelope)
            }
            .unwrap();
            queue.extend(events.into_iter().filter_map(|e| match e {
                ProtocolEvent::Send(frame) => Some(frame),
                _ => None,
            }));
        }
        assert!(queue.is_empty());
        assert!(a.connected(2) && b.connected(1));
        complete(&mut a, &mut b, 7);
        complete(&mut b, &mut a, 7);
    }
}

#[test]
fn reordering_inside_window_is_accepted_and_older_attempts_are_rejected() {
    let (mut client, mut peer) = pair();
    let first = sent(client.request(2, 1, vec![]).unwrap());
    let second = sent(client.request(2, 2, vec![]).unwrap());
    let second_token = accepted(peer.receive(second).unwrap(), 1, 2);
    let first_token = accepted(peer.receive(first.clone()).unwrap(), 1, 1);
    client
        .receive(sent(peer.respond(1, 1, first_token).unwrap()))
        .unwrap();
    client
        .receive(sent(peer.respond(1, 2, second_token).unwrap()))
        .unwrap();
    for id in 3..REPLAY_WINDOW + 3 {
        complete(&mut client, &mut peer, id);
    }
    assert_eq!(peer.receive(first), Err(ProtocolError::Replay));
}

#[test]
fn oversized_payload_neighbor_budget_and_wrong_destination_are_rejected() {
    let (mut client, mut peer) = pair();
    assert_eq!(
        client.request(2, 7, vec![0; MAX_PAYLOAD_BYTES + 1]),
        Err(ProtocolError::ResourceLimit)
    );
    let mut oversized = sent(client.request(2, 7, vec![]).unwrap());
    if let Message::Request { payload, .. } = &mut oversized.message {
        payload.resize(MAX_PAYLOAD_BYTES + 1, 0);
    }
    assert_eq!(peer.receive(oversized), Err(ProtocolError::ResourceLimit));
    let mut wrong_destination = sent(client.request(2, 8, vec![]).unwrap());
    wrong_destination.to = 99;
    assert_eq!(
        peer.receive(wrong_destination),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(peer.pending_jobs(), 0);
    let mut node = ProtocolNode::new(100, NodeRole::Client);
    for id in 0..MAX_NEIGHBORS as u64 {
        node.discover(id).unwrap();
    }
    assert_eq!(node.discover(99), Err(ProtocolError::ResourceLimit));
}
