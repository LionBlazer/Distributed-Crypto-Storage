//! PUBLIC NONSECRET fixtures. Genuine Source/Life/Kind and QCs, plus unavailable TCP.
//! Local QC tests do not stand for a distributed/network SQL success case.
use super::*;
use crate::private_predicate::{
    JointSqlNetworkConfig, JointSqlNetworkError, JointSqlNetworkHost, JointSqlNetworkInput,
    JointSqlNetworkOutcome, JointSqlNetworkPending,
};
use ed25519_dalek::SigningKey;
use peer_runtime::{Connector, Endpoint, ProofGate};
use std::{net::TcpListener, time::Duration};

fn connector() -> Connector {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let cert = params.self_signed(&key).unwrap();
    let identity = peer_runtime::Identity {
        certificate: cert.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    };
    Connector::permissionless(&identity).unwrap()
}
fn config(endpoint: Endpoint) -> JointSqlNetworkConfig {
    JointSqlNetworkConfig::new(connector(), vec![endpoint.clone()], endpoint, 4096).unwrap()
}
fn input(rig: &Rig) -> JointSqlNetworkInput<'_> {
    JointSqlNetworkInput {
        source: &rig.owner,
        fetched: rig.fetched(),
        acquire: None,
    }
}

#[test]
fn wrong_signer_and_exact_call_or_busy_rejection_precede_io_and_private_changes() {
    let (rig, opening) = Rig::new();
    let host = create(&rig, opening);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = Endpoint {
        address: listener.local_addr().unwrap(),
        identity: [0x32; 32],
    };
    assert!(matches!(
        JointSqlNetworkHost::attach(
            host,
            SigningKey::from_bytes(&[0x5c; 32]),
            config(endpoint.clone()),
            ProofGate::new()
        ),
        Err(JointSqlNetworkError::WrongSigner)
    ));
    let host = open(&rig).unwrap();
    let before = host.cursor().unwrap();
    let gate = ProofGate::new();
    let held = gate.try_acquire().unwrap();
    let mut runner = JointSqlNetworkHost::attach(
        host,
        SigningKey::from_bytes(&[0x5b; 32]),
        config(endpoint.clone()),
        gate.clone(),
    )
    .unwrap();
    assert!(
        runner
            .execute(
                CLIENT_A,
                1,
                "SELECT age FROM records",
                input(&rig),
                Duration::from_secs(1)
            )
            .is_err()
    );
    assert!(
        runner
            .resume_original(CLIENT_A, 1, "BEGIN", input(&rig), Duration::from_secs(1))
            .is_err()
    );
    assert!(matches!(
        runner
            .execute(CLIENT_A, 1, "BEGIN", input(&rig), Duration::from_secs(1))
            .unwrap(),
        JointSqlNetworkOutcome::Pending {
            reason: JointSqlNetworkPending::Busy,
            ..
        }
    ));
    assert_eq!(runner.cursor().unwrap(), before);
    assert_eq!(runner.phase().unwrap(), OwnerVaultPhase::Idle);
    drop(held);
    assert!(gate.try_acquire().is_ok());
    assert!(JointSqlNetworkConfig::new(connector(), vec![], endpoint.clone(), 1).is_err());
    assert!(
        JointSqlNetworkConfig::new(
            connector(),
            vec![endpoint.clone(), endpoint.clone()],
            endpoint,
            1
        )
        .is_err()
    );
    let host = runner.into_host();
    assert_eq!(host.cursor().unwrap(), before);
    assert_eq!(host.phase().unwrap(), OwnerVaultPhase::Idle);
    drop(host);
    drop(listener);
}

#[test]
fn unavailable_network_keeps_original_signed_body_and_reopen_retry_without_new_intent() {
    let (mut rig, opening) = Rig::new();
    let mut host = create(&rig, opening);
    // A real reserved TCP address with no TLS/application handler is explicitly
    // an unavailable endpoint, not a server returning a fabricated SQL result.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = Endpoint {
        address: listener.local_addr().unwrap(),
        identity: [0x33; 32],
    };
    let gate = ProofGate::new();
    let call = call(&host, CLIENT_A, 1, "BEGIN");
    let permit = gate.try_acquire().unwrap();
    let block = draft(&rig, &mut host, &call);
    let wire = block.encode();
    let qc = checkpoint(&rig, &initial_context(&rig), &block);
    let before = host
        .seal_body(&call, host.cursor().unwrap(), block)
        .unwrap();
    drop(permit);
    let mut runner = JointSqlNetworkHost::attach(
        host,
        SigningKey::from_bytes(&[0x5b; 32]),
        config(endpoint.clone()),
        gate.clone(),
    )
    .unwrap();
    let result = runner
        .execute(
            CLIENT_A,
            1,
            "BEGIN",
            input(&rig),
            Duration::from_millis(200),
        )
        .unwrap();
    assert!(matches!(result, JointSqlNetworkOutcome::Pending { .. }));
    assert_eq!(runner.cursor().unwrap(), before);
    assert!(matches!(
        runner.phase().unwrap(),
        OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown
    ));
    let host = runner.into_host();
    assert_eq!(host.cursor().unwrap(), before);
    assert!(matches!(
        host.phase().unwrap(),
        OwnerVaultPhase::BodyPrepared | OwnerVaultPhase::SubmittedUnknown
    ));
    drop(host);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    let saved = host.submission(&call, host.cursor().unwrap()).unwrap();
    let exact = CandidateBlock::new(saved.header().clone(), saved.body().to_vec()).unwrap();
    assert_eq!(exact.encode(), wire);
    let mut runner = JointSqlNetworkHost::attach(
        host,
        SigningKey::from_bytes(&[0x5b; 32]),
        config(endpoint),
        gate.clone(),
    )
    .unwrap();
    assert!(
        runner
            .resume_original(CLIENT_A, 1, "BEGIN;", input(&rig), Duration::from_secs(1))
            .is_err()
    );
    let result = runner
        .resume_original(
            CLIENT_A,
            1,
            "BEGIN",
            input(&rig),
            Duration::from_millis(200),
        )
        .unwrap();
    assert!(matches!(result, JointSqlNetworkOutcome::Pending { .. }));
    drop(runner);
    rig.fresh_quota();
    let mut host = open(&rig).unwrap();
    let cursor = host.cursor().unwrap();
    let saved = host.submission(&call, cursor).unwrap();
    assert_eq!(saved.header().encode(), exact.header().encode());
    assert_eq!(saved.body(), exact.body());
    // This is a local genuine-QC/private-completion regression, deliberately
    // separate from the unavailable network result above. The real closed Host
    // rechecks Source/Life/Kind/owner/Header and this QC before bank fsync.
    let permit = gate.try_acquire().unwrap();
    let reply = host
        .complete_control(&call, cursor, &rig.owner, rig.fetched(), &qc)
        .unwrap();
    assert_eq!(
        reply.control_outcome(),
        Some(control::JointControlOutcome::Begun)
    );
    drop(reply);
    drop(permit);
    let mut runner = JointSqlNetworkHost::attach(
        host,
        SigningKey::from_bytes(&[0x5b; 32]),
        config(Endpoint {
            address: listener.local_addr().unwrap(),
            identity: [0x33; 32],
        }),
        gate.clone(),
    )
    .unwrap();
    assert!(matches!(
        runner
            .execute(CLIENT_A, 1, "BEGIN", input(&rig), Duration::from_secs(1))
            .unwrap(),
        JointSqlNetworkOutcome::NeedsReopen { .. }
    ));
    drop(runner);
    drop(listener);
}
