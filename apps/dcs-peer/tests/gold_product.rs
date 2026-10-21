//! Actual daemon/TLS/FHE/certificate roundtrip. No SQL, Source or lock grant.
#[path = "support/peer_process.rs"]
mod peer_process;
use bfv_ciphertext_formation::gold::data;
use bfv_query_core::gold::{self, InputBinding, InputScope, Mask256, Owner};
use p3_field::PrimeCharacteristicRing;
use peer_process::{Process, identity};
use peer_runtime::{Connector, RemoteError};
use registry200_proof::Val;
use std::{io, time::Instant};
use zeroize::Zeroizing;

fn binding(call: u64) -> InputBinding {
    InputBinding::checked(InputScope {
        database: [1; 16],
        transaction: 1,
        call,
        principal: 1,
        application: [2; 32],
        genesis: [3; 32],
        rules: [4; 32],
        context: [5; 32],
        parent: [6; 32],
        client: [7; 32],
        controller: [8; 32],
        source_version: [9; 32],
        data_admission: [10; 32],
        snapshot: [11; 32],
        statement: [12; 32],
        command: [13; 32],
        attempt: [14; 32],
        nonce: [15; 32],
    })
    .unwrap()
}

#[test]
fn real_peer_returns_only_bounded_unverified_gold_math_and_owner_checks_originals() {
    let tls_owner = identity();
    let connector = Connector::permissionless(&tls_owner).unwrap();
    let process = Process::start(tls_owner.fingerprint(), 201);
    let remote = process.remote(&connector);
    let before = remote.status().unwrap();
    assert_eq!(before.pid, process.pid());
    assert!(before.objects.is_empty());
    let owner = Owner::generate([0x51; 32], [11; 8]).unwrap();
    // Explicit public nonsecret coefficient fixture. No stored-row answer is
    // sent to the worker or used before its actual arithmetic is checked.
    let mut values = Zeroizing::new(vec![0; gold::N]);
    for (at, value) in [(0, 17), (128, 31), (2050, 42), (4095, 65)] {
        values[at] = value;
    }
    let original_data = owner.originate_data(values.clone()).unwrap();
    let salt = [13; 4];
    let context = [51; 8];
    let data = data::Expected::checked(
        data::Request::checked([0x52; 32], original_data.ciphertext().to_vec()).unwrap(),
        [0x53; 64],
        [
            context.map(Val::from_u64),
            owner.key_expected().context_words().map(Val::from_u64),
        ],
        [
            original_data
                .commitment(context, &salt)
                .unwrap()
                .map(Val::from_u64),
            owner.key_expected().root_words().map(Val::from_u64),
        ],
    )
    .unwrap();
    let mut mask = [0; 32];
    mask[16..].fill(255); // age>=128, encrypted as p[255-age].
    let original = owner
        .originate(Mask256::new(mask), binding(1), &data)
        .unwrap();
    let began = Instant::now();
    let response = remote.gold_product(original.public_request()).unwrap();
    let rpc_ms = began.elapsed().as_secs_f64() * 1000.;
    let receiving = Instant::now();
    let completed = owner.complete(&original, &response).unwrap();
    let receive_ms = receiving.elapsed().as_secs_f64() * 1000.;
    let complete_ms = began.elapsed().as_secs_f64() * 1000.;
    // Independent full-ring oracle only AFTER real remote computation and the
    // original request/nonce certificate check, including negacyclic wrap.
    let mut expected = Zeroizing::new(vec![0; gold::N]);
    for (i, &value) in values.iter().enumerate().filter(|(_, v)| **v != 0) {
        for j in 0..128 {
            let at = (i + j) % gold::N;
            expected[at] = (expected[at]
                + if i + j < gold::N {
                    value
                } else {
                    gold::T - value
                })
                % gold::T;
        }
    }
    assert_eq!(completed.coefficients(), expected.as_slice());
    let mut broken = response.certificate().to_vec();
    broken[8] ^= 1;
    let damaged = gold::UnverifiedProduct::from_parts(response.output().to_vec(), broken).unwrap();
    assert!(owner.complete(&original, &damaged).is_err());
    let next = owner
        .originate(Mask256::new(mask), binding(2), &data)
        .unwrap();
    assert!(owner.complete(&next, &response).is_err());
    let next_response = remote.gold_product(next.public_request()).unwrap();
    assert_eq!(
        owner
            .complete(&next, &next_response)
            .unwrap()
            .coefficients(),
        expected.as_slice()
    );

    let outsider = process.remote(&Connector::permissionless(&identity()).unwrap());
    let error = outsider
        .gold_product(original.public_request())
        .err()
        .expect("foreign owner rejected");
    assert!(matches!(
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<RemoteError>()),
        Some(RemoteError::Unauthorized)
    ));
    let control = peer_runtime::RequestControl::default();
    let controlled = remote.clone().with_control(control.clone());
    let scope = control.begin().unwrap();
    assert!(control.cancel());
    assert_eq!(
        controlled
            .gold_product(original.public_request())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Interrupted
    );
    drop(scope);
    assert!(remote.gold_product(original.public_request()).is_ok());

    let after = remote.status().unwrap();
    assert!(after.objects.is_empty());
    assert_eq!(before.disk_bytes(), after.disk_bytes());
    assert!(after.recent.iter().any(|r| r.operation == "gold-product"
        && r.succeeded
        && r.received_bytes > 100_000
        && r.sent_bytes > gold::PRODUCT_CERTIFICATE_BYTES as u64));
    assert!(
        after
            .recent
            .iter()
            .any(|r| r.operation == "gold-product" && !r.succeeded)
    );
    println!(
        "gold_product_remote peer_pid={} rpc_ms={rpc_ms:.3} arithmetic_receive_and_decrypt_ms={receive_ms:.3} complete_math_rpc_ms={complete_ms:.3} request_bytes={} output_bytes={} certificate_bytes={} real_TLS=true real_process=true Source=false Word=false SQL=false freshness=false locks=false security_assessed=false",
        process.pid(),
        original.public_request().as_bytes().len(),
        response.output().len(),
        response.certificate().len()
    );
    process.finish(&remote);
}
