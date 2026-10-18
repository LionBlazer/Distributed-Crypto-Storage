//! Actual process/TLS admission with valid custody/setup; public non-secret fixtures only.
use super::*;
use bfv_query_core::{
    Geometry, Owner, PublicUpdateEvaluator, QueryContext, RowProjection, SelectedField,
};
use bincode::Options;
use peer_runtime::RemoteError;

fn source() -> RawBundle {
    let owner = compact_store::Owner::generate([41; 16]).unwrap();
    let image = |schema, value| {
        owner
            .seal(
                compact_store::Layout {
                    schema: [schema; 16],
                    row_width: 1,
                    rows_per_page: 1,
                    row_count: 1,
                },
                &[value],
                Limits::default(),
            )
            .unwrap()
    };
    RawBundle::from_snapshots(&image(43, 7), &image(47, 11)).unwrap()
}
fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn many_tiny_polynomials() -> Vec<u8> {
    let mut polynomial = vec![8, 3, 16, 8, 26, 218, 1];
    polynomial.resize(polynomial.len() + 218, 0);
    let mut wire = Vec::new();
    for _ in 0..2299 {
        wire.push(10);
        varint(polynomial.len(), &mut wire);
        wire.extend_from_slice(&polynomial);
    }
    assert_eq!(wire.len(), 524172);
    assert!(wire.len() < 512 * 1024);
    wire
}
fn replace_actual_rows(request: &[u8], payload: &[u8], replacement: &[u8]) -> Vec<u8> {
    // Ask the owning public API for its actual encrypted fields rather than
    // mirroring the private SELECT request struct or substituting metadata.
    let (rows, mask): (Vec<u8>, Vec<u8>) = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(payload)
        .unwrap();
    assert!(mask.is_empty());
    let offsets: Vec<_> = request
        .windows(rows.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == rows.as_slice()).then_some(at))
        .collect();
    assert_eq!(offsets.len(), 1);
    let at = offsets[0];
    assert!(at >= 8);
    assert_eq!(&request[at - 8..at], &(rows.len() as u64).to_le_bytes());
    let mut hostile = request[..at - 8].to_vec();
    hostile.extend_from_slice(&(replacement.len() as u64).to_le_bytes());
    hostile.extend_from_slice(replacement);
    hostile.extend_from_slice(&request[at + rows.len()..]);
    hostile
}

#[test]
fn ciphertext_preflight_rejects_amplification_with_valid_custody_and_keeps_peer_usable() {
    let authority = Authority::new();
    let identity = authority.identity();
    let connector = Connector::new(&identity, &authority.der).unwrap();
    let process = Process::start(&authority, identity.fingerprint(), 73, None);
    let remote = process.remote(&connector);
    println!("ciphertext_preflight_peer_pid={}", process.child.id());

    let (owner, public) = Owner::generate(Geometry::Rows16).unwrap();
    let evaluator =
        PublicUpdateEvaluator::from_parameters(&public.update_parameters().unwrap()).unwrap();
    let Response::Setup(setup) = remote
        .call(Request::InstallSetup(public.to_bytes().unwrap()))
        .unwrap()
    else {
        panic!("Actual setup must install");
    };
    let raw = source();
    let version = raw.target_version().unwrap();
    let object = *version.object();
    assert!(
        matches!(remote.call(Request::Store(raw)).unwrap(), Response::Stored(info) if info.id == object)
    );
    let context = QueryContext::new(
        [53; 16],
        version.data_head().encode(),
        version.index_head().encode(),
    );
    let prepared = owner
        .prepare_exact_select_for_experiment(
            context,
            &[SelectedField {
                age: 42,
                amount: 513,
                active: true,
            }],
            RowProjection::AgeAmount,
        )
        .unwrap();
    let canonical = evaluator.select_circuit_request(&prepared.request).unwrap();
    let check_proof = |reply: peer_runtime::ProofReply| {
        let checked = bfv_query_proof::verify(&canonical, &reply.output, &reply.proof).unwrap();
        assert!(checked.matches_statement(&canonical, &reply.output));
        assert_eq!(
            checked.operation(),
            bfv_query_proof::Operation::PublicPolynomialProduct
        );
        reply.output
    };
    let prove = |ciphertext| {
        remote.call(Request::Prove {
            object,
            setup,
            operation: Operation::Select,
            ciphertext,
        })
    };
    let Response::Proved(before) = prove(prepared.request.clone()).unwrap() else {
        panic!("Actual valid proof before malformed input");
    };
    let _ = check_proof(before);

    let hostile = replace_actual_rows(
        &prepared.request,
        &prepared.ciphertext_payload_bytes().unwrap(),
        &many_tiny_polynomials(),
    );
    assert!(matches!(
        evaluator.select_circuit_request(&hostile),
        Err(bfv_query_core::Error::InvalidShape)
    ));
    let error = prove(hostile)
        .err()
        .expect("Malformed ciphertext must reject");
    let remote_error = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<RemoteError>());
    assert!(
        matches!(remote_error, Some(RemoteError::Cryptography(detail)) if detail.contains("InvalidShape")),
        "Expected CT rejection, not auth/custody/setup failure: {error}"
    );

    let Response::Proved(after) = prove(prepared.request.clone()).unwrap() else {
        panic!("The same peer and admitted object remain usable after rejection");
    };
    let output = check_proof(after);
    let restored = evaluator
        .restore_select_circuit_output(&prepared.request, &output)
        .unwrap();
    let result = owner
        .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &restored)
        .unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        (result.rows[0].age, result.rows[0].amount),
        (Some(42), Some(513))
    );
    assert!(
        remote
            .status()
            .unwrap()
            .objects
            .iter()
            .any(|entry| entry.id == object && entry.available)
    );
}
