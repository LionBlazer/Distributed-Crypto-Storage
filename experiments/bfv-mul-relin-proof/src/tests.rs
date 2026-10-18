//! PUBLIC NONSECRET codec fixtures. These vectors are deliberately unproved.
use crate::*;
fn zero_claims() -> GraphClaims {
    use graph::NodeRequest;
    let mut nodes = Vec::new();
    for node in 0..NODES {
        let (k, b) = claims::metadata(node).unwrap();
        let r = match k {
            1 | 3 | 5 | 7 | 9 | 11 => {
                let direction = if matches!(k, 1 | 5 | 11) {
                    bfv_ntt_circuit::Direction::Inverse
                } else {
                    bfv_ntt_circuit::Direction::Forward
                };
                NodeRequest::Ntt(
                    bfv_ntt_circuit::decode_request(
                        &bfv_ntt_circuit::encode_request(
                            direction,
                            bfv_ntt_circuit::Basis::new(b).unwrap(),
                            [1; 32],
                            &vec![0; DEGREE],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
            }
            2 | 6 => {
                let role = if k == 2 {
                    bfv_scale_circuit::Role::Extend5To10
                } else {
                    bfv_scale_circuit::Role::Scale10To5
                };
                NodeRequest::Scale(
                    bfv_scale_circuit::decode_request(
                        &bfv_scale_circuit::encode_request(
                            role,
                            [1; 32],
                            &vec![0; role.input_coefficients()],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
            }
            4 => NodeRequest::Tensor(
                bfv_tensor_circuit::decode_request(
                    &bfv_tensor_circuit::encode_request(
                        bfv_tensor_circuit::Basis::new(b).unwrap(),
                        [1; 32],
                        &vec![0; 4 * DEGREE],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            _ => {
                let role = if k == 8 {
                    bfv_relinearization_circuit::Role::Embed
                } else {
                    bfv_relinearization_circuit::Role::AccumulateAndAdd
                };
                NodeRequest::Relin(
                    bfv_relinearization_circuit::decode_request(
                        &bfv_relinearization_circuit::encode_request(
                            role,
                            [1; 32],
                            [2; 32],
                            &vec![0; role.input_coefficients()],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )
            }
        };
        let out = match r {
            NodeRequest::Ntt(r) => NodeOutput::Ntt(
                bfv_ntt_circuit::evaluate_with_certificate(&r)
                    .unwrap()
                    .output,
            ),
            NodeRequest::Scale(r) => NodeOutput::Scale(
                bfv_scale_circuit::evaluate_with_certificate(&r)
                    .unwrap()
                    .output,
            ),
            NodeRequest::Tensor(r) => NodeOutput::Tensor(
                bfv_tensor_circuit::evaluate_with_certificate(&r)
                    .unwrap()
                    .output,
            ),
            NodeRequest::Relin(r) => NodeOutput::Relin(
                bfv_relinearization_circuit::evaluate_with_certificate(&r)
                    .unwrap()
                    .output,
            ),
        };
        nodes.push(out);
    }
    GraphClaims::new(core::array::from_fn(|_| vec![0; 5 * DEGREE]), nodes).unwrap()
}
#[test]
fn full_claim_codec_roundtrips_all134_nodes_and_rejects_geometry_aliases_before_any_proof() {
    let claims = zero_claims();
    let bytes = claims.encode();
    assert!(bytes.len() <= MAX_CLAIMS_BYTES);
    assert_eq!(GraphClaims::decode(&bytes).unwrap().encode(), bytes);
    for at in [0, 8, 72, 76, 95, 96 + 20 * DEGREE * 8 + 6] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(GraphClaims::decode(&bad).is_err());
    }
    let mut bad = bytes.clone();
    let at = 96 + 5 * DEGREE * 8 - 8;
    bad[at..at + 8].copy_from_slice(&bfv_fixed_geometry::MODULI[4].to_le_bytes());
    assert!(GraphClaims::decode(&bad).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(GraphClaims::decode(&trailing).is_err());
    assert!(GraphClaims::decode(&bytes[..bytes.len() - 1]).is_err());
    assert!(matches!(
        GraphClaims::decode(&vec![0; MAX_CLAIMS_BYTES + 1]),
        Err(Error::ResourceLimit)
    ));
}
#[test]
fn proof_obligations_cover_all_nodes_once_with_one_atomic_arithmetic_block() {
    let mut covered = graph::arithmetic_indices();
    assert_eq!(verifier::packet_node(0), Some(NODES));
    for packet in 1..PROOF_RECORDS {
        covered.push(verifier::packet_node(packet).unwrap());
    }
    covered.sort_unstable();
    assert_eq!(covered, (0..NODES).collect::<Vec<_>>());
    assert_eq!(verifier::packet_node(PROOF_RECORDS), None);
    assert_eq!(MAX_ATTEMPTS, 240);
    const {
        assert!(MAX_SESSION_BYTES > provenance::MAX_INPUT_BYTES + MAX_CLAIMS_BYTES);
    }
}
