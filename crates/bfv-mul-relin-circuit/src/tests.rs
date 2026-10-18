//! PUBLIC NONSECRET codec fixtures. These vectors are deliberately unproved.
use crate::*;
const PROFILE: [u8; 64] = [0x41; 64];
fn zero_claims() -> GraphClaims {
    let mut nodes = Vec::new();
    for node in 0..NODES {
        let NodeMetadata { kind: k, basis: b } = node_metadata(node).unwrap();
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
    let bytes = claims.encode(PROFILE);
    assert!(bytes.len() <= MAX_CLAIMS_BYTES);
    assert_eq!(
        GraphClaims::decode(PROFILE, &bytes)
            .unwrap()
            .encode(PROFILE),
        bytes
    );
    for at in [0, 8, 72, 76, 95, 96 + 20 * DEGREE * 8 + 6] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(GraphClaims::decode(PROFILE, &bad).is_err());
    }
    let mut bad = bytes.clone();
    let at = 96 + 5 * DEGREE * 8 - 8;
    bad[at..at + 8].copy_from_slice(&bfv_fixed_geometry::MODULI[4].to_le_bytes());
    assert!(GraphClaims::decode(PROFILE, &bad).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(GraphClaims::decode(PROFILE, &trailing).is_err());
    assert!(GraphClaims::decode(PROFILE, &bytes[..bytes.len() - 1]).is_err());
    assert!(matches!(
        GraphClaims::decode(PROFILE, &vec![0; MAX_CLAIMS_BYTES + 1]),
        Err(Error::ResourceLimit)
    ));
}

use bfv_query_core::{CoefficientRow, Geometry, Owner, PeerEvaluator, PublicSetup, QueryContext};
use bfv_relinearization_key_source::PreparedKey;
use fhe::bfv::{BfvParametersBuilder, Ciphertext};
use fhe_math::rq::Representation;
use fhe_traits::{DeserializeParametrized, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::sync::OnceLock;

struct SdkFixture {
    setup: PublicSetup,
    key: PreparedKey,
    inputs: [Vec<u8>; 2],
    unseeded: [Vec<u8>; 2],
    output: Vec<u8>,
    claims: GraphClaims,
}
fn evaluate(request: &NodeRequest) -> NodeOutput {
    match request {
        NodeRequest::Ntt(r) => NodeOutput::Ntt(
            bfv_ntt_circuit::evaluate_with_certificate(r)
                .unwrap()
                .output,
        ),
        NodeRequest::Scale(r) => NodeOutput::Scale(
            bfv_scale_circuit::evaluate_with_certificate(r)
                .unwrap()
                .output,
        ),
        NodeRequest::Tensor(r) => NodeOutput::Tensor(
            bfv_tensor_circuit::evaluate_with_certificate(r)
                .unwrap()
                .output,
        ),
        NodeRequest::Relin(r) => NodeOutput::Relin(
            bfv_relinearization_circuit::evaluate_with_certificate(r)
                .unwrap()
                .output,
        ),
    }
}
fn fixture() -> &'static SdkFixture {
    static PUBLIC: OnceLock<SdkFixture> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let rows = [
            CoefficientRow { age: 0, amount: 0 },
            CoefficientRow {
                age: 127,
                amount: u16::MAX,
            },
            CoefficientRow {
                age: 128,
                amount: u16::MAX - 1,
            },
            CoefficientRow {
                age: 255,
                amount: 1,
            },
        ];
        let original = owner
            .encrypt_original_coefficient_rows_for_experiment(&rows)
            .unwrap();
        let prepared = owner
            .prepare_private_coefficient_predicate_for_experiment(
                QueryContext::new([7; 16], [11; 112], [13; 112]),
                [17; 32],
                &original,
                &[0xA5; 32],
            )
            .unwrap();
        let inputs = prepared.operand_ciphertexts().unwrap().map(<[u8]>::to_vec);
        // This independent SDK operation is only the test oracle. Production
        // routing never calls PeerEvaluator or any primitive evaluator.
        let actual = PeerEvaluator::from_public_setup(&setup)
            .unwrap()
            .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
            .unwrap();
        let output = actual.ciphertext_for_experiment().unwrap().to_vec();
        let parameters = BfvParametersBuilder::new()
            .set_degree(DEGREE)
            .set_moduli(&bfv_fixed_geometry::MODULI)
            .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
            .set_variance(10)
            .build_arc()
            .unwrap();
        let decoded = inputs
            .each_ref()
            .map(|wire| Ciphertext::from_bytes(wire, &parameters).unwrap());
        let native: [Vec<u64>; 4] = core::array::from_fn(|i| Vec::from(&decoded[i / 2][i % 2]));
        let unseeded = decoded.each_ref().map(|ct| {
            Ciphertext::new(ct.iter().cloned().collect(), &parameters)
                .unwrap()
                .to_bytes()
        });
        let id = Sha256::digest(setup.to_bytes().unwrap()).into();
        let key = PreparedKey::from_original(&setup, id).unwrap();
        let mut nodes = Vec::with_capacity(NODES);
        for node in 0..NODES {
            let request = derive_request(
                node,
                native.each_ref().map(Vec::as_slice),
                &nodes,
                &key,
                [1; 32],
            )
            .unwrap();
            let output = evaluate(&request);
            require_header(&request, &output).unwrap();
            nodes.push(output);
        }
        // Every claim is still unproved. Only the test SDK oracle establishes
        // the expected mathematical endpoint; no CheckedProduct is constructed.
        let claims = GraphClaims::new(native, nodes).unwrap();
        SdkFixture {
            setup,
            key,
            inputs,
            unseeded,
            output,
            claims,
        }
    })
}
fn request(node: usize) -> NodeRequest {
    let f = fixture();
    derive_request(
        node,
        f.claims.native_components(),
        &f.claims.nodes()[..node],
        &f.key,
        [1; 32],
    )
    .unwrap()
}
fn input(request: &NodeRequest) -> &[u64] {
    match request {
        NodeRequest::Ntt(r) => r.input(),
        NodeRequest::Scale(r) => r.input(),
        NodeRequest::Tensor(r) => r.input(),
        NodeRequest::Relin(r) => r.input(),
    }
}
fn row(values: &[u64], index: usize) -> &[u64] {
    &values[index * DEGREE..(index + 1) * DEGREE]
}
fn output(node: usize) -> &'static [u64] {
    fixture().claims.node(node).unwrap().coefficients()
}

#[test]
fn profile_context_and_raw_identity_feed_preserve_exact_bytes_without_authority() {
    let claims = &fixture().claims;
    let bytes = claims.encode(PROFILE);
    assert_eq!(bytes.len(), 16_727_920);
    for index in [0, 31, 32, 63] {
        let mut other = PROFILE;
        other[index] ^= 1;
        assert!(GraphClaims::decode(other, &bytes).is_err());
        let changed = claims.encode(other);
        assert_eq!(&changed[..8], &bytes[..8]);
        assert_eq!(&changed[72..], &bytes[72..]);
        assert_eq!(
            GraphClaims::decode(other, &changed).unwrap().encode(other),
            changed
        );
    }
    let mut actual = Sha512::new();
    actual.update(b"consumer-owned-prefix");
    claims.feed_identity(&mut actual);
    let mut expected = Sha512::new();
    expected.update(b"consumer-owned-prefix");
    for component in claims.native_components() {
        for x in component {
            expected.update(x.to_le_bytes());
        }
    }
    for (node, output) in claims.nodes().iter().enumerate() {
        expected.update((node as u64).to_le_bytes());
        let meta = node_metadata(node).unwrap();
        expected.update([meta.kind, meta.basis]);
        for x in output.coefficients() {
            expected.update(x.to_le_bytes());
        }
    }
    assert_eq!(actual.finalize(), expected.finalize());
    let (native, mut nodes) = claims.clone().into_parts();
    let mut header_only = nodes[0].encode();
    header_only[40] ^= 1;
    nodes[0] = NodeOutput::decode_for_node(0, &header_only).unwrap();
    let changed = GraphClaims::new(native, nodes).unwrap();
    let mut a = Sha512::new();
    claims.feed_identity(&mut a);
    let mut b = Sha512::new();
    changed.feed_identity(&mut b);
    assert_eq!(a.finalize(), b.finalize()); // Derived headers do not create a cycle.
}

#[test]
fn all134_mathematical_nodes_reach_every_actual_sdk_pb_endpoint_without_a_proof_grant() {
    let f = fixture();
    let parameters = f.setup.relinearization_material().unwrap();
    for first in [&f.inputs[0], &f.unseeded[0]] {
        for second in [&f.inputs[1], &f.unseeded[1]] {
            check_ciphertext_bridges(
                parameters.parameters(),
                [first, second],
                &f.output,
                &f.claims,
            )
            .unwrap();
        }
    }
    let p = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_moduli(&bfv_fixed_geometry::MODULI)
        .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
        .set_variance(10)
        .build_arc()
        .unwrap();
    let actual = Ciphertext::from_bytes(&f.output, &p).unwrap();
    for (component, polynomial) in actual.iter().enumerate() {
        let mut pb = polynomial.clone();
        pb.change_representation(Representation::PowerBasis);
        for basis in 0..5 {
            assert_eq!(
                output(124 + 5 * component + basis),
                pb.coefficients().row(basis).as_slice().unwrap()
            );
        }
    }
}

#[test]
fn every_full_vector_edge_uses_original_order_including_all25_digits_and_all50_key_rows() {
    let f = fixture();
    for node in 0..20 {
        assert_eq!(
            input(&request(node)),
            row(f.claims.native_component(node / 5).unwrap(), node % 5)
        );
    }
    for component in 0..4 {
        let extend = request(20 + component);
        for basis in 0..5 {
            assert_eq!(row(input(&extend), basis), output(5 * component + basis));
            assert_eq!(
                input(&request(24 + 5 * component + basis)),
                row(output(20 + component), 5 + basis)
            );
        }
    }
    for basis in 0..10 {
        let tensor = request(44 + basis);
        for component in 0..4 {
            let expected = if basis < 5 {
                row(f.claims.native_component(component).unwrap(), basis)
            } else {
                output(24 + 5 * component + basis - 5)
            };
            assert_eq!(row(input(&tensor), component), expected);
        }
        for component in 0..3 {
            assert_eq!(
                input(&request(54 + 10 * component + basis)),
                row(output(44 + basis), component)
            );
        }
    }
    for component in 0..3 {
        let down = request(84 + component);
        for basis in 0..10 {
            assert_eq!(
                row(input(&down), basis),
                output(54 + 10 * component + basis)
            );
        }
    }
    for component in 0..2 {
        for basis in 0..5 {
            assert_eq!(
                input(&request(87 + 5 * component + basis)),
                row(output(84 + component), basis)
            );
        }
    }
    assert_eq!(input(&request(97)), output(86));
    for source in 0..5 {
        for basis in 0..5 {
            assert_eq!(
                input(&request(98 + 5 * source + basis)),
                row(output(97), 5 * source + basis)
            );
        }
    }
    let mac = request(123);
    for basis in 0..5 {
        assert_eq!(row(input(&mac), 17 * basis), output(87 + basis));
        assert_eq!(row(input(&mac), 17 * basis + 1), output(92 + basis));
        for source in 0..5 {
            assert_eq!(
                row(input(&mac), 17 * basis + 2 + source),
                output(98 + 5 * source + basis)
            );
            for component in 0..2 {
                assert_eq!(
                    row(input(&mac), 17 * basis + 7 + 5 * component + source),
                    row(f.key.component(component, source).unwrap(), basis)
                );
            }
        }
        for component in 0..2 {
            assert_eq!(
                input(&request(124 + 5 * component + basis)),
                row(output(123), 2 * basis + component)
            );
        }
    }
    assert_eq!(
        ARITHMETIC_NODES,
        [
            20, 21, 22, 23, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 84, 85, 86
        ]
    );
    assert!(node_metadata(NODES).is_err());
    assert!(node_metadata(usize::MAX).is_err());
}

#[test]
fn prefixes_native_aliases_and_derived_header_substitutions_reject_before_any_evaluator() {
    let f = fixture();
    let native = f.claims.native_components();
    for node in [1, 19, 20, 44, 97, 123, 133] {
        assert!(
            derive_request(node, native, &f.claims.nodes()[..node - 1], &f.key, [1; 32]).is_err()
        );
        assert!(
            derive_request(node, native, &f.claims.nodes()[..node + 1], &f.key, [1; 32]).is_err()
        );
    }
    let mut swapped = f.claims.nodes()[..2].to_vec();
    swapped.swap(0, 1);
    assert!(derive_request(2, native, &swapped, &f.key, [1; 32]).is_err());
    assert!(derive_request(usize::MAX, native, &[], &f.key, [1; 32]).is_err());
    let mut alias = native[3].to_vec();
    alias[5 * DEGREE - 1] = bfv_fixed_geometry::MODULI[4];
    let mut wrong = native;
    wrong[3] = &alias;
    assert!(derive_request(0, wrong, &[], &f.key, [1; 32]).is_err());
    wrong[3] = &alias[..alias.len() - 1];
    assert!(derive_request(0, wrong, &[], &f.key, [1; 32]).is_err());
    require_header(&request(0), f.claims.node(0).unwrap()).unwrap();
    let foreign = derive_request(0, native, &[], &f.key, [2; 32]).unwrap();
    assert!(require_header(&foreign, f.claims.node(0).unwrap()).is_err());
    assert!(require_header(&request(0), f.claims.node(1).unwrap()).is_err());
    let mut digest = f.claims.node(0).unwrap().encode();
    digest[111] ^= 1;
    let decoded = NodeOutput::decode_for_node(0, &digest).unwrap();
    assert!(require_header(&request(0), &decoded).is_err());
}

fn varint(mut value: usize, bytes: &mut Vec<u8>) {
    loop {
        let next = value & 0x7f;
        value >>= 7;
        bytes.push(next as u8 | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}
fn polynomial(packed: &[u8], variable_time: bool) -> Vec<u8> {
    let mut wire = vec![8, 2, 16, 0x80, 0x40, 26];
    varint(packed.len(), &mut wire);
    wire.extend(packed);
    if variable_time {
        wire.extend([32, 1]);
    }
    wire
}
fn envelope(polynomials: &[Vec<u8>], seed: Option<&[u8]>) -> Vec<u8> {
    let mut wire = Vec::new();
    for p in polynomials {
        wire.push(10);
        varint(p.len(), &mut wire);
        wire.extend(p);
    }
    if let Some(seed) = seed {
        wire.push(18);
        varint(seed.len(), &mut wire);
        wire.extend(seed);
    }
    wire
}
fn changed_last(packed: &[u8], old: u64) -> Vec<u8> {
    let mut packed = packed.to_vec();
    let value = if old == 0 { 1 } else { old - 1 };
    let width = (u64::BITS - (bfv_fixed_geometry::MODULI[4] - 1).leading_zeros()) as usize;
    let start = packed.len() * 8 - width;
    for bit in 0..width {
        let at = start + bit;
        let mask = 1 << (at % 8);
        packed[at / 8] = (packed[at / 8] & !mask) | (((value >> bit) & 1) as u8 * mask);
    }
    packed
}

#[test]
fn bridge_forms_preserve_bools_seed_and_reject_canonical_last_input_output_or_seed_changes() {
    use bfv_ciphertext_wire::{SecondComponent, parse};
    let f = fixture();
    let material = f.setup.relinearization_material().unwrap();
    let first = parse(&f.inputs[0]).unwrap();
    let stored = parse(&f.unseeded[0]).unwrap();
    let SecondComponent::Seed(seed) = first.second() else {
        panic!("seeded SDK fixture");
    };
    let SecondComponent::Stored(second) = stored.second() else {
        panic!("unseeded SDK fixture");
    };
    for c0_flag in [false, true] {
        let c0 = polynomial(first.c0().packed_bytes(), c0_flag);
        let seeded = envelope(std::slice::from_ref(&c0), Some(seed));
        check_ciphertext_bridges(
            material.parameters(),
            [&seeded, &f.inputs[1]],
            &f.output,
            &f.claims,
        )
        .unwrap();
        for c1_flag in [false, true] {
            let wire = envelope(
                &[c0.clone(), polynomial(second.packed_bytes(), c1_flag)],
                None,
            );
            check_ciphertext_bridges(
                material.parameters(),
                [&wire, &f.inputs[1]],
                &f.output,
                &f.claims,
            )
            .unwrap();
        }
    }
    let changed = changed_last(
        first.c0().packed_bytes(),
        first.c0().row(4).unwrap().last().unwrap(),
    );
    let changed = envelope(&[polynomial(&changed, true)], Some(seed));
    parse(&changed).unwrap();
    assert!(
        check_ciphertext_bridges(
            material.parameters(),
            [&changed, &f.inputs[1]],
            &f.output,
            &f.claims
        )
        .is_err()
    );
    let mut changed_seed = *seed;
    changed_seed[31] ^= 1;
    let changed = envelope(
        &[polynomial(first.c0().packed_bytes(), true)],
        Some(&changed_seed),
    );
    parse(&changed).unwrap();
    assert!(
        check_ciphertext_bridges(
            material.parameters(),
            [&changed, &f.inputs[1]],
            &f.output,
            &f.claims
        )
        .is_err()
    );
    let output = parse(&f.output).unwrap();
    let SecondComponent::Stored(last) = output.second() else {
        panic!("unseeded SDK output");
    };
    let changed = changed_last(last.packed_bytes(), last.row(4).unwrap().last().unwrap());
    let changed = envelope(
        &[
            polynomial(output.c0().packed_bytes(), true),
            polynomial(&changed, true),
        ],
        None,
    );
    parse(&changed).unwrap();
    assert!(
        check_ciphertext_bridges(
            material.parameters(),
            f.inputs.each_ref().map(Vec::as_slice),
            &changed,
            &f.claims
        )
        .is_err()
    );
    let false_output = envelope(
        &[
            polynomial(output.c0().packed_bytes(), false),
            polynomial(last.packed_bytes(), true),
        ],
        None,
    );
    parse(&false_output).unwrap();
    assert!(
        check_ciphertext_bridges(
            material.parameters(),
            f.inputs.each_ref().map(Vec::as_slice),
            &false_output,
            &f.claims
        )
        .is_err()
    );
    assert!(
        check_ciphertext_bridges(
            &[],
            f.inputs.each_ref().map(Vec::as_slice),
            &f.output,
            &f.claims
        )
        .is_err()
    );
}
