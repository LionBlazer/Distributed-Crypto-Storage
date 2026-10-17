//! PUBLIC NONSECRET owning transport examples; no Journal verifier is installed.
use super::*;
use crate::backend::{Backend, Challenge, Config, Val};
use crate::opening::registry_lifecycle;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::MerkleCap;
use p3_uni_stark::Proof;
use std::sync::OnceLock;
use version_journal::Body;

struct Stored {
    expected: Expected,
    values: Vec<Val>,
    bytes: Vec<u8>,
}
fn stored(role: Role) -> &'static Stored {
    static BOOTSTRAP: OnceLock<Stored> = OnceLock::new();
    static TRANSITION: OnceLock<Stored> = OnceLock::new();
    let cell = match role {
        Role::Bootstrap => &BOOTSTRAP,
        Role::Transition => &TRANSITION,
    };
    cell.get_or_init(|| {
        let fixture = Fixture::new().unwrap();
        let (e, w) = match role {
            Role::Bootstrap => fixture.bootstrap().unwrap(),
            Role::Transition => fixture.begin().unwrap(),
        };
        if role == Role::Transition {
            let initial = stored(Role::Bootstrap);
            let initial = verify(&initial.expected, &initial.bytes).unwrap();
            let Phase::Transition { old, .. } = e.phase else {
                unreachable!()
            };
            assert_eq!(old, initial.next);
        }
        let (values, bytes) = {
            let (s, p) = prove(&e, &fixture.source_witness, &w).unwrap();
            registry_lifecycle::verify(&e, &s, &p).unwrap();
            (s.public_values(), encode(&e, &s, &p).unwrap())
        };
        drop(w);
        drop(fixture);
        // The original Source+child proof objects and their witnesses are gone.
        let fresh = verify(&e, &bytes).unwrap();
        assert_eq!(fresh.public_values(), values);
        Stored {
            expected: e,
            values,
            bytes,
        }
    })
}
fn pair(stored: &Stored) -> (Statement, CompositeProof) {
    let role = role(&stored.expected);
    let view = Frame::parse(role, &stored.bytes).unwrap();
    let s = verify(&stored.expected, &stored.bytes).unwrap();
    let source = proof_codec::decode(
        view.source,
        &topology(&stored.expected.source).unwrap(),
        MAX_SEQUENCE_ELEMENTS,
        SOURCE_SLOTS,
    )
    .unwrap();
    let child = proof_codec::decode(
        view.child,
        &topology(&s).unwrap(),
        MAX_SEQUENCE_ELEMENTS,
        CHILD_SLOTS,
    )
    .unwrap();
    (
        s,
        CompositeProof {
            source: Some(source),
            child,
        },
    )
}
fn altered_child(stored: &Stored, change: impl FnOnce(&mut Proof<Config>)) -> Vec<u8> {
    let view = Frame::parse(role(&stored.expected), &stored.bytes).unwrap();
    let s = verify(&stored.expected, &stored.bytes).unwrap();
    let mut p = proof_codec::decode(
        view.child,
        &topology(&s).unwrap(),
        MAX_SEQUENCE_ELEMENTS,
        CHILD_SLOTS,
    )
    .unwrap();
    change(&mut p);
    let changed = postcard::to_allocvec(&p).unwrap();
    frame::join(
        role(&stored.expected),
        view.outputs.as_chunks::<32>().0,
        view.source,
        &changed,
    )
    .unwrap()
}
#[test]
fn borrowed_registry200_frame_enforces_roles_profiles_lengths_and_body_reservation() {
    // Sentinel components exercise grammar only; they are never accepted proofs.
    for role in [Role::Bootstrap, Role::Transition] {
        let roots = vec![[0; 32]; role.output_count()];
        let bytes = frame::join(role, &roots, &[1], &[2]).unwrap();
        assert!(Frame::parse(role, &bytes).is_ok());
        for index in [0, 8, 9, 16, 48] {
            let mut bad = bytes.clone();
            bad[index] ^= 0x80;
            assert!(Frame::parse(role, &bad).is_err());
        }
        for size in [0, u32::MAX] {
            for at in [80, 84] {
                let mut bad = bytes.clone();
                bad[at..at + 4].copy_from_slice(&size.to_le_bytes());
                assert!(Frame::parse(role, &bad).is_err());
            }
        }
        assert!(Frame::parse(role, &bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(Frame::parse(role, &bad).is_err());
        let opposite = if role == Role::Bootstrap {
            Role::Transition
        } else {
            Role::Bootstrap
        };
        assert!(Frame::parse(opposite, &bytes).is_err());
        for magic in [b"DCSLKPW1", b"DCSLFPW2"] {
            let mut bad = bytes.clone();
            bad[..8].copy_from_slice(magic);
            assert!(Frame::parse(role, &bad).is_err());
        }
    }
    assert_eq!(frame::MAX_CHILD_BYTES, 12_578_091);
    assert_eq!(frame::MAX_BUNDLE_BYTES, 33_549_763);
    assert_eq!(
        frame::body_length(4096, frame::MAX_BUNDLE_BYTES).unwrap(),
        version_journal::MAX_BODY_BYTES
    );
    assert!(frame::body_length(4097, 1).is_err());
    assert!(frame::body_length(0, 1).is_err());
    assert!(frame::body_length(4096, frame::MAX_BUNDLE_BYTES + 1).is_err());
    assert_eq!(crate::opening::proof_wire::MAX_CHILD_BYTES, 5 * 1024 * 1024);
    assert_eq!(
        crate::opening::proof_wire::MAX_BUNDLE_BYTES,
        26 * 1024 * 1024
    );
}
#[test]
fn genuine_both_roles_roundtrip_after_original_objects_are_dropped() {
    for role in [Role::Bootstrap, Role::Transition] {
        let saved = stored(role);
        let (s, p) = pair(saved);
        assert_eq!(s.public_values(), saved.values);
        assert_eq!(encode(&saved.expected, &s, &p).unwrap(), saved.bytes);
        let mut absent = p;
        let original = absent.source.take();
        assert!(encode(&saved.expected, &s, &absent).is_err());
        absent.source = original;
        let view = Frame::parse(role, &saved.bytes).unwrap();
        assert!(frame::join(role, view.outputs.as_chunks::<32>().0, &[], view.child).is_err());
        assert!(frame::join(role, view.outputs.as_chunks::<32>().0, view.source, &[]).is_err());
    }
}
#[test]
fn independent_expected_matrix_and_every_output_root_reject_rebinding() {
    for role in [Role::Bootstrap, Role::Transition] {
        let saved = stored(role);
        for case in 0..16 {
            let mut wrong = saved.expected.clone();
            match case {
                0 => wrong.source.relation = crate::opening::Relation::Bytes,
                1 => wrong.source.request[31] ^= 1,
                2 | 3 => wrong.source.heads[case - 2][111] ^= 1,
                4 | 5 => wrong.source.packets[case - 4][0] ^= 1,
                6 => wrong.source.key_commitment[3] += Val::ONE,
                7 => wrong.source.open_commitment[3] += Val::ONE,
                8 => wrong.genesis[31] ^= 1,
                9 => wrong.parent[31] ^= 1,
                10 => wrong.enrollment[3] += Val::ONE,
                11 => {
                    wrong.phase = match wrong.phase {
                        Phase::Bootstrap => Phase::Transition {
                            old: [Val::ZERO; 4],
                            command: [Val::ZERO; 4],
                        },
                        Phase::Transition { .. } => Phase::Bootstrap,
                    };
                }
                12 | 13 => {
                    let Phase::Transition {
                        mut old,
                        mut command,
                    } = wrong.phase
                    else {
                        continue;
                    };
                    if case == 12 {
                        old[3] += Val::ONE;
                    } else {
                        command[3] += Val::ONE;
                    }
                    wrong.phase = Phase::Transition { old, command };
                }
                14 | 15 => {
                    *wrong.source.packets[case - 14].last_mut().unwrap() ^= 1;
                }
                _ => unreachable!(),
            };
            assert!(
                verify(&wrong, &saved.bytes).is_err(),
                "Expected case {case}"
            );
        }
        for root in 0..role.output_count() {
            let mut wrong = saved.bytes.clone();
            let at = frame::COMMON_HEADER + 32 * root;
            let original = u64::from_le_bytes(wrong[at..at + 8].try_into().unwrap());
            let next = if original + 1 == Val::ORDER_U64 {
                0
            } else {
                original + 1
            };
            wrong[at..at + 8].copy_from_slice(&next.to_le_bytes());
            assert!(verify(&saved.expected, &wrong).is_err());
            wrong[at..at + 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
            assert!(verify(&saved.expected, &wrong).is_err());
        }
    }
}
#[test]
fn genuine_foreign_enrollment_and_mixed_child_cannot_satisfy_original_expected() {
    let original = stored(Role::Bootstrap);
    let fixture = Fixture::new().unwrap();
    let (mut e, mut w) = fixture.bootstrap().unwrap();
    e.source = fixture.source([0xB9; 32]);
    w.controllers[1][31] ^= 1;
    e.enrollment = crate::opening::commitment::digest(&statement::enrollment_fields(&e, &w));
    let (s, p) = prove(&e, &fixture.source_witness, &w).unwrap();
    registry_lifecycle::verify(&e, &s, &p).unwrap();
    let foreign = encode(&e, &s, &p).unwrap();
    drop(p);
    verify(&e, &foreign).unwrap();
    assert!(verify(&original.expected, &foreign).is_err());
    let left = Frame::parse(Role::Bootstrap, &original.bytes).unwrap();
    let right = Frame::parse(Role::Bootstrap, &foreign).unwrap();
    let mixed = frame::join(
        Role::Bootstrap,
        right.outputs.as_chunks::<32>().0,
        left.source,
        right.child,
    )
    .unwrap();
    assert_ne!(left.source, right.source);
    assert_ne!(mixed, foreign);
    assert!(verify(&e, &mixed).is_err()); // Original Source is invalid under the foreign independent request.
    assert!(verify(&original.expected, &mixed).is_err());
}

#[test]
fn every_nested_sdk_family_canonical_encoding_and_component_budget_is_checked() {
    for role in [Role::Bootstrap, Role::Transition] {
        let saved = stored(role);
        let view = Frame::parse(role, &saved.bytes).unwrap();
        let statement = verify(&saved.expected, &saved.bytes).unwrap();
        let child = topology(&statement).unwrap();
        let source = topology(&saved.expected.source).unwrap();
        for case in 0..31 {
            let mut p = proof_codec::decode(view.child, &child, MAX_SEQUENCE_ELEMENTS, CHILD_SLOTS)
                .unwrap();
            match case {
                0 => p.degree_bits += 1,
                1 => {
                    p.opened_values.trace_local.pop();
                }
                2 => p.opened_values.trace_next = None,
                3 => {
                    p.opened_values.preprocessed = Some(p3_uni_stark::PreprocessedOpenedValues {
                        local: vec![crate::backend::Challenge::ZERO],
                        next: None,
                    })
                }
                4 => {
                    p.opened_values.quotient_chunks.pop();
                }
                5 => {
                    p.opened_values.quotient_chunks[0].pop();
                }
                6 => p.opened_values.random = None,
                7 => p.commitments.random = None,
                8 => p.commitments.trace = MerkleCap::new(vec![[Val::ZERO; 4]; 2]),
                9 => {
                    p.opening_proof.0.pop();
                }
                10 => {
                    p.opening_proof.0[1][0].pop();
                }
                11 => {
                    p.opening_proof.0[2][0][0].pop();
                }
                12 => {
                    p.opening_proof.1.commit_phase_commits.pop();
                }
                13 => {
                    p.opening_proof.1.commit_pow_witnesses.pop();
                }
                14 => {
                    p.opening_proof.1.input_openings.pop();
                }
                15 => {
                    p.opening_proof.1.input_openings[1].opened_values[0][0].pop();
                }
                16 => {
                    p.opening_proof.1.input_openings[1].opening_proof.0[0][0].pop();
                }
                17 => {
                    p.opening_proof.1.input_openings[0]
                        .opening_proof
                        .1
                        .sibling_hashes = vec![[Val::ZERO; 4]; 192 * 13 + 1]
                }
                18 => {
                    p.opening_proof.1.commit_phase_openings.pop();
                }
                19 => {
                    p.opening_proof.1.commit_phase_openings[0].sibling_values[0].pop();
                }
                20 => {
                    p.opening_proof.1.commit_phase_openings[0]
                        .opening_proof
                        .0
                        .pop();
                }
                21 => p
                    .opening_proof
                    .1
                    .final_poly
                    .push(crate::backend::Challenge::ZERO),
                22 => p.ood_pow_witness = Val::ONE,
                23 => p.opening_proof.1.batch_pow_witness = Val::ONE,
                24 => p.opening_proof.1.query_pow_witness = Val::ONE,
                25 => p.opening_proof.1.commit_pow_witnesses[0] = Val::ONE,
                26 => {
                    p.opening_proof.1.commit_phase_commits[0] =
                        MerkleCap::new(vec![[Val::ZERO; 4]; 2])
                }
                27 => {
                    p.opening_proof.1.input_openings[0].opened_values.pop();
                }
                28 => {
                    p.opening_proof.1.commit_phase_openings[0]
                        .sibling_values
                        .pop();
                }
                29 => {
                    p.opening_proof.1.commit_phase_openings[9]
                        .opening_proof
                        .1
                        .sibling_hashes = vec![[Val::ZERO; 4]; 192 * 3 + 1]
                }
                30 => {
                    p.opening_proof.0[0].pop();
                }
                _ => unreachable!(),
            }
            let bytes = postcard::to_allocvec(&p).unwrap();
            let frame =
                frame::join(role, view.outputs.as_chunks::<32>().0, view.source, &bytes).unwrap();
            assert!(
                verify(&saved.expected, &frame).is_err(),
                "nested family {case}"
            );
        }
        let p =
            proof_codec::decode(view.source, &source, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS).unwrap();
        let prefix = postcard::to_allocvec(&p.commitments).unwrap();
        assert!(view.source.starts_with(&prefix));
        let length = postcard::to_allocvec(&p.opened_values.trace_local.len()).unwrap();
        let mut oversized = view.source.to_vec();
        oversized.splice(
            prefix.len()..prefix.len() + length.len(),
            postcard::to_allocvec(&(MAX_SEQUENCE_ELEMENTS + 1)).unwrap(),
        );
        assert!(matches!(
            proof_codec::decode(&oversized, &source, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS),
            Err(proof_codec::Error::ResourceLimit)
        ));
        let bad = frame::join(
            role,
            view.outputs.as_chunks::<32>().0,
            &oversized,
            view.child,
        )
        .unwrap();
        assert!(verify(&saved.expected, &bad).is_err());
        for (bytes, shape) in [(view.source, &source), (view.child, &child)] {
            assert!(matches!(
                proof_codec::decode(bytes, shape, MAX_SEQUENCE_ELEMENTS, 1),
                Err(proof_codec::Error::ResourceLimit)
            ));
        }
        let mut nonminimal = length.clone();
        *nonminimal.last_mut().unwrap() |= 0x80;
        nonminimal.push(0);
        let mut altered = view.source.to_vec();
        altered.splice(prefix.len()..prefix.len() + length.len(), nonminimal);
        assert!(
            verify(
                &saved.expected,
                &frame::join(role, view.outputs.as_chunks::<32>().0, &altered, view.child).unwrap()
            )
            .is_err()
        );
        let mut nonfield = view.source.to_vec();
        assert_eq!(nonfield[0], 1);
        nonfield[1..9].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        assert!(
            verify(
                &saved.expected,
                &frame::join(
                    role,
                    view.outputs.as_chunks::<32>().0,
                    &nonfield,
                    view.child
                )
                .unwrap()
            )
            .is_err()
        );
        let mut trailing = view.child.to_vec();
        trailing.push(0);
        for (source, child) in [
            (&[0xA5; 32][..], view.child),
            (view.source, &[0xA5; 32][..]),
            (view.source, trailing.as_slice()),
        ] {
            assert!(
                verify(
                    &saved.expected,
                    &frame::join(role, view.outputs.as_chunks::<32>().0, source, child).unwrap()
                )
                .is_err()
            );
        }
        let mut source_proof = p;
        assert_eq!(
            source_proof.opening_proof.1.input_openings[1].opened_values[191][0].len(),
            11526
        );
        source_proof.opening_proof.1.input_openings[1].opened_values[191][0].pop();
        let bytes = postcard::to_allocvec(&source_proof).unwrap();
        assert!(
            verify(
                &saved.expected,
                &frame::join(role, view.outputs.as_chunks::<32>().0, &bytes, view.child).unwrap()
            )
            .is_err()
        );
    }
}
#[test]
fn same_shape_crypto_corruption_and_invalid_source_cannot_hide_behind_genuine_child() {
    for role in [Role::Bootstrap, Role::Transition] {
        let saved = stored(role);
        for case in 0..8 {
            let bad = altered_child(saved, |p| match case {
                0 => {
                    let mut roots = p.commitments.trace.roots().to_vec();
                    roots[0][0] += Val::ONE;
                    p.commitments.trace = MerkleCap::new(roots);
                }
                1 => *p.opened_values.trace_local.last_mut().unwrap() += Challenge::ONE,
                2 => {
                    *p.opened_values
                        .trace_next
                        .as_mut()
                        .unwrap()
                        .last_mut()
                        .unwrap() += Challenge::ONE
                }
                3 => p.opened_values.quotient_chunks[0][0] += Challenge::ONE,
                4 => p.opening_proof.1.final_poly[0] += Challenge::ONE,
                5 => p.opening_proof.1.input_openings[1].opened_values[191][0][0] += Val::ONE,
                6 => {
                    let hashes = &mut p.opening_proof.1.input_openings[1]
                        .opening_proof
                        .1
                        .sibling_hashes;
                    assert!(!hashes.is_empty());
                    hashes[0][0] += Val::ONE;
                }
                7 => {
                    p.opening_proof.1.commit_phase_openings[9].sibling_values[191][0] +=
                        Challenge::ONE
                }
                _ => unreachable!(),
            });
            assert!(
                verify(&saved.expected, &bad).is_err(),
                "crypto family {case}"
            );
        }
        let view = Frame::parse(role, &saved.bytes).unwrap();
        let shape = topology(&saved.expected.source).unwrap();
        let mut source =
            proof_codec::decode(view.source, &shape, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS).unwrap();
        Backend::new(&saved.expected.source)
            .unwrap()
            .verify(&saved.expected.source, &source)
            .unwrap();
        *source.opened_values.trace_local.last_mut().unwrap() += Challenge::ONE;
        shape.check(&source).unwrap();
        let bad = frame::join(
            role,
            view.outputs.as_chunks::<32>().0,
            &postcard::to_allocvec(&source).unwrap(),
            view.child,
        )
        .unwrap();
        assert!(matches!(
            verify(&saved.expected, &bad),
            Err(Error::Proof(BackendError::Verification))
        ));
    }
}
#[test]
fn actual_owner_signed_body_roundtrip_covers_2716_and_4096_request_envelopes() {
    for role in [Role::Bootstrap, Role::Transition] {
        let saved = stored(role);
        for request in [2716, frame::MAX_REQUEST_BYTES] {
            let actual = transport::roundtrip(&saved.expected, &saved.bytes, request).unwrap();
            assert_eq!(actual, 117 + request + 456 + saved.bytes.len());
            assert!(actual <= version_journal::MAX_BODY_BYTES);
            let body = Body::Transition(
                transport::transition(&saved.expected, &saved.bytes, request).unwrap(),
            );
            let mut exact = transport::profile();
            exact.max_body_bytes = actual as u32;
            exact.max_proof_bytes = saved.bytes.len() as u32;
            exact.validate().unwrap();
            let bytes = body.encode(&exact).unwrap();
            let decoded = Body::decode(&bytes, &exact).unwrap();
            assert_eq!(decoded.encode(&exact).unwrap(), bytes);
            let mut below = exact.clone();
            below.max_body_bytes -= 1;
            below.validate().unwrap();
            assert!(matches!(
                body.encode(&below),
                Err(version_journal::Error::ResourceLimit)
            ));
            assert!(matches!(
                Body::decode(&bytes, &below),
                Err(version_journal::Error::ResourceLimit)
            ));
            let mut above = exact;
            above.max_body_bytes += 1;
            above.validate().unwrap();
            assert!(body.encode(&above).is_ok());
            println!(
                "{{\"stage\":\"actual_registry200_signed_body_transport_test\",\"role\":\"{:?}\",\"request_bytes\":{},\"update_count\":1,\"bundle_bytes\":{},\"body_bytes\":{},\"journal_admission\":false}}",
                role,
                request,
                saved.bytes.len(),
                actual
            );
        }
    }
}
#[test]
fn owner_signature_binds_full_body_request_proof_update_parent_and_genesis() {
    let saved = stored(Role::Transition);
    let original = transport::transition(&saved.expected, &saved.bytes, 2716).unwrap();
    transport::authorization(&saved.expected, &original).unwrap();
    for case in 0..5 {
        let mut bad = original.clone();
        let mut expected = saved.expected.clone();
        match case {
            0 => *bad.request.last_mut().unwrap() ^= 1,
            1 => *bad.proof.last_mut().unwrap() ^= 1,
            2 => bad.updates[0].new.index[111] ^= 1,
            3 => bad.parent[31] ^= 1,
            4 => expected.genesis[31] ^= 1,
            _ => unreachable!(),
        };
        let bytes = Body::Transition(bad).encode(&transport::profile()).unwrap();
        let Body::Transition(decoded) = Body::decode(&bytes, &transport::profile()).unwrap() else {
            unreachable!()
        };
        assert!(transport::authorization(&expected, &decoded).is_err());
    }
    // A valid computation proof is not permission to substitute a different signed request.
    verify(&saved.expected, &original.proof).unwrap();
}
