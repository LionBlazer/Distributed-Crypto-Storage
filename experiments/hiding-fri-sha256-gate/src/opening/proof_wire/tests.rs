//! Malformed bytes here are rejection inputs, never cryptographic controls.
use super::*;
use crate::backend::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::MerkleCap;

#[test]
fn frame_rejects_absent_oversized_truncated_and_trailing_components_before_decode() {
    // Non-proof sentinel slices exercise only the borrowed frame grammar.
    let frame = join(Role::Bootstrap, &[[0; 32]], &[7], &[8]).unwrap();
    assert!(Frame::parse(Role::Bootstrap, &frame).is_ok());
    for index in [0, 8, 9, 16, 48] {
        let mut bad = frame.clone();
        bad[index] ^= 0x80;
        assert!(Frame::parse(Role::Bootstrap, &bad).is_err());
    }
    for len in [0, u32::MAX] {
        for offset in [80, 84] {
            let mut bad = frame.clone();
            bad[offset..offset + 4].copy_from_slice(&len.to_le_bytes());
            assert!(Frame::parse(Role::Bootstrap, &bad).is_err());
        }
    }
    assert!(Frame::parse(Role::Bootstrap, &frame[..frame.len() - 1]).is_err());
    let mut extra = frame.clone();
    extra.push(0);
    assert!(Frame::parse(Role::Bootstrap, &extra).is_err());
    assert!(Frame::parse(Role::Locking, &frame).is_err());
}
#[test]
fn component_and_combined_limits_are_explicit_without_widening_journal() {
    assert_eq!(SOURCE_SLOTS + CHILD_SLOTS, 32 * 1024 * 1024);
    let large = vec![0; MAX_BUNDLE_BYTES + 1];
    assert!(matches!(
        Frame::parse(Role::Locking, &large),
        Err(Error::ResourceLimit)
    ));
    const {
        assert!(MAX_SOURCE_BYTES + MAX_CHILD_BYTES + HEADER + 96 < MAX_BUNDLE_BYTES);
    }
}

pub(in crate::opening) fn check_rejections(
    role: Role,
    source: &Shape,
    child: &Shape,
    bytes: &[u8],
    mut reject: impl FnMut(&[u8]),
) {
    let frame = Frame::parse(role, bytes).unwrap();
    let outputs = frame.outputs.as_chunks::<32>().0;
    // Every attack starts from the real child's original SDK bytes. Encode these
    // mutated native objects without the writer's check to exercise the decoder.
    for case in 0..31 {
        let mut p = decode(frame.child, child, CHILD_SLOTS).unwrap();
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
                p.opening_proof.1.commit_phase_commits[0] = MerkleCap::new(vec![[Val::ZERO; 4]; 2])
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
        let altered = postcard::to_allocvec(&p).unwrap();
        reject(&join(role, outputs, frame.source, &altered).unwrap());
    }
    // A real Source includes W11521 fields and a W+5=11526 input row.
    let mut p = decode(frame.source, source, SOURCE_SLOTS).unwrap();
    assert_eq!(
        p.opening_proof.1.input_openings[1].opened_values[0][0].len(),
        11526
    );
    p.opening_proof.1.input_openings[1].opened_values[191][0].pop();
    reject(
        &join(
            role,
            outputs,
            &postcard::to_allocvec(&p).unwrap(),
            frame.child,
        )
        .unwrap(),
    );

    // Overlong Vec declaration is rejected by the shared-budget wrapper BEFORE
    // the SDK's Vec consumer can reserve. Locate it through SDK serialization.
    let p = decode(frame.source, source, SOURCE_SLOTS).unwrap();
    let prefix = postcard::to_allocvec(&p.commitments).unwrap();
    assert!(frame.source.starts_with(&prefix));
    let len = postcard::to_allocvec(&p.opened_values.trace_local.len()).unwrap();
    let mut oversized = frame.source.to_vec();
    oversized.splice(
        prefix.len()..prefix.len() + len.len(),
        postcard::to_allocvec(&(MAX_SEQUENCE_ELEMENTS + 1)).unwrap(),
    );
    assert!(matches!(
        decode(&oversized, source, SOURCE_SLOTS),
        Err(Error::ResourceLimit)
    ));
    reject(&join(role, outputs, &oversized, frame.child).unwrap());
    assert!(matches!(
        decode(frame.source, source, 1),
        Err(Error::ResourceLimit)
    ));

    let mut nonminimal = len.clone();
    *nonminimal.last_mut().unwrap() |= 0x80;
    nonminimal.push(0);
    let mut altered = frame.source.to_vec();
    altered.splice(prefix.len()..prefix.len() + len.len(), nonminimal);
    reject(&join(role, outputs, &altered, frame.child).unwrap());
    let mut nonfield = frame.source.to_vec();
    assert_eq!(nonfield[0], 1);
    nonfield[1..9].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    reject(&join(role, outputs, &nonfield, frame.child).unwrap());
    // A real-looking receipt/hash has no actual SDK proof structure.
    reject(&join(role, outputs, &[0xA5; 32], frame.child).unwrap());
    reject(&join(role, outputs, frame.source, &[0xA5; 32]).unwrap());
    let mut trailing = frame.child.to_vec();
    trailing.push(0);
    reject(&join(role, outputs, frame.source, &trailing).unwrap());
}

pub(in crate::opening) fn alter_child(
    role: Role,
    bytes: &[u8],
    child: &Shape,
    change: impl FnOnce(&mut Proof<Config>),
) -> Vec<u8> {
    let frame = Frame::parse(role, bytes).unwrap();
    let mut p = decode(frame.child, child, CHILD_SLOTS).unwrap();
    change(&mut p);
    join(
        role,
        frame.outputs.as_chunks::<32>().0,
        frame.source,
        &postcard::to_allocvec(&p).unwrap(),
    )
    .unwrap()
}

pub(in crate::opening) fn foreign_child(role: Role, original: &[u8], foreign: &[u8]) -> Vec<u8> {
    let original = Frame::parse(role, original).unwrap();
    let foreign = Frame::parse(role, foreign).unwrap();
    join(
        role,
        foreign.outputs.as_chunks::<32>().0,
        original.source,
        foreign.child,
    )
    .unwrap()
}

pub(in crate::opening) fn check_crypto_rejections(
    role: Role,
    bytes: &[u8],
    child: &Shape,
    mut reject: impl FnMut(&[u8]),
) {
    let frame = Frame::parse(role, bytes).unwrap();
    for case in 0..15 {
        let altered = alter_child(role, bytes, child, |p| {
            let bump = |cap: &mut p3_symmetric::MerkleCap<Val, [Val; 4]>| {
                let mut roots = cap.roots().to_vec();
                roots[0][0] += Val::ONE;
                *cap = MerkleCap::new(roots);
            };
            match case {
                0 => bump(&mut p.commitments.trace),
                1 => bump(&mut p.commitments.quotient_chunks),
                2 => bump(p.commitments.random.as_mut().unwrap()),
                3 => {
                    *p.opened_values.trace_local.last_mut().unwrap() +=
                        crate::backend::Challenge::ONE
                }
                4 => {
                    *p.opened_values
                        .trace_next
                        .as_mut()
                        .unwrap()
                        .last_mut()
                        .unwrap() += crate::backend::Challenge::ONE
                }
                5 => {
                    *p.opened_values
                        .quotient_chunks
                        .last_mut()
                        .unwrap()
                        .last_mut()
                        .unwrap() += crate::backend::Challenge::ONE
                }
                6 => {
                    *p.opened_values.random.as_mut().unwrap().last_mut().unwrap() +=
                        crate::backend::Challenge::ONE
                }
                7 => {
                    *p.opening_proof.0[2].last_mut().unwrap()[0]
                        .last_mut()
                        .unwrap() += crate::backend::Challenge::ONE
                }
                8 => {
                    *p.opening_proof.1.input_openings[1].opened_values[191][0]
                        .last_mut()
                        .unwrap() += Val::ONE
                }
                9 => p.opening_proof.1.input_openings[1].opening_proof.0[191][0][3] += Val::ONE,
                10 => {
                    p.opening_proof.1.input_openings[1]
                        .opening_proof
                        .1
                        .sibling_hashes[0][3] += Val::ONE
                }
                11 => {
                    p.opening_proof.1.commit_phase_openings[0].sibling_values[191][0] +=
                        crate::backend::Challenge::ONE
                }
                12 => {
                    p.opening_proof.1.commit_phase_openings[0].opening_proof.0[191][0][3] +=
                        Val::ONE
                }
                13 => {
                    p.opening_proof.1.commit_phase_openings[0]
                        .opening_proof
                        .1
                        .sibling_hashes[0][3] += Val::ONE
                }
                14 => p.opening_proof.1.final_poly[0] += crate::backend::Challenge::ONE,
                _ => unreachable!(),
            }
        });
        // These preserve every accepted structural length. Rejection therefore
        // requires the real cryptographic verifier, not only the shape filter.
        let view = Frame::parse(role, &altered).unwrap();
        let p = decode(view.child, child, CHILD_SLOTS).unwrap();
        child.check(&p).unwrap();
        reject(&altered);
    }
    // Also require actual verification of the complete original Source proof.
    let mut source: Proof<Config> = bounded_postcard::take_from_bytes(
        frame.source,
        bounded_postcard::Limits {
            max_sequence_elements: MAX_SEQUENCE_ELEMENTS,
            max_total_elements: SOURCE_SLOTS,
        },
    )
    .unwrap()
    .0;
    *source.opening_proof.1.input_openings[1].opened_values[191][0]
        .last_mut()
        .unwrap() += Val::ONE;
    reject(
        &join(
            role,
            frame.outputs.as_chunks::<32>().0,
            &postcard::to_allocvec(&source).unwrap(),
            frame.child,
        )
        .unwrap(),
    );
}
