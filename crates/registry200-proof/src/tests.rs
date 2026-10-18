//! Public contract tests; no fixture is a proof/admission substitute.
use crate as registry200_proof;

fn source_claim() -> registry200_proof::source::Statement {
    use compact_store::{Layout, Owner};
    use registry200_proof::source::{self, statement::limits};
    // PUBLIC NONSECRET geometry fixture; checked metadata alone proves no logical index.
    let owner = Owner::generate([0x31; 16]).unwrap();
    let data = owner
        .seal(
            Layout {
                schema: source::DATA_SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 4,
            },
            &[0; 12],
            limits(),
        )
        .unwrap();
    let index = owner
        .seal(
            Layout {
                schema: source::INDEX_SCHEMA,
                row_width: 1,
                rows_per_page: 4096,
                row_count: 2336,
            },
            &[0; 2336],
            limits(),
        )
        .unwrap();
    source::Statement::checked_relation(
        source::Relation::CanonicalIndex,
        [&data.encode(), &index.encode()],
        [data.commitment(), index.commitment()],
        [0xA4; 32],
        [0; 32],
        [0; 32],
    )
    .unwrap()
}

#[test]
fn canonical_frontend_reaudits_last_packet_byte_and_all_geometry() {
    let c = source_claim();
    let checked = crate::admission::CanonicalSource::checked_claim(&c).unwrap();
    assert_eq!(checked.claim().packets[1].len(), 2384);
    for page in 0..2 {
        let mut bad = c.clone();
        let last = bad.packets[page].len() - 1;
        bad.packets[page][last] ^= 1;
        assert!(crate::admission::CanonicalSource::checked_claim(&bad).is_err());
    }
    let mut bad = c;
    bad.heads[1][8] ^= 1;
    assert!(crate::admission::CanonicalSource::checked_claim(&bad).is_err());
}
#[test]
fn mutable_low_level_claims_never_bypass_sealed_canonical_admission() {
    let c = source_claim();
    for relation in [
        crate::source::Relation::Bytes,
        crate::source::Relation::PackedCanonicalIndex,
        crate::source::Relation::FactorizedPackedCanonicalIndex,
        crate::source::Relation::StateCertificate,
    ] {
        let mut wrong = c.clone();
        wrong.relation = relation;
        assert!(crate::admission::CanonicalSource::checked_claim(&wrong).is_err());
    }
    for page in 0..2 {
        let mut wrong = c.clone();
        wrong.packets[page].pop();
        assert!(crate::admission::CanonicalSource::checked_claim(&wrong).is_err());
    }
}

#[test]
fn source_circuit_rejects_mutated_packet_geometry_before_allocating_a_trace() {
    use crate::source::circuit::Witness;
    use bfv_hiding_stark::{Error, Val};
    let witness = Witness::new([0x31; 32], [Val::default(); 4], [Val::default(); 4], [0; 4]);
    let source = source_claim();
    source.reaudit().unwrap();
    for page in 0..2 {
        for truncate in [false, true] {
            let mut changed = source.clone();
            if truncate {
                changed.packets[page].pop();
            } else {
                changed.packets[page].push(0);
            }
            assert!(matches!(witness.trace(&changed), Err(Error::Shape)));
            assert!(changed.reaudit().is_err());
        }
    }
}

#[test]
fn private_mask_witness_owns_its_role_and_full_expected_before_source_decode() {
    use crate::coefficient_encoding::{
        self as encoding, Role,
        circuit::Witness,
        commitment,
        statement::{BfvBinding, Expected, Statement},
    };
    use bfv_hiding_stark::{Error, Val};
    use p3_field::PrimeCharacteristicRing;
    use zeroize::Zeroizing;
    let source = crate::admission::CanonicalSource::checked_claim(&source_claim()).unwrap();
    let descriptor = bfv_key_transform::SetupDescriptor {
        database: compact_store::Commitment::decode(
            &source.claim().heads[0],
            crate::source::statement::limits(),
        )
        .unwrap()
        .database(),
        key_domain: [0x71; 16],
        public_setup_digest: [0x95; 32],
        key_epoch: 1,
    };
    let binding = BfvBinding::new(
        [0x53; 32],
        bfv_key_transform::Statement {
            expected: bfv_key_transform::Expected {
                descriptor,
                coefficients: [Val::ONE; 4],
            },
            transformed: [Val::ONE; 4],
        },
    );
    let draft =
        Expected::private_mask(&source, binding.clone(), [0xB1; 32], [0xA1; 32], [0; 32]).unwrap();
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 128;
    let command = commitment::command_digest(&commitment::command_fields(
        &draft,
        mask,
        [Val::from_u8(23); 4],
    ));
    let expected = Expected::private_mask(
        &source,
        binding.clone(),
        [0xB1; 32],
        [0xA1; 32],
        crate::source::statement::encode_digest(command),
    )
    .unwrap();
    let witness = Witness::private_mask(&expected, Zeroizing::new(mask), [23; 4], [31; 4]).unwrap();
    let coefficients = witness.coefficients();
    assert_eq!(coefficients.len(), 8192);
    for (n, value) in coefficients.iter().copied().enumerate() {
        assert_eq!(
            value,
            if n == 0 || n == 255 {
                encoding::SCALE
            } else {
                0
            }
        );
    }
    let wrong_role = Statement {
        expected: Expected::source(&source, binding.clone()).unwrap(),
        encoded: [Val::ZERO; 4],
    };
    assert_eq!(wrong_role.expected.role(), Role::SourceAllOriginal);
    assert!(matches!(witness.trace(&wrong_role), Err(Error::Shape)));
    // Correct Expected proceeds to the mandatory byte verifier; no proof is fabricated.
    assert!(matches!(
        encoding::prove(&expected, &witness, &[]),
        Err(encoding::wire::Error::ResourceLimit)
    ));
    let mut foreign_binding = binding;
    let mut foreign_key = foreign_binding.key().clone();
    foreign_key.transformed[3] += Val::ONE;
    foreign_binding = BfvBinding::new(foreign_binding.full_setup(), foreign_key);
    let foreign = Expected::private_mask(
        &source,
        foreign_binding,
        [0xB1; 32],
        [0xA1; 32],
        crate::source::statement::encode_digest(command),
    )
    .unwrap();
    assert!(matches!(
        encoding::prove(&foreign, &witness, &[]),
        Err(encoding::wire::Error::Proof(Error::Shape))
    ));
    assert!(
        witness
            .formation_opening(&Statement {
                expected: foreign,
                encoded: witness.statement().encoded
            })
            .is_err()
    );
}
#[test]
fn original_three_profile_bytes_and_geometry_are_preserved() {
    fn hex(d: [u8; 32]) -> String {
        d.iter().map(|x| format!("{x:02x}")).collect()
    }
    assert_eq!(
        hex(crate::source::profile_digest(
            crate::source::Relation::CanonicalIndex
        )),
        "04fb26bee57f61c6b3c6c58951c0ee8b17a250d1486044eb76f5ef954962f72a"
    );
    assert_eq!(
        hex(crate::lifecycle::profile_digest(true)),
        "f2d2ebf42dd57e43fd392d55c1fcf01ef8d5051f575474f5fcd18d5c2bc62490"
    );
    assert_eq!(
        hex(crate::lifecycle::profile_digest(false)),
        "9afa632080e9fe123597032d94b2684577fd4bb99911702762c76c441f507e1c"
    );
    assert_eq!(
        (
            crate::source::canonical::WIDTH,
            crate::source::statement::PUBLIC_VALUES
        ),
        (11521, 691)
    );
    assert_eq!(
        (
            crate::lifecycle::bootstrap::WIDTH,
            crate::lifecycle::statement::BOOTSTRAP_VALUES
        ),
        (1082, 104)
    );
    assert_eq!(
        (
            crate::lifecycle::layout::WIDTH,
            crate::lifecycle::statement::STEP_VALUES
        ),
        (6741, 116)
    );
}
#[test]
fn phase_root_alias_and_header_limits_reject_before_proof_decode() {
    use crate::{
        admission::{CanonicalSource, Expected},
        wire::{
            self,
            frame::{self, Role},
        },
    };
    let s = CanonicalSource::checked_claim(&source_claim()).unwrap();
    let e = Expected::bootstrap(&s, [1; 32], [2; 32], [0; 32]).unwrap();
    // These bytes are explicitly malformed placeholders, never a computation proof.
    let b = frame::join(Role::Transition, &[[0; 32]; 2], &[0], &[0]).unwrap();
    assert!(matches!(wire::verify(&e, &b), Err(wire::Error::Profile)));
    let mut b = frame::join(Role::Bootstrap, &[[0; 32]], &[0], &[0]).unwrap();
    b[88..96].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
    assert!(matches!(
        wire::verify(&e, &b),
        Err(wire::Error::Proof(crate::BackendError::Shape))
    ));
    let mut too_long = frame::join(Role::Bootstrap, &[[0; 32]], &[0], &[0]).unwrap();
    too_long[80..84].copy_from_slice(&((frame::MAX_SOURCE_BYTES + 1) as u32).to_le_bytes());
    assert!(matches!(
        wire::verify(&e, &too_long),
        Err(wire::Error::ResourceLimit)
    ));
}

mod coefficient_wire {
    use crate::{
        admission::CanonicalSource,
        coefficient_encoding::{
            Role, profile_digest,
            statement::{BfvBinding, Expected},
            wire,
        },
        source,
    };
    use p3_field::{PrimeCharacteristicRing, PrimeField64};

    fn expected(role: Role) -> Expected {
        let source = CanonicalSource::checked_claim(&super::source_claim()).unwrap();
        // PUBLIC NONSECRET metadata only. No Key or Source proof is claimed.
        let binding = BfvBinding::new(
            [0x53; 32],
            bfv_key_transform::Statement {
                expected: bfv_key_transform::Expected {
                    descriptor: bfv_key_transform::SetupDescriptor {
                        database: [0x31; 16],
                        key_domain: [0x71; 16],
                        public_setup_digest: [0x95; 32],
                        key_epoch: 1,
                    },
                    coefficients: [crate::Val::ONE; 4],
                },
                transformed: [crate::Val::ONE; 4],
            },
        );
        match role {
            Role::SourceAllOriginal => Expected::source(&source, binding).unwrap(),
            Role::PrivateMask => {
                Expected::private_mask(&source, binding, [0xB1; 32], [0xA1; 32], [0; 32]).unwrap()
            }
        }
    }

    /// Independently spell out the existing wire ABI with deliberately invalid proof placeholders.
    fn malformed_pair(e: &Expected) -> Vec<u8> {
        let mut out = b"DCSCEP01".to_vec();
        out.extend([e.role().tag(), 0, 0, 0, 0, 0, 0, 0]);
        out.extend(source::profile_digest(source::Relation::CanonicalIndex));
        out.extend(profile_digest(e.role()));
        for word in e.encoding_context() {
            out.extend((word.as_canonical_u64() as u32).to_le_bytes());
        }
        out.extend(source::statement::encode_digest(e.command()));
        out.extend([0; 32]);
        out.extend(1u32.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        out.extend([0, 0]);
        out
    }

    #[test]
    fn coefficient_pair_parser_preserves_both_roles_and_borrows_only_exact_payloads() {
        for role in [Role::SourceAllOriginal, Role::PrivateMask] {
            let e = expected(role);
            let bytes = malformed_pair(&e);
            let f = wire::BorrowedFrame::parse(&e, &bytes).unwrap();
            assert_eq!(wire::HEADER, 184);
            assert_eq!(f.encoded(), [0; 32]);
            assert_eq!(f.source().as_ptr(), bytes[184..].as_ptr());
            assert_eq!(f.child().as_ptr(), bytes[185..].as_ptr());
            assert_eq!((f.source(), f.child()), (&[0][..], &[0][..]));
            assert!(
                wire::verify(&e, &bytes).is_err(),
                "framing is not cryptographic verification"
            );
        }
    }

    #[test]
    fn coefficient_pair_parser_rejects_noncanonical_roots_flags_lengths_and_trailing_bytes() {
        let e = expected(Role::PrivateMask);
        let bytes = malformed_pair(&e);
        for at in [0, 8, 15, 47, 79, 111, 143] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(wire::BorrowedFrame::parse(&e, &bad).is_err());
        }
        let mut alias = bytes.clone();
        alias[144..152].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
        assert!(wire::BorrowedFrame::parse(&e, &alias).is_err());
        for (offset, cap) in [(176, wire::MAX_SOURCE), (180, wire::MAX_CHILD)] {
            for len in [0, cap + 1] {
                let mut bad = bytes.clone();
                bad[offset..offset + 4].copy_from_slice(&(len as u32).to_le_bytes());
                assert!(matches!(
                    wire::BorrowedFrame::parse(&e, &bad),
                    Err(wire::Error::ResourceLimit)
                ));
            }
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            wire::BorrowedFrame::parse(&e, &trailing),
            Err(wire::Error::Encoding)
        ));
        assert!(matches!(
            wire::BorrowedFrame::parse(&e, &bytes[..183]),
            Err(wire::Error::Encoding)
        ));
        assert!(matches!(
            wire::BorrowedFrame::parse(&e, &vec![0; wire::MAX_FRAME + 1]),
            Err(wire::Error::ResourceLimit)
        ));
    }

    #[test]
    fn coefficient_pair_header_pins_the_full_transformed_key_and_independent_setup() {
        let e = expected(Role::SourceAllOriginal);
        let bytes = malformed_pair(&e);
        let source = CanonicalSource::checked_claim(e.source_claim()).unwrap();
        let mut key = e.bfv().key().clone();
        key.transformed[3] += crate::Val::ONE;
        let changed_key =
            Expected::source(&source, BfvBinding::new(e.bfv().full_setup(), key)).unwrap();
        let mut setup = e.bfv().full_setup();
        setup[31] ^= 1;
        let changed_setup =
            Expected::source(&source, BfvBinding::new(setup, e.bfv().key().clone())).unwrap();
        for changed in [changed_key, changed_setup] {
            assert!(matches!(
                wire::BorrowedFrame::parse(&changed, &bytes),
                Err(wire::Error::Shape)
            ));
        }
    }
}
