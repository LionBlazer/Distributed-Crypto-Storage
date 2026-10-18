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
