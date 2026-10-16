//! Public ciphertext fixtures exercise reconstruction without owner secrets on the peer.
use compact_store::{EncryptedSnapshot, Error, Layout, Limits, Owner, VerifiedPage};

fn fixture() -> (Owner, EncryptedSnapshot, EncryptedSnapshot) {
    let limits = Limits::default();
    let owner = Owner::generate([93; 16]).unwrap();
    let original = owner
        .seal(
            Layout {
                schema: [7; 16],
                row_width: 3,
                rows_per_page: 2,
                row_count: 7,
            },
            &(0..21).collect::<Vec<_>>(),
            limits,
        )
        .unwrap();
    let mut next = original.clone();
    owner
        .replace_pages(
            &mut next,
            original.commitment(),
            &[(0, &[9; 6]), (3, &[8; 3])],
            limits,
        )
        .unwrap();
    (owner, original, next)
}
fn pages(next: &EncryptedSnapshot, indices: &[u64]) -> Vec<VerifiedPage> {
    indices
        .iter()
        .map(|index| {
            next.lookup(*index, Limits::default())
                .unwrap()
                .verify(next.commitment(), *index, Limits::default())
                .unwrap()
        })
        .collect()
}

#[test]
fn verified_full_and_partial_pages_reconstruct_the_exact_complete_target() {
    let (owner, original, next) = fixture();
    let restored = original
        .clone()
        .apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            pages(&next, &[0, 3]),
            Limits::default(),
        )
        .unwrap();
    assert_eq!(restored.encode(), next.encode());
    for index in 0..4 {
        let actual = restored
            .lookup(index, Limits::default())
            .unwrap()
            .verify(next.commitment(), index, Limits::default())
            .unwrap();
        let expected = next
            .lookup(index, Limits::default())
            .unwrap()
            .verify(next.commitment(), index, Limits::default())
            .unwrap();
        assert_eq!(
            owner.decrypt(&actual).unwrap().as_bytes(),
            owner.decrypt(&expected).unwrap().as_bytes()
        );
    }
    assert_eq!(original.commitment().revision(), 0);
}
#[test]
fn omitted_duplicate_foreign_and_stale_replacements_never_return_a_partial_target() {
    let (_, original, next) = fixture();
    for indices in [vec![], vec![0], vec![3], vec![0, 0]] {
        assert!(
            original
                .clone()
                .apply_verified_replacements(
                    original.commitment(),
                    next.commitment(),
                    pages(&next, &indices),
                    Limits::default()
                )
                .is_err()
        );
    }
    assert!(matches!(
        original.clone().apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            pages(&original, &[0, 3]),
            Limits::default()
        ),
        Err(Error::WrongVersion)
    ));
    assert!(matches!(
        original.clone().apply_verified_replacements(
            next.commitment(),
            next.commitment(),
            pages(&next, &[0, 3]),
            Limits::default()
        ),
        Err(Error::WrongVersion)
    ));
    let (_, _, foreign) = fixture();
    assert!(
        original
            .clone()
            .apply_verified_replacements(
                original.commitment(),
                next.commitment(),
                pages(&foreign, &[0, 3]),
                Limits::default()
            )
            .is_err()
    );
    // An exact unchanged image needs no packet or revision rewrite.
    let unchanged = original
        .clone()
        .apply_verified_replacements(
            original.commitment(),
            original.commitment(),
            vec![],
            Limits::default(),
        )
        .unwrap();
    assert_eq!(unchanged.encode(), original.encode());
}
#[test]
fn a_target_from_another_geometry_or_multiple_revisions_cannot_reuse_unchanged_packets() {
    let (owner, original, mut next) = fixture();
    let first_head = next.commitment().clone();
    owner
        .replace_page(&mut next, &first_head, 1, &[5; 6], Limits::default())
        .unwrap();
    assert!(matches!(
        original.clone().apply_verified_replacements(
            original.commitment(),
            next.commitment(),
            pages(&next, &[0, 1, 3]),
            Limits::default()
        ),
        Err(Error::WrongVersion)
    ));
    let other = owner
        .seal(
            Layout {
                schema: [7; 16],
                row_width: 1,
                rows_per_page: 6,
                row_count: 21,
            },
            &[3; 21],
            Limits::default(),
        )
        .unwrap();
    assert!(
        original
            .clone()
            .apply_verified_replacements(
                original.commitment(),
                other.commitment(),
                pages(&other, &[0]),
                Limits::default()
            )
            .is_err()
    );
}
