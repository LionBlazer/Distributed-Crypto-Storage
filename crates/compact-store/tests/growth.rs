//! Owner-authorized public fixtures; this storage primitive does not claim SQL computation.
use compact_store::{EncryptedSnapshot, Error, Layout, Limits, Owner};
#[test]
fn growth_preserves_identity_advances_revision_refreshes_nonces_and_keeps_source_immutable() {
    let owner = Owner::generate([41; 16]).unwrap();
    let limits = Limits::default();
    let layout = Layout {
        schema: [3; 16],
        row_width: 3,
        rows_per_page: 1,
        row_count: 1,
    };
    let original = owner.seal(layout, &[18, 255, 0], limits).unwrap();
    let before = original.encode();
    let head = original.commitment().clone();
    let grown = owner
        .grow_from_checked_plaintext(&original, &head, 2, &[18, 255, 0, 42, 0, 1], limits)
        .unwrap();
    assert_eq!(original.encode(), before);
    assert_eq!(grown.commitment().database(), head.database());
    assert_eq!(grown.commitment().key_domain(), head.key_domain());
    assert_eq!(grown.commitment().revision(), head.revision() + 1);
    assert_eq!(
        grown.commitment().layout(),
        Layout {
            row_count: 2,
            ..layout
        }
    );
    let old = original
        .lookup(0, limits)
        .unwrap()
        .verify(&head, 0, limits)
        .unwrap();
    let fresh = grown
        .lookup(0, limits)
        .unwrap()
        .verify(grown.commitment(), 0, limits)
        .unwrap();
    assert_ne!(old.nonce(), fresh.nonce());
    assert_eq!(owner.decrypt(&fresh).unwrap().as_bytes(), [18, 255, 0]);
    assert!(EncryptedSnapshot::decode_for_head(&before, grown.commitment(), limits).is_err());
    assert!(matches!(
        owner.grow_from_checked_plaintext(&original, grown.commitment(), 3, &[0; 9], limits),
        Err(Error::WrongVersion)
    ));
    let other = Owner::generate([41; 16]).unwrap();
    assert!(matches!(
        other.grow_from_checked_plaintext(&original, &head, 2, &[0; 6], limits),
        Err(Error::WrongOwner)
    ));
    assert!(
        owner
            .grow_from_checked_plaintext(&original, &head, 1, &[0; 3], limits)
            .is_err()
    );
    assert!(
        owner
            .grow_from_checked_plaintext(&original, &head, 2, &[0; 5], limits)
            .is_err()
    );
    assert!(
        owner
            .grow_from_checked_plaintext(
                &original,
                &head,
                2,
                &[0; 6],
                Limits {
                    max_rows: 1,
                    ..limits
                }
            )
            .is_err()
    );
    assert_eq!(original.encode(), before);
}
