//! Public synthetic encrypted pages; a hostile provider never forges VerifiedPage.
use super::*;
use compact_store::{Layout, Owner};

struct Misdirected<'a> {
    advertised: &'a Commitment,
    actual: &'a EncryptedSnapshot,
    returned_address: u64,
}
impl PageSource for Misdirected<'_> {
    fn commitment(&self) -> &Commitment {
        self.advertised
    }
    fn lookup(&self, _: u64, limits: Limits) -> Result<VerifiedPage> {
        Ok(self.actual.lookup(self.returned_address, limits)?.verify(
            self.actual.commitment(),
            self.returned_address,
            limits,
        )?)
    }
}
#[test]
fn genuine_membership_from_another_head_or_address_is_rejected_before_aead() {
    let limits = Limits::default();
    let owner = Owner::generate([91; 16]).unwrap();
    let layout = Layout {
        schema: crate::SCHEMA,
        row_width: 3,
        rows_per_page: 1,
        row_count: 2,
    };
    let first = owner.seal(layout, &[7, 1, 0, 18, 2, 0], limits).unwrap();
    let second = owner.seal(layout, &[7, 1, 0, 18, 2, 0], limits).unwrap();
    for (actual, returned_address) in [(&second, 0), (&first, 1)] {
        let source = Misdirected {
            advertised: first.commitment(),
            actual,
            returned_address,
        };
        assert!(matches!(
            checked_page(&source, first.commitment(), 0, limits),
            Err(Error::WrongVersion)
        ));
    }
    let valid = checked_page(&first, first.commitment(), 0, limits).unwrap();
    assert_eq!(owner.decrypt(&valid).unwrap().as_bytes(), &[7, 1, 0]);
}
#[test]
fn fixed_layout_read_requirements_fit_the_public_profile_at_actual_limit_boundaries() {
    let limits = Limits::default();
    let owner = Owner::generate([92; 16]).unwrap();
    let data = owner
        .seal(
            Layout {
                schema: crate::SCHEMA,
                row_width: 3,
                rows_per_page: 256,
                row_count: 0,
            },
            &[],
            limits,
        )
        .unwrap();
    // These are public geometry fixtures, not independently authorized SQL heads.
    // Exercise the actual Layout/ReadHeads validators without allocating 1M rows.
    for rows in [0, 1, 256, limits.max_rows] {
        for rows_per_page in [16_u32, 256, 21_845] {
            let mut bytes = data.commitment().encode();
            bytes[68..72].copy_from_slice(&rows_per_page.to_le_bytes());
            bytes[72..80].copy_from_slice(&rows.to_le_bytes());
            let data_head = Commitment::decode(&bytes, limits).unwrap();
            bytes[40..56].copy_from_slice(&crate::INDEX_SCHEMA);
            bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
            bytes[68..72].copy_from_slice(&(index::INDEX_PAGE_BYTES as u32).to_le_bytes());
            let index_bytes = index::identity_offset(rows).unwrap() as u64 + 32 * rows;
            bytes[72..80].copy_from_slice(&index_bytes.to_le_bytes());
            let index_head = Commitment::decode(&bytes, index::index_limits()).unwrap();
            let heads = ReadHeads::new(
                TableId::from_bytes([3; 32]).unwrap(),
                &data_head,
                &index_head,
                limits,
            )
            .unwrap();
            let required = heads.read_requirements().unwrap();
            assert!((1..=493).contains(&required.index_prefix_pages));
            assert!(
                required.data_image_bytes
                    <= 3_000_000
                        + 65_536 * compact_store::PAGE_OVERHEAD
                        + compact_store::MANIFEST_BYTES
            );
            if rows == 1_000_000 {
                assert_eq!(required.index_prefix_pages, 493);
                if rows_per_page == 256 {
                    assert_eq!(required.data_image_bytes, 3_187_648);
                }
            }
        }
    }
    let mut invalid = data.commitment().encode();
    invalid[68..72].copy_from_slice(&15_u32.to_le_bytes());
    invalid[72..80].copy_from_slice(&limits.max_rows.to_le_bytes());
    assert_eq!(
        Commitment::decode(&invalid, limits),
        Err(compact_store::Error::ResourceLimit)
    );
    invalid[68..72].copy_from_slice(&21_846_u32.to_le_bytes());
    assert_eq!(
        Commitment::decode(&invalid, limits),
        Err(compact_store::Error::ResourceLimit)
    );
}
