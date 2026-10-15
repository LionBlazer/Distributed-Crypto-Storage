//! Candidate owning compact-store API. The caller supplies authenticated secret storage.
use super::Owner;
use crate::{Error, OWNER_RECOVERY_IMAGE_BYTES, Result};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"CSTOWNR1";

/// Opaque owner-only image. Zeroizing storage; deliberately no Debug/Display/Serialize.
pub struct OwnerRecoveryImage {
    bytes: Zeroizing<[u8; OWNER_RECOVERY_IMAGE_BYTES]>,
}
impl AsRef<[u8]> for OwnerRecoveryImage {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
impl Owner {
    /// Owner-only secret image. Never log, serialize with a generic serializer, or send to a peer.
    /// Authentication, latest-checkpoint selection and secure custody belong to the caller.
    pub fn export_secret_for_recovery(&self) -> OwnerRecoveryImage {
        let mut image = Zeroizing::new([0u8; OWNER_RECOVERY_IMAGE_BYTES]);
        image[..8].copy_from_slice(MAGIC);
        image[8..10].copy_from_slice(&1u16.to_le_bytes());
        image[16..32].copy_from_slice(&self.database);
        image[32..48].copy_from_slice(&self.domain);
        image[48..80].copy_from_slice(self.key.as_ref());
        OwnerRecoveryImage { bytes: image }
    }

    /// Restore the ORIGINAL key only from an already authenticated, confidential image.
    /// Expected identities must come from the caller's independently trusted current checkpoint.
    /// This image has no standalone checksum/MAC and does not establish head freshness.
    pub fn restore_secret_for_recovery(
        image: &[u8],
        expected_database: [u8; 16],
        expected_domain: [u8; 16],
    ) -> Result<Self> {
        if image.len() != OWNER_RECOVERY_IMAGE_BYTES
            || &image[..8] != MAGIC
            || image[8..10] != 1u16.to_le_bytes()
            || image[10..16] != [0; 6]
        {
            return Err(Error::InvalidFormat);
        }
        if image[16..32] != expected_database || image[32..48] != expected_domain {
            return Err(Error::WrongOwner);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&image[48..80]);
        Ok(Self {
            key,
            database: expected_database,
            domain: expected_domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptedSnapshot, Layout, Limits};

    #[test]
    fn restored_owner_decrypts_original_data_and_index_after_original_owner_drops() {
        let limits = Limits::default();
        let original = Owner::generate([23; 16]).unwrap();
        let layout = Layout {
            schema: [1; 16],
            row_width: 3,
            rows_per_page: 2,
            row_count: 4,
        };
        let data = original.seal(layout, &[7; 12], limits).unwrap();
        let index = original
            .seal(
                Layout {
                    schema: [2; 16],
                    ..layout
                },
                &[9; 12],
                limits,
            )
            .unwrap();
        let data_head = data.commitment().clone();
        let index_head = index.commitment().clone();
        let original_data_bytes = data.encode();
        let original_index_bytes = index.encode();
        let image = original.export_secret_for_recovery();
        drop(original);
        drop(data);
        drop(index);

        let restored = Owner::restore_secret_for_recovery(
            image.as_ref(),
            data_head.database(),
            data_head.key_domain(),
        )
        .unwrap();

        for (bytes, head, expected) in [
            (original_data_bytes, data_head, [7; 6]),
            (original_index_bytes, index_head, [9; 6]),
        ] {
            let unchanged = EncryptedSnapshot::decode(&bytes, limits).unwrap();
            let verified = unchanged
                .lookup(0, limits)
                .unwrap()
                .verify(&head, 0, limits)
                .unwrap();
            assert_eq!(restored.decrypt(&verified).unwrap().as_bytes(), expected);
            assert_eq!(unchanged.encode(), bytes);
        }
    }

    #[test]
    fn wrong_expected_identity_and_nonexact_image_are_rejected() {
        let owner = Owner::generate([31; 16]).unwrap();
        let snapshot = owner
            .seal(
                Layout {
                    schema: [1; 16],
                    row_width: 1,
                    rows_per_page: 1,
                    row_count: 1,
                },
                &[4],
                Limits::default(),
            )
            .unwrap();
        let head = snapshot.commitment();
        let image = owner.export_secret_for_recovery();
        assert!(matches!(
            Owner::restore_secret_for_recovery(image.as_ref(), [32; 16], head.key_domain()),
            Err(Error::WrongOwner)
        ));
        for length in [0, 8, OWNER_RECOVERY_IMAGE_BYTES - 1] {
            assert!(
                Owner::restore_secret_for_recovery(
                    &image.as_ref()[..length],
                    head.database(),
                    head.key_domain()
                )
                .is_err()
            );
        }
        let mut extended = Zeroizing::new(image.as_ref().to_vec());
        extended.push(0);
        assert!(
            Owner::restore_secret_for_recovery(&extended, head.database(), head.key_domain())
                .is_err()
        );
    }
}
