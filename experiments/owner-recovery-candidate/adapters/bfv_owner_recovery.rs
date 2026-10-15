//! Candidate owning BFV API; deliberately independent of storage, PIR and backup composition.
use super::*;

pub const OWNER_RECOVERY_IMAGE_BYTES: usize = 8_327;
const SECRET_BYTES: usize = 8_195;
const PARAMETER_BYTES: usize = 46;
const SECRET_OFFSET: usize = 132;
const MAGIC: &[u8; 8] = b"BFVOWNR1";
const CONTRACT: &[u8] = b"compact-bfv-owner-v1;fhe=0.1.1;fhe-traits=0.1.1;N8192;t114689;Q43,43,44,44,44;pinned-Q-values;CBD20-variance10;prost-packed-sint64-tag1-canonical;native-level0;setup-wire-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerRecoveryError {
    ImageFormat,
    ImageProfile,
    Geometry,
    PublicSetup,
    KeysetIdentity,
    SecretEncoding,
}
impl std::fmt::Display for OwnerRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BFV owner recovery rejected {self:?}")
    }
}
impl std::error::Error for OwnerRecoveryError {}
type RecoveryResult<T> = std::result::Result<T, OwnerRecoveryError>;

fn strict_secret_encoding(bytes: &[u8]) -> RecoveryResult<()> {
    // Verified source contract, NOT a universal BFV/protobuf size:
    // fhe-util0.1.1 variance10 samples difference of two 20-bit popcounts => [-20,20].
    // fhe0.1.1 SecretKey protobuf is one packed repeated sint64 field, tag1.
    // Zigzag coefficients are 0..=40, each one byte. Exactly8192 values:
    // tag0x0a, canonical length8192=0x80,0x40, then8192 single-byte values.
    // Reject unknown/duplicate fields, noncanonical varints, trailing data and excess allocation
    // BEFORE upstream prost decoding, whose own check only enforces coefficient count.
    if bytes.len() != SECRET_BYTES
        || bytes[..3] != [0x0a, 0x80, 0x40]
        || bytes[3..].iter().any(|coefficient| *coefficient > 40)
    {
        return Err(OwnerRecoveryError::SecretEncoding);
    }
    Ok(())
}

/// Opaque owner-only image. Zeroizing storage; deliberately no Debug/Display/Serialize.
pub struct OwnerRecoveryImage {
    bytes: Zeroizing<Vec<u8>>,
}
impl OwnerRecoveryImage {
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}
impl AsRef<[u8]> for OwnerRecoveryImage {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Owner {
    /// Export only to trusted authenticated confidential recovery storage.
    /// Original public setup identity is checked; this does not prove arbitrary secret/key consistency.
    /// Upstream serialization's temporary protobuf coefficient copy is not comprehensively zeroized.
    pub fn export_secret_for_recovery(
        &self,
        original_public: &PublicSetup,
    ) -> RecoveryResult<OwnerRecoveryImage> {
        let parameters = original_public
            .checked_parameters()
            .map_err(|_| OwnerRecoveryError::PublicSetup)?;
        if self.geometry != original_public.geometry {
            return Err(OwnerRecoveryError::Geometry);
        }
        if self.parameters.to_bytes() != parameters.to_bytes()
            || original_public.parameters.len() != PARAMETER_BYTES
        {
            return Err(OwnerRecoveryError::ImageProfile);
        }
        let original_id =
            keyset_id(original_public).map_err(|_| OwnerRecoveryError::PublicSetup)?;
        if self.keyset_id != original_id {
            return Err(OwnerRecoveryError::KeysetIdentity);
        }
        let secret = Zeroizing::new(self.key.to_bytes());
        strict_secret_encoding(&secret)?;
        let mut image = Zeroizing::new(vec![0u8; OWNER_RECOVERY_IMAGE_BYTES]);
        image[..8].copy_from_slice(MAGIC);
        image[8..10].copy_from_slice(&1u16.to_le_bytes());
        image[10..12].copy_from_slice(&VERSION.to_le_bytes());
        image[12..16].copy_from_slice(&(self.geometry.slots() as u32).to_le_bytes());
        image[16..48].copy_from_slice(&Sha256::digest(CONTRACT));
        image[48..80].copy_from_slice(&original_id);
        image[80..82].copy_from_slice(&(PARAMETER_BYTES as u16).to_le_bytes());
        image[82..128].copy_from_slice(&original_public.parameters);
        image[128..132].copy_from_slice(&(SECRET_BYTES as u32).to_le_bytes());
        image[SECRET_OFFSET..].copy_from_slice(&secret);
        Ok(OwnerRecoveryImage { bytes: image })
    }

    /// Accept only an already authenticated, confidential image from the original live Owner.
    /// Checks exact framing/profile/geometry and ORIGINAL setup identity before secret decode.
    /// A digest is identity binding, not a proof that an attacker-chosen secret matches public keys.
    pub fn restore_secret_for_recovery(
        image: &[u8],
        expected_geometry: Geometry,
        original_public: &PublicSetup,
    ) -> RecoveryResult<Self> {
        if image.len() != OWNER_RECOVERY_IMAGE_BYTES
            || &image[..8] != MAGIC
            || image[8..10] != 1u16.to_le_bytes()
            || image[10..12] != VERSION.to_le_bytes()
            || image[16..48] != Sha256::digest(CONTRACT)[..]
            || image[80..82] != (PARAMETER_BYTES as u16).to_le_bytes()
            || image[128..132] != (SECRET_BYTES as u32).to_le_bytes()
        {
            return Err(OwnerRecoveryError::ImageFormat);
        }
        if image[12..16] != (expected_geometry.slots() as u32).to_le_bytes()
            || expected_geometry != original_public.geometry
        {
            return Err(OwnerRecoveryError::Geometry);
        }
        let parameters = original_public
            .checked_parameters()
            .map_err(|_| OwnerRecoveryError::PublicSetup)?;
        if original_public.parameters.len() != PARAMETER_BYTES
            || image[82..128] != original_public.parameters
        {
            return Err(OwnerRecoveryError::ImageProfile);
        }
        let original_id =
            keyset_id(original_public).map_err(|_| OwnerRecoveryError::PublicSetup)?;
        if image[48..80] != original_id {
            return Err(OwnerRecoveryError::KeysetIdentity);
        }
        strict_secret_encoding(&image[SECRET_OFFSET..])?;
        let key = SecretKey::from_bytes(&image[SECRET_OFFSET..], &parameters)
            .map_err(|_| OwnerRecoveryError::SecretEncoding)?;
        Ok(Self {
            parameters,
            key,
            geometry: expected_geometry,
            keyset_id: original_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_secret_gate_rejects_unknown_fields_noncanonical_encoding_and_degree_changes() {
        let mut public_synthetic = vec![0; SECRET_BYTES];
        public_synthetic[..3].copy_from_slice(&[0x0a, 0x80, 0x40]);
        assert!(strict_secret_encoding(&public_synthetic).is_ok());
        for bytes in [&public_synthetic[..SECRET_BYTES - 1], &[]] {
            assert!(strict_secret_encoding(bytes).is_err());
        }
        public_synthetic[3] = 41;
        assert!(strict_secret_encoding(&public_synthetic).is_err());
        public_synthetic[3] = 0;
        public_synthetic.extend_from_slice(&[0x10, 0]);
        assert!(strict_secret_encoding(&public_synthetic).is_err());
    }

    #[test]
    #[ignore = "exclusive CPU lease: original public-key rotation/product/relinearization recovery"]
    fn dropped_owner_recovers_with_original_evaluation_keys_and_no_regeneration() {
        let (original, original_setup) = Owner::generate(Geometry::Rows256).unwrap();
        let original_wire = original_setup.to_bytes().unwrap();
        let original_peer = PeerEvaluator::from_public_setup(&original_setup).unwrap();
        let image = original
            .export_secret_for_recovery(&original_setup)
            .unwrap();
        assert_eq!(image.byte_len(), OWNER_RECOVERY_IMAGE_BYTES);
        drop(original);
        drop(original_setup);
        let unchanged_setup = PublicSetup::from_bytes(&original_wire).unwrap();

        let restored =
            Owner::restore_secret_for_recovery(image.as_ref(), Geometry::Rows256, &unchanged_setup)
                .unwrap();
        let prepared = restored
            .prepare(
                QueryContext::new([5; 16], [6; HEAD_BYTES], [7; HEAD_BYTES]),
                &[
                    SelectedField {
                        age: 7,
                        amount: u16::MAX,
                        active: true,
                    },
                    SelectedField {
                        age: 8,
                        amount: 257,
                        active: true,
                    },
                ],
                Predicate::Equal(7),
            )
            .unwrap();
        let result = original_peer.evaluate(&prepared.request).unwrap();
        assert!(result.stats.rotations > 0);
        assert!(result.stats.ct_ct_multiplications > 0);
        let aggregate = restored
            .decrypt_unverified(prepared.pending, &result.output)
            .unwrap();
        assert_eq!((aggregate.count, aggregate.sum), (1, u32::from(u16::MAX)));
        assert_eq!(unchanged_setup.to_bytes().unwrap(), original_wire);
        assert!(
            Owner::restore_secret_for_recovery(image.as_ref(), Geometry::Rows16, &unchanged_setup)
                .is_err()
        );
        let mut bad_profile = unchanged_setup.clone();
        bad_profile.parameters[0] ^= 1;
        assert!(
            Owner::restore_secret_for_recovery(image.as_ref(), Geometry::Rows256, &bad_profile)
                .is_err()
        );
        let (other_owner, other_setup) = Owner::generate(Geometry::Rows256).unwrap();
        assert!(
            Owner::restore_secret_for_recovery(image.as_ref(), Geometry::Rows256, &other_setup)
                .is_err()
        );
        assert!(
            other_owner
                .export_secret_for_recovery(&unchanged_setup)
                .is_err()
        );
    }
}
