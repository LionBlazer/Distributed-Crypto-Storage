use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{Commitment, EncryptedSnapshot, Error, Layout, Limits, Result, VerifiedPage};

/// Sole key owner. No Debug, Clone, serialization, or secret-key accessor.
/// The key is zeroized on drop; the application owns plaintext supplied to seal.
pub struct Owner {
    key: Zeroizing<[u8; 32]>,
    database: [u8; 16],
    domain: [u8; 16],
}

/// Owner-only temporary stream mask; erased on drop. Never send this plaintext pad to a peer.
pub struct SecretMask {
    bytes: Zeroizing<Vec<u8>>,
}
impl SecretMask {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Decrypted owner-side page. Its byte buffer is zeroized on drop.
/// Application copies and source plaintext remain the application's responsibility.
pub struct PlainPage {
    bytes: Zeroizing<Vec<u8>>,
}
impl PlainPage {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Owner {
    pub fn generate(database: [u8; 16]) -> Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        let mut domain = [0; 16];
        getrandom::getrandom(key.as_mut()).map_err(|_| Error::Randomness)?;
        getrandom::getrandom(&mut domain).map_err(|_| Error::Randomness)?;
        Ok(Self {
            key,
            database,
            domain,
        })
    }

    /// Creates a new owner-built immutable read head at revision zero.
    pub fn seal(
        &self,
        layout: Layout,
        plaintext: &[u8],
        limits: Limits,
    ) -> Result<EncryptedSnapshot> {
        layout.validate(limits)?;
        if plaintext.len() != layout.logical_bytes()? {
            return Err(Error::InvalidPage);
        }
        let commitment = Commitment {
            database: self.database,
            domain: self.domain,
            layout,
            revision: 0,
            root: [0; 32],
        };
        let mut pages = Vec::with_capacity(layout.page_count()?);
        let mut offset = 0;
        for index in 0..layout.page_count()? {
            let size = layout.page_plaintext_len(index as u64)?;
            pages.push(self.encrypt_page(
                &commitment,
                index as u64,
                &plaintext[offset..offset + size],
            )?);
            offset += size;
        }
        Ok(EncryptedSnapshot::from_owner(commitment, pages))
    }

    /// Owner-authorized growth from a fully checked plaintext relation. The caller must
    /// authenticate/validate its old prefix before calling; this primitive does not run SQL.
    /// Geometry other than row count and owner identity are retained. Every page uses a
    /// fresh nonce and the next revision because row count is part of every page's AAD.
    /// Returns staged state only; failure never mutates the source image.
    pub fn grow_from_checked_plaintext(
        &self,
        snapshot: &EncryptedSnapshot,
        expected: &Commitment,
        row_count: u64,
        plaintext: &[u8],
        limits: Limits,
    ) -> Result<EncryptedSnapshot> {
        if snapshot.commitment() != expected {
            return Err(Error::WrongVersion);
        }
        self.check_owner(expected)?;
        if row_count <= expected.layout.row_count {
            return Err(Error::InvalidFormat);
        }
        let mut next = expected.clone();
        next.layout.row_count = row_count;
        next.layout.validate(limits)?;
        if plaintext.len() != next.layout.logical_bytes()? {
            return Err(Error::InvalidPage);
        }
        next.revision = expected
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        let mut pages = Vec::with_capacity(next.layout.page_count()?);
        let mut offset = 0;
        for index in 0..next.layout.page_count()? {
            let size = next.layout.page_plaintext_len(index as u64)?;
            pages.push(self.encrypt_page(
                &next,
                index as u64,
                &plaintext[offset..offset + size],
            )?);
            offset += size;
        }
        Ok(EncryptedSnapshot::from_owner(next, pages))
    }

    /// Replaces one existing page, retaining no historical ciphertext in the
    /// snapshot. The caller must hold the previously confirmed head and publish
    /// the returned head through its separate authorization/consensus protocol.
    pub fn replace_page(
        &self,
        snapshot: &mut EncryptedSnapshot,
        expected: &Commitment,
        index: u64,
        plaintext: &[u8],
        limits: Limits,
    ) -> Result<Commitment> {
        if snapshot.commitment() != expected {
            return Err(Error::WrongVersion);
        }
        self.check_owner(expected)?;
        expected.layout.validate(limits)?;
        if plaintext.len() != expected.layout.page_plaintext_len(index)? {
            return Err(Error::InvalidPage);
        }
        let mut next = expected.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        let packet = self.encrypt_page(&next, index, plaintext)?;
        snapshot.replace_from_owner(next, index as usize, packet);
        Ok(snapshot.commitment().clone())
    }

    /// Reissues one authenticated page using its retained path, without a partial
    /// snapshot. The exact independently trusted source head is required again.
    /// Authenticates old AEAD before generating a fresh nonce; returns a proposal
    /// head and ordinary membership response, not SQL proof or publication.
    pub fn reissue_page(
        &self,
        source: crate::VerifiedPagePath,
        expected: &Commitment,
        plaintext: &[u8],
        limits: Limits,
    ) -> Result<(Commitment, crate::LookupResponse)> {
        if source.page().commitment() != expected {
            return Err(Error::WrongVersion);
        }
        self.check_owner(expected)?;
        expected.layout.validate(limits)?;
        if source.encoded_len() > limits.max_response_bytes {
            return Err(Error::ResourceLimit);
        }
        let index = source.page().page_index();
        if plaintext.len() != expected.layout.page_plaintext_len(index)? {
            return Err(Error::InvalidPage);
        }
        let mut next = expected.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        // This temporary plaintext is erased before new encryption begins.
        drop(self.decrypt(source.page())?);
        let packet = self.encrypt_page(&next, index, plaintext)?;
        source.reissue(next, packet)
    }

    pub fn decrypt(&self, page: &VerifiedPage) -> Result<PlainPage> {
        self.check_owner(&page.commitment)?;
        let revision = page.page_revision();
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref()).unwrap();
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&page.nonce()),
                Payload {
                    msg: &page.packet[32..],
                    aad: &page.commitment.aad(page.index, revision),
                },
            )
            .map_err(|_| Error::Authentication)?;
        Ok(PlainPage {
            bytes: Zeroizing::new(plaintext),
        })
    }

    /// Authenticates and decrypts only at the owner, then XORs the requested range
    /// with the public ciphertext. No key export or new stream primitive is used.
    /// Both the decrypted page and temporary returned mask are erased on drop.
    pub fn derive_keystream_range(
        &self,
        page: &VerifiedPage,
        range: std::ops::Range<usize>,
    ) -> Result<SecretMask> {
        if range.start > range.end || range.end > page.ciphertext().len() {
            return Err(Error::InvalidPage);
        }
        let plaintext = self.decrypt(page)?;
        let bytes = plaintext.as_bytes()[range.clone()]
            .iter()
            .zip(&page.ciphertext()[range])
            .map(|(plain, cipher)| plain ^ cipher)
            .collect();
        Ok(SecretMask {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Stage every replacement and fresh nonce before mutating the live snapshot.
    /// A single global revision covers all pages; failure leaves every page intact.
    pub fn replace_pages(
        &self,
        snapshot: &mut EncryptedSnapshot,
        expected: &Commitment,
        replacements: &[(u64, &[u8])],
        limits: Limits,
    ) -> Result<Commitment> {
        if snapshot.commitment() != expected {
            return Err(Error::WrongVersion);
        }
        self.check_owner(expected)?;
        expected.layout.validate(limits)?;
        let mut seen = std::collections::BTreeSet::new();
        for (index, plain) in replacements {
            if !seen.insert(*index) || plain.len() != expected.layout.page_plaintext_len(*index)? {
                return Err(Error::InvalidPage);
            }
        }
        if replacements.is_empty() {
            return Ok(expected.clone());
        }
        let mut next = expected.clone();
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        let packets = replacements
            .iter()
            .map(|(index, plain)| Ok((*index, self.encrypt_page(&next, *index, plain)?)))
            .collect::<Result<Vec<_>>>()?;
        for (index, packet) in packets {
            snapshot.replace_from_owner(next.clone(), index as usize, packet);
        }
        Ok(snapshot.commitment().clone())
    }
    fn check_owner(&self, commitment: &Commitment) -> Result<()> {
        if commitment.database != self.database || commitment.domain != self.domain {
            return Err(Error::WrongOwner);
        }
        Ok(())
    }

    fn encrypt_page(
        &self,
        commitment: &Commitment,
        index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        // Fresh 192-bit OS-random nonces avoid reuse across snapshots and retries.
        // Production key/message limits and durable key management remain external.
        let mut nonce = [0; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Randomness)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref()).unwrap();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &commitment.aad(index, commitment.revision),
                },
            )
            .map_err(|_| Error::Authentication)?;
        let mut packet = Vec::with_capacity(32 + ciphertext.len());
        packet.extend_from_slice(&commitment.revision.to_le_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> (Owner, VerifiedPage) {
        let limits = Limits::default();
        let owner = Owner::generate([99; 16]).unwrap();
        let layout = Layout {
            schema: [1; 16],
            row_width: 3,
            rows_per_page: 2,
            row_count: 4,
        };
        let snapshot = owner.seal(layout, &[7; 12], limits).unwrap();
        let verified = snapshot
            .lookup(0, limits)
            .unwrap()
            .verify(snapshot.commitment(), 0, limits)
            .unwrap();
        (owner, verified)
    }

    #[test]
    fn aead_independently_rejects_modified_nonce_payload_and_tag() {
        // Deliberately bypass Merkle verification to test the separate AEAD boundary.
        for offset in [8, 32, 53] {
            let (owner, mut verified) = page();

            verified.packet[offset] ^= 1;

            assert!(matches!(
                owner.decrypt(&verified),
                Err(Error::Authentication)
            ));
        }
    }

    #[test]
    fn aead_rejects_rebinding_the_same_ciphertext_to_schema_geometry_address_or_page_revision() {
        for field in 0..5 {
            let (owner, mut verified) = page();

            match field {
                0 => verified.commitment.layout.schema[0] ^= 1,
                1 => verified.commitment.layout.row_width += 1,
                2 => verified.commitment.layout.row_count += 1,
                3 => verified.index += 1,
                4 => verified.packet[0] ^= 1,
                _ => unreachable!(),
            }

            assert!(matches!(
                owner.decrypt(&verified),
                Err(Error::Authentication)
            ));
        }
    }

    fn reissue_fixture() -> (Owner, EncryptedSnapshot) {
        let owner = Owner::generate([83; 16]).unwrap();
        let image = owner
            .seal(
                Layout {
                    schema: [84; 16],
                    row_width: 3,
                    rows_per_page: 2,
                    row_count: 2,
                },
                &[7; 6],
                Limits::default(),
            )
            .unwrap();
        (owner, image)
    }

    #[test]
    fn reissue_authenticates_old_aead_even_when_membership_is_valid_for_modified_bytes() {
        for offset in [8, 32, 53] {
            let (owner, original) = reissue_fixture();
            let original_bytes = original.encode();
            let mut packet = original.lookup(0, Limits::default()).unwrap().packet;
            packet[offset] ^= 1;
            // Complete malformed fixture with a valid Merkle root, invalid AEAD.
            let hostile =
                EncryptedSnapshot::from_owner(original.commitment().clone(), vec![packet]);
            let before = hostile.encode();
            let head = hostile.commitment();
            let source = hostile
                .lookup(0, Limits::default())
                .unwrap()
                .verify_for_reissue(head, 0, Limits::default())
                .unwrap();

            assert!(matches!(
                owner.reissue_page(source, head, &[9; 6], Limits::default()),
                Err(Error::Authentication)
            ));

            assert_eq!(hostile.encode(), before);
            assert_eq!(original.encode(), original_bytes);
        }
    }

    #[test]
    fn reissue_rejects_a_wrong_key_even_with_matching_owner_metadata() {
        let (owner, image) = reissue_fixture();
        let mut wrong_key = Owner::generate(owner.database).unwrap();
        wrong_key.domain = owner.domain;
        let before = image.encode();
        let source = image
            .lookup(0, Limits::default())
            .unwrap()
            .verify_for_reissue(image.commitment(), 0, Limits::default())
            .unwrap();

        assert!(matches!(
            wrong_key.reissue_page(source, image.commitment(), &[9; 6], Limits::default()),
            Err(Error::Authentication)
        ));

        assert_eq!(image.encode(), before);
    }

    #[test]
    fn reissue_rejects_global_revision_exhaustion_without_changing_the_source() {
        let (owner, original) = reissue_fixture();
        let mut head = original.commitment().clone();
        head.revision = u64::MAX;
        let packet = original.lookup(0, Limits::default()).unwrap().packet;
        let exhausted = EncryptedSnapshot::from_owner(head, vec![packet]);
        let before = exhausted.encode();
        let source = exhausted
            .lookup(0, Limits::default())
            .unwrap()
            .verify_for_reissue(exhausted.commitment(), 0, Limits::default())
            .unwrap();

        assert!(matches!(
            owner.reissue_page(source, exhausted.commitment(), &[9; 6], Limits::default()),
            Err(Error::RevisionExhausted)
        ));

        assert_eq!(exhausted.encode(), before);
    }
}
