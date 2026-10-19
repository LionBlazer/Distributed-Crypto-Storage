//! Fixed in-memory Source AD and guarded payload; no persistent or network I/O.
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use compact_query::ReadHeads;
use compact_store::{Commitment, Layout, Limits};

pub(super) const HEADER: usize = 368;
pub(super) const PRIVATE: usize = 104;
const TAG: usize = 16;
pub(super) const RECORD: usize = HEADER + PRIVATE + TAG;
const MAGIC: &[u8; 8] = b"DCSOSS01";
pub(super) const PRIVATE_MAGIC: &[u8; 8] = b"SRCSEC01";
const VERSION: u16 = 1;
const ROLE: u8 = 1;

pub(super) struct Pins<'a> {
    identity: &'a SourceStateIdentity,
    object: [u8; 32],
    heads: &'a ReadHeads,
}
impl<'a> Pins<'a> {
    pub(super) fn new(
        identity: &'a SourceStateIdentity,
        object: [u8; 32],
        heads: &'a ReadHeads,
    ) -> crate::Result<Self> {
        check_heads(heads.data(), heads.index())?;
        Ok(Self {
            identity,
            object,
            heads,
        })
    }
}
fn check_heads(data: &Commitment, index: &Commitment) -> crate::Result<()> {
    let data_layout = Layout {
        schema: source::DATA_SCHEMA,
        row_width: 3,
        rows_per_page: 256,
        row_count: 4,
    };
    let index_layout = Layout {
        schema: source::INDEX_SCHEMA,
        row_width: 1,
        rows_per_page: 4096,
        row_count: 2336,
    };
    if data.database() != index.database()
        || data.key_domain() != index.key_domain()
        || data.layout() != data_layout
        || index.layout() != index_layout
    {
        return Err(invalid(
            "Source state requires one exact N4 database/domain/head scope",
        ));
    }
    Ok(())
}
pub(super) fn validate(bytes: &[u8]) -> crate::Result<()> {
    if bytes.len() != RECORD {
        return Err(invalid(
            "Source state requires the exact bounded record length",
        ));
    }
    if &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_le_bytes()
        || bytes[10] != ROLE
        || bytes[11..16] != [0; 5]
        || bytes[364..368] != [0; 4]
        || bytes[360..364] != ((PRIVATE + TAG) as u32).to_le_bytes()
    {
        return Err(invalid("Noncanonical Source state envelope"));
    }
    let data = Commitment::decode(&bytes[80..192], Limits::default()).map_err(cryptography)?;
    let index = Commitment::decode(&bytes[192..304], Limits::default()).map_err(cryptography)?;
    check_heads(&data, &index)?;
    let _ = source::statement::decode_digest(bytes[304..336].try_into().unwrap())
        .map_err(cryptography)?;
    Ok(())
}
fn header(pins: &Pins<'_>, nonce: &[u8; 24]) -> Vec<u8> {
    let mut bytes = vec![0; HEADER];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[10] = ROLE;
    bytes[16..48].copy_from_slice(&pins.identity.record_id);
    bytes[48..80].copy_from_slice(&pins.object);
    bytes[80..192].copy_from_slice(&pins.heads.data().encode());
    bytes[192..304].copy_from_slice(&pins.heads.index().encode());
    bytes[304..336].copy_from_slice(&pins.identity.key_commitment);
    bytes[336..360].copy_from_slice(nonce);
    bytes[360..364].copy_from_slice(&((PRIVATE + TAG) as u32).to_le_bytes());
    bytes
}
pub(super) fn seal(
    pins: Pins<'_>,
    authority: &SourceStateAuthority,
    plain: &[u8; PRIVATE],
) -> crate::Result<EncryptedSourceState> {
    let mut nonce = [0; 24];
    getrandom::getrandom(&mut nonce).map_err(cryptography)?;
    let mut bytes = header(&pins, &nonce);
    let mut ciphertext = Zeroizing::new(*plain);
    let cipher = XChaCha20Poly1305::new_from_slice(authority.0.as_ref()).map_err(cryptography)?;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &bytes, ciphertext.as_mut())
        .map_err(cryptography)?;
    bytes.extend_from_slice(ciphertext.as_ref());
    bytes.extend_from_slice(&tag);
    validate(&bytes)?;
    Ok(EncryptedSourceState { bytes })
}
pub(super) fn open(
    pins: Pins<'_>,
    authority: &SourceStateAuthority,
    record: &EncryptedSourceState,
) -> crate::Result<Zeroizing<[u8; PRIVATE]>> {
    let bytes = record.as_bytes();
    validate(bytes)?;
    let expected = header(&pins, bytes[336..360].try_into().unwrap());
    if bytes[..HEADER] != expected {
        return Err(invalid(
            "Source state differs from the independent snapshot/record/Ckey pins",
        ));
    }
    let mut plain = Zeroizing::new([0; PRIVATE]);
    plain.copy_from_slice(&bytes[HEADER..HEADER + PRIVATE]);
    let cipher = XChaCha20Poly1305::new_from_slice(authority.0.as_ref()).map_err(cryptography)?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&bytes[336..360]),
            &expected,
            plain.as_mut(),
            Tag::<XChaCha20Poly1305>::from_slice(&bytes[HEADER + PRIVATE..]),
        )
        .map_err(cryptography)?;
    Ok(plain)
}
