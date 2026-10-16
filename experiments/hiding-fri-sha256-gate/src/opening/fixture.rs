//! Explicitly PUBLIC NONSECRET keys/plaintexts. No Owner API or key exporter.
use super::{
    DATA_SCHEMA, INDEX_SCHEMA, Relation, commitment,
    statement::{Statement, encode_digest, limits},
    trace::Witness,
};
use crate::backend::{Error, Val};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use compact_store::{Commitment, MANIFEST_BYTES};
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};

pub(crate) fn fixture() -> Result<(Statement, Witness), Error> {
    // Known nonsecret input; private-in-proof does not make this fixture a secret.
    let key = core::array::from_fn(|i| i as u8);
    let mut key_rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let key_salt = core::array::from_fn(|_| key_rng.random::<Val>());
    let mut open_rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let open_salt = core::array::from_fn(|_| open_rng.random::<Val>());
    make(
        key,
        key_salt,
        open_salt,
        [0x83; 32],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255],
    )
}
pub(super) fn make(
    key: [u8; 32],
    key_salt: [Val; 4],
    open_salt: [Val; 4],
    request: [u8; 32],
    data: [u8; 12],
) -> Result<(Statement, Witness), Error> {
    // Preserve the historical byte-only fixture exactly.
    let suffix: Vec<_> = (112..2336).map(|i| (i * 113 + 7) as u8).collect();
    from_suffix(
        Relation::Bytes,
        key,
        (key_salt, open_salt),
        request,
        data,
        &suffix,
    )
}
pub(crate) fn canonical_fixture() -> Result<(Statement, Witness), Error> {
    canonical_fixture_relation(Relation::CanonicalIndex)
}
pub(crate) fn packed_canonical_fixture() -> Result<(Statement, Witness), Error> {
    canonical_fixture_relation(Relation::PackedCanonicalIndex)
}
pub(crate) fn factorized_canonical_fixture() -> Result<(Statement, Witness), Error> {
    canonical_fixture_relation(Relation::FactorizedPackedCanonicalIndex)
}
fn canonical_fixture_relation(relation: Relation) -> Result<(Statement, Witness), Error> {
    let key = core::array::from_fn(|i| i as u8); // PUBLIC NONSECRET fixture key.
    let mut key_rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let key_salt = core::array::from_fn(|_| key_rng.random::<Val>());
    let mut open_rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let open_salt = core::array::from_fn(|_| open_rng.random::<Val>());
    from_suffix(
        relation,
        key,
        (key_salt, open_salt),
        [0x83; 32],
        [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0],
        &canonical_suffix(),
    )
}
/// Independent codec-owned PUBLIC NONSECRET vector; no compact-query dependency.
pub(super) fn canonical_suffix() -> Vec<u8> {
    let text = include_str!(
        "../../../../crates/compact-query/tests/fixtures/index-v3-four-row-suffix.hex"
    );
    let bytes: Vec<_> = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|hex| u8::from_str_radix(hex, 16).expect("Reviewed core-owned vector"))
        .collect();
    assert_eq!(bytes.len(), 2224);
    bytes
}
/// Fixture encryption never validates semantic index contents. Rebuilt malicious
/// tests can use genuine AEAD and recomputed commitments for invalid indexes.
pub(super) fn from_suffix(
    relation: Relation,
    key: [u8; 32],
    (key_salt, open_salt): ([Val; 4], [Val; 4]),
    request: [u8; 32],
    data: [u8; 12],
    suffix: &[u8],
) -> Result<(Statement, Witness), Error> {
    if suffix.len() != 2224 {
        return Err(Error::Shape);
    }
    let data_image = image(0, &data, key, [0x24; 24], 2, 3);
    let data_head = Commitment::decode(&data_image[..112], limits()).map_err(|_| Error::Shape)?;
    let mut index = data_head.encode().to_vec();
    index.extend_from_slice(suffix);
    let index_image = image(1, &index, key, [0x91; 24], 1, 3);
    let index_head = Commitment::decode(&index_image[..112], limits()).map_err(|_| Error::Shape)?;
    // Stable C_key is fixed before assembling the request/opening statement.
    let ckey = commitment::digest(&commitment::key_fields(&data_head.encode(), key, key_salt));
    let images = [&data_image[..], &index_image[..]];
    let expected = [&data_head, &index_head];
    let mut statement = match relation {
        Relation::Bytes => {
            Statement::checked(images, expected, request, encode_digest(ckey), [0; 32])?
        }
        Relation::CanonicalIndex
        | Relation::PackedCanonicalIndex
        | Relation::FactorizedPackedCanonicalIndex
        | Relation::StateCertificate => Statement::checked_relation(
            relation,
            images,
            expected,
            request,
            encode_digest(ckey),
            [0; 32],
        )?,
    };
    if relation == Relation::StateCertificate {
        statement.request = super::state::version_tag(&statement);
    }
    let mut plain = data.to_vec();
    plain.extend(index);
    statement.open_commitment =
        commitment::digest(&commitment::opening_fields(&statement, open_salt, &plain));
    Ok((
        statement,
        Witness::new(
            key,
            key_salt,
            open_salt,
            [data[0], data[3], data[6], data[9]],
        ),
    ))
}
/// Fixture-only canonical writer. Acceptance always uses compact-store's complete
/// independent parser/root audit; this is never an alternate accepting validator.
pub(super) fn image(
    page: usize,
    plain: &[u8],
    key: [u8; 32],
    nonce: [u8; 24],
    packet_revision: u64,
    global_revision: u64,
) -> Vec<u8> {
    let mut head = [0; MANIFEST_BYTES];
    head[..8].copy_from_slice(b"CSTORE01");
    head[8..24].fill(0x44);
    head[24..40].fill(0x55);
    head[40..56].copy_from_slice(if page == 0 {
        &DATA_SCHEMA
    } else {
        &INDEX_SCHEMA
    });
    head[56..64].copy_from_slice(&global_revision.to_le_bytes());
    head[64..68].copy_from_slice(&(if page == 0 { 3_u32 } else { 1 }).to_le_bytes());
    head[68..72].copy_from_slice(&(if page == 0 { 256_u32 } else { 4096 }).to_le_bytes());
    head[72..80].copy_from_slice(&(if page == 0 { 4_u64 } else { 2336 }).to_le_bytes());
    let mut aad = b"compact-store/page-aead/v1".to_vec();
    aad.extend_from_slice(&head[8..56]);
    aad.extend_from_slice(&head[64..80]);
    aad.extend_from_slice(&0_u64.to_le_bytes());
    aad.extend_from_slice(&packet_revision.to_le_bytes());
    let encrypted = XChaCha20Poly1305::new(&key.into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .unwrap();
    let mut packet = packet_revision.to_le_bytes().to_vec();
    packet.extend(nonce);
    packet.extend(encrypted);
    assemble(head, packet)
}
pub(super) fn assemble(mut head: [u8; 112], packet: Vec<u8>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"compact-store/leaf/v1");
    h.update(0_u64.to_le_bytes());
    h.update((packet.len() as u64).to_le_bytes());
    h.update(&packet);
    let leaf = h.finalize();
    let mut h = Sha256::new();
    h.update(b"compact-store/snapshot/v1");
    h.update(&head[..80]);
    h.update(leaf);
    head[80..].copy_from_slice(&h.finalize());
    let mut out = head.to_vec();
    out.extend(packet);
    out
}
