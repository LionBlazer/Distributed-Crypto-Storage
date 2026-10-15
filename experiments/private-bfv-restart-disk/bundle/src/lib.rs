//! Candidate sealed checkpoint composition. Owning cryptographic libraries have no dependency here.
//! AEAD authenticity does not select the latest checkpoint or supply durable multi-file publication.
#![forbid(unsafe_code)]

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use compact_bfv_byte_limb_core::{Geometry, Owner as BfvOwner, PublicSetup};
use compact_store::{Commitment, EncryptedSnapshot, Limits, MANIFEST_BYTES, Owner as CompactOwner};
use sha2::{Digest, Sha256};
use spiral_owner_state::{OwnerState, Restored as RestoredPir};
use spiral_rs::params::Params;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

pub const MIN_TABLES: usize = 3;
pub const MAX_TABLES: usize = 2_000;
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BFV_PUBLIC_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_BUNDLE_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const WRAPPING_KEY_BYTES: usize = 32;
pub const OUTER_HEADER_BYTES: usize = 112;
pub const MAX_SEALED_BUNDLE_BYTES: usize = OUTER_HEADER_BYTES + MAX_BUNDLE_PLAINTEXT_BYTES + 16;
const OUTER_MAGIC: &[u8; 8] = b"OWNBNDL1";
const INNER_MAGIC: &[u8; 8] = b"OWNBODY1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    Bounds,
    Format,
    Authentication,
    Randomness,
    Checkpoint,
    PublicIdentity,
    Catalog,
    File,
    StorageOwner,
    BfvOwner,
    PirOwner,
}
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealed owner recovery rejected {self:?}")
    }
}
impl std::error::Error for RecoveryError {}
pub type Result<T> = std::result::Result<T, RecoveryError>;

/// Keep separately from sealed backups. No Debug, serializer, byte accessor or file/CLI loader.
pub struct WrappingKey(Zeroizing<[u8; WRAPPING_KEY_BYTES]>);
impl WrappingKey {
    pub fn generate() -> Result<Self> {
        let mut key = Zeroizing::new([0u8; WRAPPING_KEY_BYTES]);
        getrandom::getrandom(key.as_mut()).map_err(|_| RecoveryError::Randomness)?;
        Ok(Self(key))
    }
    /// The external key custodian supplies protected RAM; this crate performs no key persistence.
    pub fn from_protected_memory(key: Zeroizing<[u8; WRAPPING_KEY_BYTES]>) -> Self {
        Self(key)
    }
}

/// Public binding. Only a separately authenticated latest-checkpoint authority makes it current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointBinding {
    pub bundle_id: [u8; 32],
    pub checkpoint_id: [u8; 32],
    pub generation: u64,
}

/// This PUBLIC anchor must be held/published independently of the untrusted backup source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAnchor {
    pub binding: CheckpointBinding,
    pub catalog_digest: [u8; 32],
    pub bfv_public_digest: [u8; 32],
    pub pir_public_digest: [u8; 32],
    pub geometry: Geometry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableMetadata {
    pub table_id: u32,
    pub data_file: String,
    pub index_file: String,
    pub data_bytes: u64,
    pub index_bytes: u64,
    pub data_head: Commitment,
    pub index_head: Commitment,
}
pub struct TableCheckpoint<'a> {
    pub metadata: TableMetadata,
    pub owner: &'a CompactOwner,
}
pub struct OriginalPublic<'a> {
    pub bfv: &'a [u8],
    pub pir: &'a [u8],
}
pub struct SealedCheckpoint {
    pub wire: Vec<u8>,            // ciphertext only; safe for a peer/backup file.
    pub anchor: CheckpointAnchor, // public, but needs separate freshness/authentication.
}
pub struct RestoredTable {
    metadata: TableMetadata,
    owner: CompactOwner,
}
impl RestoredTable {
    pub fn metadata(&self) -> &TableMetadata {
        &self.metadata
    }
    pub fn owner(&self) -> &CompactOwner {
        &self.owner
    }

    /// Read unchanged canonical files; reconstruct full Merkle roots before returning snapshots.
    /// Held-file exact reads are bounded and trusted heads remain authoritative.
    pub fn read_original_snapshots(
        &self,
        directory: &Path,
    ) -> Result<(EncryptedSnapshot, EncryptedSnapshot)> {
        let data = read_snapshot(
            directory,
            &self.metadata.data_file,
            self.metadata.data_bytes,
            &self.metadata.data_head,
        )?;
        let index = read_snapshot(
            directory,
            &self.metadata.index_file,
            self.metadata.index_bytes,
            &self.metadata.index_head,
        )?;
        Ok((data, index))
    }
}
pub struct RestoredCheckpoint<'p> {
    anchor: CheckpointAnchor,
    tables: Vec<RestoredTable>,
    bfv_owner: BfvOwner,
    bfv_public: PublicSetup,
    pir: RestoredPir<'p>,
}
impl<'p> RestoredCheckpoint<'p> {
    pub fn anchor(&self) -> &CheckpointAnchor {
        &self.anchor
    }
    pub fn tables(&self) -> &[RestoredTable] {
        &self.tables
    }
    pub fn bfv_owner(&self) -> &BfvOwner {
        &self.bfv_owner
    }
    pub fn bfv_public(&self) -> &PublicSetup {
        &self.bfv_public
    }
    pub fn pir(&self) -> &RestoredPir<'p> {
        &self.pir
    }
}
pub fn snapshot_limits() -> Limits {
    Limits {
        max_rows: MAX_IMAGE_BYTES as u64,
        max_image_bytes: MAX_IMAGE_BYTES,
        ..Limits::default()
    }
}

fn leaf_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || matches!(x, b'.' | b'_' | b'-'))
}
fn check_catalog(metadata: &[TableMetadata]) -> Result<()> {
    if !(MIN_TABLES..=MAX_TABLES).contains(&metadata.len()) {
        return Err(RecoveryError::Bounds);
    }
    let mut previous = None;
    let mut names = BTreeSet::new();
    let mut databases = BTreeSet::new();
    for table in metadata {
        if table.table_id as usize >= MAX_TABLES
            || previous.is_some_and(|id| table.table_id <= id)
            || !leaf_name(&table.data_file)
            || !leaf_name(&table.index_file)
            || !names.insert(table.data_file.as_str())
            || !names.insert(table.index_file.as_str())
            || !databases.insert(table.data_head.database())
            || table.data_head.database() != table.index_head.database()
            || table.data_head.key_domain() != table.index_head.key_domain()
        {
            return Err(RecoveryError::Catalog);
        }
        previous = Some(table.table_id);
        for (head, bytes) in [
            (&table.data_head, table.data_bytes),
            (&table.index_head, table.index_bytes),
        ] {
            head.layout()
                .validate(snapshot_limits())
                .map_err(|_| RecoveryError::Catalog)?;
            if bytes as u128
                != head
                    .layout()
                    .encoded_len()
                    .map_err(|_| RecoveryError::Catalog)? as u128
                || bytes as u128 > MAX_IMAGE_BYTES as u128
            {
                return Err(RecoveryError::Bounds);
            }
        }
    }
    Ok(())
}
fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| RecoveryError::Bounds)?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put_name(out: &mut Vec<u8>, name: &str) {
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
}
fn put_metadata(out: &mut Vec<u8>, table: &TableMetadata) {
    out.extend_from_slice(&table.table_id.to_le_bytes());
    put_name(out, &table.data_file);
    put_name(out, &table.index_file);
    out.extend_from_slice(&table.data_bytes.to_le_bytes());
    out.extend_from_slice(&table.index_bytes.to_le_bytes());
    out.extend_from_slice(&table.data_head.encode());
    out.extend_from_slice(&table.index_head.encode());
}
pub fn catalog_digest(metadata: &[TableMetadata]) -> Result<[u8; 32]> {
    check_catalog(metadata)?;
    let mut public = Vec::with_capacity(metadata.len() * 400);
    public.extend_from_slice(b"owner-checkpoint/catalog/v1");
    put_u32(&mut public, metadata.len())?;
    for table in metadata {
        put_metadata(&mut public, table);
    }
    Ok(Sha256::digest(&public).into())
}
fn check_public(public: &OriginalPublic<'_>) -> Result<([u8; 32], [u8; 32])> {
    if public.bfv.is_empty()
        || public.bfv.len() > MAX_BFV_PUBLIC_BYTES
        || public.pir.len() != spiral_owner_state::PUBLIC_SETUP_BYTES
    {
        return Err(RecoveryError::Bounds);
    }
    Ok((
        Sha256::digest(public.bfv).into(),
        Sha256::digest(public.pir).into(),
    ))
}
fn outer_header(
    binding: CheckpointBinding,
    cipher_len: usize,
    nonce: &[u8; 24],
) -> Result<[u8; 112]> {
    let mut header = [0u8; OUTER_HEADER_BYTES];
    header[..8].copy_from_slice(OUTER_MAGIC);
    header[8..10].copy_from_slice(&1u16.to_le_bytes()); // format
    header[10..12].copy_from_slice(&1u16.to_le_bytes()); // standard XChaCha20Poly1305
    header[12..16].copy_from_slice(
        &u32::try_from(cipher_len)
            .map_err(|_| RecoveryError::Bounds)?
            .to_le_bytes(),
    );
    header[16..48].copy_from_slice(&binding.bundle_id);
    header[48..80].copy_from_slice(&binding.checkpoint_id);
    header[80..88].copy_from_slice(&binding.generation.to_le_bytes());
    header[88..112].copy_from_slice(nonce);
    Ok(header)
}

/// Seal a consistent live-owner checkpoint. Only ciphertext and a PUBLIC anchor leave this API.
/// Actual snapshot/public-file durable publication and wrapping-key custody are external.
pub fn seal_checkpoint(
    wrapping: &WrappingKey,
    binding: CheckpointBinding,
    tables: &[TableCheckpoint<'_>],
    bfv_owner: &BfvOwner,
    public: OriginalPublic<'_>,
    pir_owner: &OwnerState,
    pir_domain: [u8; 32],
) -> Result<SealedCheckpoint> {
    if !(MIN_TABLES..=MAX_TABLES).contains(&tables.len()) {
        return Err(RecoveryError::Bounds);
    }
    let metadata: Vec<_> = tables.iter().map(|t| t.metadata.clone()).collect();
    let catalog_digest = catalog_digest(&metadata)?;
    let (bfv_digest, pir_digest) = check_public(&public)?;
    let original_bfv = PublicSetup::from_bytes(public.bfv).map_err(|_| RecoveryError::BfvOwner)?;
    let bfv_image = bfv_owner
        .export_secret_for_recovery(&original_bfv)
        .map_err(|_| RecoveryError::BfvOwner)?;
    let pir_image = pir_owner.encode_secret_for_experiment();
    // Existing wrapper validates original public/seed/domain/profile/platform before use.
    // The transient validation Client is dropped here, never retained as a second live setup.
    let params = spiral_owner_state::profile_params();
    drop(
        OwnerState::restore(&params, pir_domain, pir_image.as_ref(), public.pir)
            .map_err(|_| RecoveryError::PirOwner)?,
    );
    let anchor = CheckpointAnchor {
        binding,
        catalog_digest,
        bfv_public_digest: bfv_digest,
        pir_public_digest: pir_digest,
        geometry: original_bfv.geometry(),
    };
    let mut plaintext = Zeroizing::new(Vec::with_capacity(16_384 + metadata.len() * 456));
    plaintext.extend_from_slice(INNER_MAGIC);
    put_u32(&mut plaintext, public.bfv.len())?;
    plaintext.extend_from_slice(&bfv_digest);
    put_u32(&mut plaintext, anchor.geometry.slots())?;
    put_u32(&mut plaintext, public.pir.len())?;
    plaintext.extend_from_slice(&pir_digest);
    plaintext.extend_from_slice(&pir_domain);
    put_u32(&mut plaintext, bfv_image.byte_len())?;
    plaintext.extend_from_slice(bfv_image.as_ref());
    put_u32(&mut plaintext, pir_image.len())?;
    plaintext.extend_from_slice(pir_image.as_ref());
    put_u32(&mut plaintext, tables.len())?;
    for table in tables {
        put_metadata(&mut plaintext, &table.metadata);
        let image = table.owner.export_secret_for_recovery();
        if image.as_ref()[16..32] != table.metadata.data_head.database()
            || image.as_ref()[32..48] != table.metadata.data_head.key_domain()
        {
            return Err(RecoveryError::StorageOwner);
        }
        plaintext.extend_from_slice(image.as_ref());
    }
    if plaintext.len() > MAX_BUNDLE_PLAINTEXT_BYTES {
        return Err(RecoveryError::Bounds);
    }
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| RecoveryError::Randomness)?;
    let header = outer_header(binding, plaintext.len() + 16, &nonce)?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping.0.as_ref())
        .map_err(|_| RecoveryError::Format)?;
    cipher
        .encrypt_in_place(XNonce::from_slice(&nonce), &header, &mut *plaintext)
        .map_err(|_| RecoveryError::Authentication)?;
    let mut wire = Vec::with_capacity(header.len() + plaintext.len());
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&plaintext);
    Ok(SealedCheckpoint { wire, anchor })
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(size)
            .ok_or(RecoveryError::Bounds)?;
        let part = self
            .bytes
            .get(self.position..end)
            .ok_or(RecoveryError::Format)?;
        self.position = end;
        Ok(part)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| RecoveryError::Format)?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RecoveryError::Format)?,
        ))
    }
    fn digest(&mut self) -> Result<[u8; 32]> {
        self.take(32)?.try_into().map_err(|_| RecoveryError::Format)
    }
    fn name(&mut self) -> Result<String> {
        let size = usize::from(self.take(1)?[0]);
        if size == 0 || size > 64 {
            return Err(RecoveryError::Bounds);
        }
        let name = std::str::from_utf8(self.take(size)?).map_err(|_| RecoveryError::Catalog)?;
        if !leaf_name(name) {
            return Err(RecoveryError::Catalog);
        }
        Ok(name.to_owned())
    }
    fn metadata(&mut self) -> Result<TableMetadata> {
        let table_id = self.u32()?;
        let data_file = self.name()?;
        let index_file = self.name()?;
        let data_bytes = self.u64()?;
        let index_bytes = self.u64()?;
        let data_head = Commitment::decode(self.take(MANIFEST_BYTES)?, snapshot_limits())
            .map_err(|_| RecoveryError::Catalog)?;
        let index_head = Commitment::decode(self.take(MANIFEST_BYTES)?, snapshot_limits())
            .map_err(|_| RecoveryError::Catalog)?;
        Ok(TableMetadata {
            table_id,
            data_file,
            index_file,
            data_bytes,
            index_bytes,
            data_head,
            index_head,
        })
    }
}

fn open_checkpoint(
    wrapping: &WrappingKey,
    expected: &CheckpointAnchor,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < OUTER_HEADER_BYTES + 16 || sealed.len() > MAX_SEALED_BUNDLE_BYTES {
        return Err(RecoveryError::Bounds);
    }
    let header = &sealed[..OUTER_HEADER_BYTES];
    if &header[..8] != OUTER_MAGIC
        || header[8..10] != 1u16.to_le_bytes()
        || header[10..12] != 1u16.to_le_bytes()
    {
        return Err(RecoveryError::Format);
    }
    let length = u32::from_le_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| RecoveryError::Format)?,
    ) as usize;
    if length != sealed.len() - OUTER_HEADER_BYTES {
        return Err(RecoveryError::Bounds);
    }
    let generation = u64::from_le_bytes(
        header[80..88]
            .try_into()
            .map_err(|_| RecoveryError::Format)?,
    );
    if header[16..48] != expected.binding.bundle_id
        || header[48..80] != expected.binding.checkpoint_id
        || generation != expected.binding.generation
    {
        return Err(RecoveryError::Checkpoint);
    }
    // Only fixed bounded public framing is inspected before AEAD. No secret/protobuf/SDK decode.
    let mut plaintext = Zeroizing::new(sealed[OUTER_HEADER_BYTES..].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping.0.as_ref())
        .map_err(|_| RecoveryError::Format)?;
    cipher
        .decrypt_in_place(
            XNonce::from_slice(&header[88..112]),
            header,
            &mut *plaintext,
        )
        .map_err(|_| RecoveryError::Authentication)?;
    Ok(plaintext)
}

/// Restore only after complete bounded AEAD and authenticated catalog/public identity gates.
/// expected must come from the caller's EXTERNAL latest-checkpoint authority.
/// All handle construction is provisional; failure drops every already-created secret owner.
pub fn restore_checkpoint<'p>(
    wrapping: &WrappingKey,
    expected: &CheckpointAnchor,
    sealed: &[u8],
    public: OriginalPublic<'_>,
    pir_params: &'p Params,
    directory: &Path,
) -> Result<RestoredCheckpoint<'p>> {
    let plaintext = open_checkpoint(wrapping, expected, sealed)?;
    let mut reader = Reader {
        bytes: &plaintext,
        position: 0,
    };
    if reader.take(8)? != INNER_MAGIC {
        return Err(RecoveryError::Format);
    }
    let bfv_length = reader.u32()? as usize;
    let bfv_digest = reader.digest()?;
    let geometry = match reader.u32()? {
        16 => Geometry::Rows16,
        256 => Geometry::Rows256,
        _ => return Err(RecoveryError::Bounds),
    };
    let pir_length = reader.u32()? as usize;
    let pir_digest = reader.digest()?;
    let pir_domain = reader.digest()?;
    if reader.u32()? as usize != compact_bfv_byte_limb_core::OWNER_RECOVERY_IMAGE_BYTES {
        return Err(RecoveryError::Bounds);
    }
    let bfv_image = reader.take(compact_bfv_byte_limb_core::OWNER_RECOVERY_IMAGE_BYTES)?;
    if reader.u32()? as usize != spiral_owner_state::OWNER_STATE_BYTES {
        return Err(RecoveryError::Bounds);
    }
    let pir_image = reader.take(spiral_owner_state::OWNER_STATE_BYTES)?;
    let count = reader.u32()? as usize;
    if !(MIN_TABLES..=MAX_TABLES).contains(&count) {
        return Err(RecoveryError::Bounds);
    }
    let mut metadata = Vec::with_capacity(count);
    let mut images = Vec::with_capacity(count);
    for _ in 0..count {
        metadata.push(reader.metadata()?);
        images.push(reader.take(compact_store::OWNER_RECOVERY_IMAGE_BYTES)?);
    }
    if reader.position != plaintext.len() {
        return Err(RecoveryError::Format);
    }
    if catalog_digest(&metadata)? != expected.catalog_digest || geometry != expected.geometry {
        return Err(RecoveryError::Checkpoint);
    }
    let (actual_bfv_digest, actual_pir_digest) = check_public(&public)?;
    if bfv_length != public.bfv.len()
        || pir_length != public.pir.len()
        || bfv_digest != expected.bfv_public_digest
        || pir_digest != expected.pir_public_digest
        || bfv_digest != actual_bfv_digest
        || pir_digest != actual_pir_digest
    {
        return Err(RecoveryError::PublicIdentity);
    }
    // Public files and ALL physical snapshot head/length pairs are checked before secret decode.
    for table in &metadata {
        check_original_file(
            directory,
            &table.data_file,
            table.data_bytes,
            &table.data_head,
        )?;
        check_original_file(
            directory,
            &table.index_file,
            table.index_bytes,
            &table.index_head,
        )?;
    }
    let bfv_public = PublicSetup::from_bytes(public.bfv).map_err(|_| RecoveryError::BfvOwner)?;
    let bfv_owner = BfvOwner::restore_secret_for_recovery(bfv_image, geometry, &bfv_public)
        .map_err(|_| RecoveryError::BfvOwner)?;
    let pir = OwnerState::restore(pir_params, pir_domain, pir_image, public.pir)
        .map_err(|_| RecoveryError::PirOwner)?;
    let mut tables = Vec::with_capacity(count);
    for (table, image) in metadata.into_iter().zip(images) {
        let owner = CompactOwner::restore_secret_for_recovery(
            image,
            table.data_head.database(),
            table.data_head.key_domain(),
        )
        .map_err(|_| RecoveryError::StorageOwner)?;
        tables.push(RestoredTable {
            metadata: table,
            owner,
        });
    }
    Ok(RestoredCheckpoint {
        anchor: expected.clone(),
        tables,
        bfv_owner,
        bfv_public,
        pir,
    })
}

fn checked_file(directory: &Path, name: &str, expected: u64) -> Result<std::fs::File> {
    if !leaf_name(name) || expected > MAX_IMAGE_BYTES as u64 {
        return Err(RecoveryError::Bounds);
    }
    let file = std::fs::File::open(directory.join(name)).map_err(|_| RecoveryError::File)?;
    let metadata = file.metadata().map_err(|_| RecoveryError::File)?;
    if !metadata.is_file() || metadata.len() != expected {
        return Err(RecoveryError::File);
    }
    Ok(file)
}
fn check_original_file(directory: &Path, name: &str, bytes: u64, head: &Commitment) -> Result<()> {
    let mut file = checked_file(directory, name, bytes)?;
    let mut actual = [0u8; MANIFEST_BYTES];
    file.read_exact(&mut actual)
        .map_err(|_| RecoveryError::File)?;
    if actual != head.encode() {
        return Err(RecoveryError::Checkpoint);
    }
    Ok(())
}
fn read_snapshot(
    directory: &Path,
    name: &str,
    bytes: u64,
    head: &Commitment,
) -> Result<EncryptedSnapshot> {
    let mut file = checked_file(directory, name, bytes)?;
    let mut image = vec![0u8; usize::try_from(bytes).map_err(|_| RecoveryError::Bounds)?];
    file.read_exact(&mut image)
        .map_err(|_| RecoveryError::File)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(|_| RecoveryError::File)? != 0 {
        return Err(RecoveryError::File);
    }
    let snapshot =
        EncryptedSnapshot::decode(&image, snapshot_limits()).map_err(|_| RecoveryError::Catalog)?;
    if snapshot.commitment() != head {
        return Err(RecoveryError::Checkpoint);
    }
    Ok(snapshot)
}

/// Owned lifecycle seam for a separate process reader. No secret cloning or self references.
pub struct RestoredTableParts {
    pub metadata: TableMetadata,
    pub owner: CompactOwner,
}
impl RestoredTable {
    pub fn into_parts(self) -> RestoredTableParts {
        RestoredTableParts {
            metadata: self.metadata,
            owner: self.owner,
        }
    }
}
/// All owners move into the caller's independently scoped runtime.
pub struct RestoredCheckpointParts<'p> {
    pub anchor: CheckpointAnchor,
    pub tables: Vec<RestoredTable>,
    pub bfv_owner: BfvOwner,
    pub bfv_public: PublicSetup,
    pub pir: RestoredPir<'p>,
}
impl<'p> RestoredCheckpoint<'p> {
    pub fn into_parts(self) -> RestoredCheckpointParts<'p> {
        RestoredCheckpointParts {
            anchor: self.anchor,
            tables: self.tables,
            bfv_owner: self.bfv_owner,
            bfv_public: self.bfv_public,
            pir: self.pir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_anchor() -> CheckpointAnchor {
        CheckpointAnchor {
            binding: CheckpointBinding {
                bundle_id: [1; 32],
                checkpoint_id: [2; 32],
                generation: 3,
            },
            catalog_digest: [0; 32],
            bfv_public_digest: [0; 32],
            pir_public_digest: [0; 32],
            geometry: Geometry::Rows256,
        }
    }
    #[test]
    fn tag_and_wrong_key_fail_before_body_secret_or_filesystem_decoding() {
        let wrapping = WrappingKey::generate().unwrap();
        let other = WrappingKey::generate().unwrap();
        let anchor = public_anchor();
        // Deliberately NOT a valid body. Correct AEAD reaches body-format rejection;
        // wrong key/tag must return Authentication before that or any file/public/secret decode.
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).unwrap();
        let header = outer_header(anchor.binding, 24, &nonce).unwrap();
        let mut body = Zeroizing::new(vec![0u8; 8]);
        XChaCha20Poly1305::new_from_slice(wrapping.0.as_ref())
            .unwrap()
            .encrypt_in_place(XNonce::from_slice(&nonce), &header, &mut *body)
            .unwrap();
        let mut wire = header.to_vec();
        wire.extend_from_slice(&body);
        assert!(matches!(
            open_checkpoint(&other, &anchor, &wire),
            Err(RecoveryError::Authentication)
        ));
        wire[OUTER_HEADER_BYTES] ^= 1;
        assert!(matches!(
            open_checkpoint(&wrapping, &anchor, &wire),
            Err(RecoveryError::Authentication)
        ));
    }
    #[test]
    fn bounds_truncation_trailing_and_external_checkpoint_mismatch_reject_before_aead() {
        let key = WrappingKey::generate().unwrap();
        let expected = public_anchor();
        for length in [0, OUTER_HEADER_BYTES, MAX_SEALED_BUNDLE_BYTES + 1] {
            assert!(matches!(
                open_checkpoint(&key, &expected, &vec![0; length]),
                Err(RecoveryError::Bounds)
            ));
        }
        let mut wire = outer_header(expected.binding, 16, &[0; 24])
            .unwrap()
            .to_vec();
        wire.extend_from_slice(&[0; 16]);
        let mut newer = expected.clone();
        newer.binding.generation += 1;
        assert!(matches!(
            open_checkpoint(&key, &newer, &wire),
            Err(RecoveryError::Checkpoint)
        ));
        wire.push(0);
        assert!(matches!(
            open_checkpoint(&key, &expected, &wire),
            Err(RecoveryError::Bounds)
        ));
    }
    #[test]
    fn filenames_cannot_escape_the_fixed_table_directory() {
        for invalid in ["", ".", "..", "../table", "C:table", "a/b", "a\\b", "a\0b"] {
            assert!(!leaf_name(invalid));
        }
        assert!(leaf_name("table-1999-data.bin"));
    }
}
