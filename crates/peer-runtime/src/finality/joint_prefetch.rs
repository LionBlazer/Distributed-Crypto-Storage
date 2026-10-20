//! Owner authorization and immutable byte prefetch, never computation admission.
use super::{busy, error, invalid, owner::Snapshot};
use super::{proof_application::Installed, proof_client::Client};
use protocol_storage::BlobId;
use registry200_finality::CandidateBlock;
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// Untrusted fixed-role selector. The signed Body/catalog determines its ID and
/// byte cap; a selector never authorizes a write or marks a proof verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofBlobSelector {
    kind: u8,
    role: u16,
    ordinal: u16,
}
impl ProofBlobSelector {
    pub fn manifest(ordinal: u16) -> io::Result<Self> {
        if ordinal > 2 {
            return Err(invalid());
        }
        Ok(Self {
            kind: 0,
            role: 0,
            ordinal,
        })
    }
    pub fn catalog(role: u16, ordinal: u16) -> io::Result<Self> {
        if !(1..=11).contains(&role) {
            return Err(invalid());
        }
        Ok(Self {
            kind: 1,
            role,
            ordinal,
        })
    }
    pub(super) fn encode(self) -> [u8; 8] {
        let mut b = [0; 8];
        b[0] = self.kind;
        b[2..4].copy_from_slice(&self.role.to_le_bytes());
        b[4..6].copy_from_slice(&self.ordinal.to_le_bytes());
        b
    }
    pub(super) fn decode(b: &[u8]) -> io::Result<Self> {
        if b.len() != 8 || b[1] != 0 || b[6..] != [0; 2] {
            return Err(invalid());
        }
        let r = u16::from_le_bytes(b[2..4].try_into().map_err(|_| invalid())?);
        let n = u16::from_le_bytes(b[4..6].try_into().map_err(|_| invalid())?);
        match b[0] {
            0 if r == 0 => Self::manifest(n),
            1 => Self::catalog(r, n),
            _ => Err(invalid()),
        }
    }
}

// One download/receive and one export buffer, each <=32MiB. These are byte
// reservations, NOT compute gates, storage budgets or proof-authority flags.
#[derive(Clone)]
pub(super) struct BlobGate(Arc<[AtomicBool; 2]>);
pub(super) struct BlobLease {
    inner: Arc<[AtomicBool; 2]>,
    index: usize,
}
impl BlobGate {
    pub fn new() -> Self {
        Self(Arc::new([AtomicBool::new(false), AtomicBool::new(false)]))
    }
    fn acquire(&self, index: usize) -> io::Result<BlobLease> {
        self.0[index]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| busy())?;
        Ok(BlobLease {
            inner: self.0.clone(),
            index,
        })
    }
    pub fn download(&self) -> io::Result<BlobLease> {
        self.acquire(0)
    }
    pub fn export(&self) -> io::Result<BlobLease> {
        self.acquire(1)
    }
}
impl Drop for BlobLease {
    fn drop(&mut self) {
        self.inner[self.index].store(false, Ordering::Release)
    }
}

pub(super) fn authorized_reference(
    application: &Installed,
    block: &CandidateBlock,
    parent: Option<[u8; 32]>,
    selector: ProofBlobSelector,
) -> io::Result<(BlobId, usize)> {
    let references = application.references(block, parent)?;
    if selector.kind == 0 {
        return references
            .iter()
            .find(|r| r.ordinal == usize::from(selector.ordinal))
            .map(|r| (r.id, r.cap))
            .ok_or_else(invalid);
    }
    let catalog = references.iter().find(|r| r.catalog).ok_or_else(invalid)?;
    let id = bfv_product_evidence::CatalogId::from_blob(catalog.id).map_err(error)?;
    let claim = application.catalog(id)?;
    application.require_setup(&claim)?;
    claim
        .references()
        .find(|r| r.role() == selector.role && r.ordinal() == selector.ordinal)
        .map(|r| (r.blob_id(), r.byte_cap()))
        .ok_or_else(invalid)
}
pub(super) fn require_blob(id: BlobId, cap: usize, bytes: &[u8]) -> io::Result<()> {
    if cap == 0
        || cap > protocol_storage::MAX_BLOB_BYTES as usize
        || id.bytes() > cap as u64
        || bytes.len() as u64 != id.bytes()
    {
        return Err(invalid());
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if &digest != id.sha256() {
        return Err(invalid());
    }
    Ok(())
}
fn ensure(
    client: Option<&Client>,
    application: &Installed,
    gate: &BlobGate,
    id: BlobId,
    cap: usize,
    expires: Instant,
) -> io::Result<()> {
    if Instant::now() >= expires {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Joint prefetch expired",
        ));
    }
    let _lease = gate.download()?;
    match application.read(id, cap) {
        Ok(bytes) => {
            require_blob(id, cap, &bytes)?;
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let client = client
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Joint premise is not retained"))?;
    let bytes = client.fetch_blob(id, cap, expires)?;
    require_blob(id, cap, &bytes)?;
    if application.retain(&bytes)? != id {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn prefetch(
    client: &Client,
    application: &Installed,
    gate: &BlobGate,
    block: &CandidateBlock,
    snapshot: Snapshot,
    expires: Instant,
) -> io::Result<()> {
    prefetch_from(Some(client), application, gate, block, snapshot, expires)
}
pub(super) fn prefetch_local(
    application: &Installed,
    gate: &BlobGate,
    block: &CandidateBlock,
    snapshot: Snapshot,
    expires: Instant,
) -> io::Result<()> {
    prefetch_from(None, application, gate, block, snapshot, expires)
}
fn prefetch_from(
    client: Option<&Client>,
    application: &Installed,
    gate: &BlobGate,
    block: &CandidateBlock,
    snapshot: Snapshot,
    expires: Instant,
) -> io::Result<()> {
    let genesis = application.genesis();
    if block.header().genesis != genesis.id().map_err(error)?
        || block.header().body_hash != version_journal::hash(block.body())
        || block.header().parent != snapshot.parent
    {
        return Err(invalid());
    }
    // Empty is authenticated by the actual Journal/Work/QC path. It cannot
    // manufacture an own-operation receipt or skip that independent admission.
    if matches!(
        version_journal::Body::decode(block.body(), &genesis.profile).map_err(error)?,
        version_journal::Body::Empty
    ) {
        return Ok(());
    }
    for reference in application.references(block, Some(snapshot.parent))? {
        ensure(
            client,
            application,
            gate,
            reference.id,
            reference.cap,
            expires,
        )?;
        if reference.catalog {
            let claim = application.catalog(
                bfv_product_evidence::CatalogId::from_blob(reference.id).map_err(error)?,
            )?;
            application.require_setup(&claim)?;
            for part in claim.references() {
                ensure(
                    client,
                    application,
                    gate,
                    part.blob_id(),
                    part.byte_cap(),
                    expires,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selectors_are_canonical_and_blob_identity_precedes_publication() {
        for s in [
            ProofBlobSelector::manifest(0).unwrap(),
            ProofBlobSelector::manifest(2).unwrap(),
            ProofBlobSelector::catalog(11, 117).unwrap(),
        ] {
            assert_eq!(ProofBlobSelector::decode(&s.encode()).unwrap(), s);
            let mut b = s.encode();
            b[7] = 1;
            assert!(ProofBlobSelector::decode(&b).is_err());
        }
        assert!(ProofBlobSelector::manifest(3).is_err());
        assert!(ProofBlobSelector::catalog(0, 0).is_err());
        assert!(ProofBlobSelector::decode(&[0; 7]).is_err());
        let bytes = b"public bytes";
        let id = BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap();
        require_blob(id, bytes.len(), bytes).unwrap();
        assert!(require_blob(id, 0, bytes).is_err());
        assert!(require_blob(id, bytes.len() - 1, bytes).is_err());
        assert!(require_blob(id, bytes.len(), b"public byteS").is_err());
    }
    #[test]
    fn download_and_export_are_distinct_bounded_leases() {
        let gate = BlobGate::new();
        let download = gate.download().unwrap();
        assert!(gate.download().is_err());
        let export = gate.export().unwrap();
        assert!(gate.export().is_err());
        drop(download);
        gate.download().unwrap();
        drop(export);
        gate.export().unwrap();
    }
}
