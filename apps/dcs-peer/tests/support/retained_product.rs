//! Owning actual-proof replay challenges for the real OS-peer positive scenario.
//! All retained bytes/pins are public. Expected plaintext remains in the caller's
//! test oracle; it is never supplied to the peer or retained verifier.
use bfv_mul_relin_proof::{InputEvidence, Provenance};
use bfv_product_evidence::{CatalogId, ProductStore};
use bfv_query_core::PublicSetup;
use peer_runtime::{RemotePeer, RequestControl};
use protocol_storage::{BlobId, EvidenceStore, MAX_BLOB_BYTES, ParticipantQuota, StoreLimits};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

const NAMESPACE: [u8; 32] = [0x91; 32];
const CAPACITY: u64 = 10_000_000_000;

pub(super) struct Pins {
    object: [u8; 32],
    setup: PublicSetup,
    claim: Vec<u8>,
    request: Vec<u8>,
}
impl Pins {
    pub fn new(object: [u8; 32], setup: PublicSetup, p: &Provenance, request: &[u8]) -> Self {
        // Move the caller's original public setup rather than adding another
        // complete setup copy while the live product is being verified.
        Self {
            object,
            setup,
            claim: p.encode_claim().unwrap(),
            request: request.to_vec(),
        }
    }
    fn provenance(&self) -> Provenance {
        // This is the previously copied LOCAL public pin, not a decoded catalog
        // or untrusted peer-selected anchor. Actual proofs are always replayed.
        Provenance::decode_claim(self.setup.clone(), &self.claim).unwrap()
    }
}
pub(super) struct OwnedDepot(PathBuf);
impl OwnedDepot {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..128 {
            let path = parent.join(format!(
                "dcs-retained-FHE-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path.canonicalize().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("owned evidence directory: {e}"),
            }
        }
        panic!("bounded owned directory allocation exhausted")
    }
    fn root(&self) -> PathBuf {
        self.0.join("participant")
    }
    pub fn create(&self) -> ParticipantQuota {
        ParticipantQuota::create_new(self.root(), NAMESPACE, CAPACITY).unwrap()
    }
    fn open(&self) -> ParticipantQuota {
        ParticipantQuota::open_existing(self.root(), NAMESPACE, CAPACITY).unwrap()
    }
    pub fn replay_and_challenge(
        self,
        pins: Pins,
        catalog: CatalogId,
        identity: [u8; 64],
        response: &[u8],
        output: &[u8],
    ) {
        let started = Instant::now();
        let q = self.open();
        let mut store = ProductStore::open(q.depot_budget()).unwrap();
        let checked = store
            .replay(catalog, pins.object, pins.provenance(), &pins.request)
            .unwrap();
        assert_eq!(checked.product().identity(), identity);
        assert_eq!(checked.product().output_ciphertext(), output);
        assert_eq!(checked.encrypted_response(), response);
        assert!(checked.product().output_sdk_security_bits() >= 144.);
        drop(checked);
        let replay_ms = started.elapsed().as_secs_f64() * 1000.;
        let mut foreign_object = pins.object;
        foreign_object[0] ^= 1;
        assert!(matches!(
            store.replay(catalog, foreign_object, pins.provenance(), &pins.request),
            Err(bfv_product_evidence::Error::Association)
        ));
        assert!(matches!(
            store.replay(
                catalog,
                pins.object,
                pins.provenance(),
                &pins.request[..pins.request.len() - 1]
            ),
            Err(bfv_product_evidence::Error::Association)
        ));
        drop(store);
        let original = read_blob(&q, catalog.blob_id());
        // Retag the CATALOG entries while preserving each target role/ordinal.
        // Every inner child/record remains a genuine original proof. Parsing
        // succeeds; the existing cryptographic/statement verifier must reject.
        let child0 = entry(&original, 7, 0);
        let child1 = entry(&original, 7, 1);
        let mut swapped_children = original.clone();
        swapped_children[child0 + 4..child0 + 44]
            .copy_from_slice(&original[child1 + 4..child1 + 44]);
        swapped_children[child1 + 4..child1 + 44]
            .copy_from_slice(&original[child0 + 4..child0 + 44]);
        let swapped_children = put_catalog(&q, &swapped_children);
        let mut store = ProductStore::open(q.depot_budget()).unwrap();
        assert!(
            matches!(
                store.replay(
                    swapped_children,
                    pins.object,
                    pins.provenance(),
                    &pins.request
                ),
                Err(bfv_product_evidence::Error::Proof(
                    bfv_mul_relin_proof::Error::InputVerification
                ))
            ),
            "canonical repaired catalog must reach actual input verification"
        );
        drop(store);
        let first = entry(&original, 11, 0);
        let second = entry(&original, 11, 1);
        let mut duplicate = original.clone();
        duplicate[second + 4..second + 44].copy_from_slice(&original[first + 4..first + 44]);
        let duplicate = put_catalog(&q, &duplicate);
        let mut store = ProductStore::open(q.depot_budget()).unwrap();
        assert!(
            matches!(
                store.replay(duplicate, pins.object, pins.provenance(), &pins.request),
                Err(bfv_product_evidence::Error::Proof(
                    bfv_mul_relin_proof::Error::Statement
                ))
            ),
            "canonical duplicated reference must reach actual ordered record verification"
        );
        drop(store);
        let mut omitted = original[..original.len() - 44].to_vec();
        let count = u16::from_le_bytes(omitted[240..242].try_into().unwrap()) - 1;
        omitted[240..242].copy_from_slice(&count.to_le_bytes());
        let omitted = put_catalog(&q, &omitted);
        let mut trailing = original.clone();
        trailing.push(0);
        let trailing_id = CatalogId::from_blob(put_blob(&q, &trailing));
        let trailing_id = if trailing.len() > bfv_product_evidence::MAX_CATALOG_BYTES {
            assert!(matches!(
                trailing_id,
                Err(bfv_product_evidence::Error::ResourceLimit)
            ));
            None // Exact two-chunk maximum rejects at the outer identity cap.
        } else {
            Some(trailing_id.expect("one-chunk trailing catalog fits the outer cap"))
        };
        let mut store = ProductStore::open(q.depot_budget()).unwrap();
        for id in core::iter::once(omitted).chain(trailing_id) {
            assert!(matches!(
                store.replay(id, pins.object, pins.provenance(), &pins.request),
                Err(bfv_product_evidence::Error::Encoding)
            ));
        }
        drop(store);
        let claims = entry_id(&original, entry(&original, 10, 0));
        let claims_bytes = read_blob(&q, claims);
        let claims_path = blob_path(&q.depot_directory(), claims);
        drop(q);
        fs::remove_file(&claims_path).unwrap(); // Actual missing immutable ref, not a boolean fault.
        let q = self.open();
        let mut store = ProductStore::open(q.depot_budget()).unwrap();
        let missing = store
            .replay(catalog, pins.object, pins.provenance(), &pins.request)
            .err()
            .expect("missing actual graph claims must reject");
        assert!(
            matches!(missing, bfv_product_evidence::Error::Storage(protocol_storage::Error::Io(ref e))
            if e.kind() == std::io::ErrorKind::NotFound)
        );
        drop(store);
        assert_eq!(put_blob(&q, &claims_bytes), claims); // Explicit test-owned repair through CAS.
        let original_used = q.usage().unwrap().total_bytes();
        drop(q);
        // Corruption after a successful fresh replay must be detected on another
        // actual reopen; no saved catalog/QC/verified bit bypasses hashing.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&claims_path)
            .unwrap();
        file.write_all(&[claims_bytes[0] ^ 1]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(
            matches!(
                ParticipantQuota::open_existing(self.root(), NAMESPACE, CAPACITY),
                Err(protocol_storage::Error::Identity)
            ),
            "fresh complete inventory must reject changed bytes"
        );
        println!(
            "{}",
            serde_json::json!({"case":"retained-public-product-fresh-replay","catalog_bytes":catalog.blob_id().bytes(),
            "input_proofs":16,"output_records":118,"owner_and_producer_dropped":true,"peer_stopped":true,
            "fresh_replay_ms":replay_ms,"retained_logical_bytes_before_corruption":original_used,
            "repaired_children_and_record_refs_rejected":true,"missing_corrupt_trailing_refs_rejected":true,
            "sql_grant":false,"fresh_finalized_head":false,"whole128_claim":false})
        );
    }
}
impl Drop for OwnedDepot {
    fn drop(&mut self) {
        let root = self.root();
        for path in [
            root.join("control"),
            root.join("depot"),
            root.join("custody"),
            root,
            self.0.clone(),
        ] {
            if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_dir())
                && path.canonicalize().ok().as_ref() == Some(&path)
            {
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
                let _ = fs::remove_dir(path);
            }
        }
    }
}
pub(super) fn cancel_before_io_keeps_only_existing_public_bytes(
    remote: &RemotePeer,
    pins: &Pins,
    inputs: &InputEvidence<'_>,
    store: &mut ProductStore,
    quota: &ParticipantQuota,
) {
    let control = RequestControl::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    let remote = remote
        .clone()
        .with_control(control.clone())
        .with_activity(Arc::new(move |event| observed.lock().unwrap().push(event)));
    let scope = control.begin().unwrap();
    assert!(control.cancel());
    let before = quota.usage().unwrap();
    let error = remote
        .prove_private_product_recorded(
            pins.object,
            pins.provenance(),
            &pins.request,
            inputs,
            store,
        )
        .err()
        .expect("cancelled recording returns no checked product/catalog");
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(quota.usage().unwrap(), before);
    drop(scope);
}
fn read_blob(q: &ParticipantQuota, id: BlobId) -> Vec<u8> {
    let mut store = EvidenceStore::open_depot(
        q.depot_budget(),
        StoreLimits::new(MAX_BLOB_BYTES, 4094).unwrap(),
    )
    .unwrap();
    let mut reader = store.reader(id).unwrap();
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    reader.finish().unwrap();
    out
}
fn put_blob(q: &ParticipantQuota, bytes: &[u8]) -> BlobId {
    let id = BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap();
    let mut store = EvidenceStore::open_depot(
        q.depot_budget(),
        StoreLimits::new(MAX_BLOB_BYTES, 4094).unwrap(),
    )
    .unwrap();
    let mut stage = store.stage(id).unwrap();
    stage.write_chunk(bytes).unwrap();
    stage.finish().unwrap()
}
fn put_catalog(q: &ParticipantQuota, bytes: &[u8]) -> CatalogId {
    CatalogId::from_blob(put_blob(q, bytes)).unwrap()
}
// Deliberate untrusted-wire mutations against the documented fixed catalog
// grammar. These helpers do not parse proofs or supply expected FHE answers.
fn entry(bytes: &[u8], role: u16, ordinal: u16) -> usize {
    assert_eq!(&bytes[..8], b"DCSFPE01");
    bytes[256..]
        .as_chunks::<44>()
        .0
        .iter()
        .enumerate()
        .find_map(|(i, e)| {
            (e[..2] == role.to_le_bytes() && e[2..4] == ordinal.to_le_bytes())
                .then_some(256 + i * 44)
        })
        .unwrap()
}
fn entry_id(bytes: &[u8], at: usize) -> BlobId {
    BlobId::new(
        bytes[at + 12..at + 44].try_into().unwrap(),
        u64::from_le_bytes(bytes[at + 4..at + 12].try_into().unwrap()),
    )
    .unwrap()
}
fn blob_path(directory: &Path, id: BlobId) -> PathBuf {
    let hash: String = id.sha256().iter().map(|b| format!("{b:02x}")).collect();
    directory.join(format!("{hash}-{:016x}.blob", id.bytes()))
}
