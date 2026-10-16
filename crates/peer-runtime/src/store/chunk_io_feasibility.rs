//! Opt-in PUBLIC NONSECRET storage-I/O candidate, not a production backend.
//! Generic CSTORE index bytes are not a semantically valid compact-query Table.
//! Every physical reread runs the existing complete two-image custody auditor.
use super::{Store, custody_limits};
use crate::{PageAddress, PageImage, RawBundle, StoreDeltaRequest, objects};
use compact_store::{EncryptedSnapshot, Layout, Owner};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

mod packed;

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_CHUNKS: usize = peer_transport::MAX_FRAME_BYTES / CHUNK_BYTES;
const MAX_CREATED_CHUNKS: usize = 3 * MAX_CHUNKS;

#[derive(Default, Serialize)]
struct Counts {
    explicit_file_opens: u64,
    read_calls: u64,
    read_bytes: u64,
    write_calls: u64,
    write_bytes: u64,
    successful_syncs: u64,
    successful_unlinks: u64,
    reused_payload_bytes: u64,
}
struct Metered<'a> {
    file: &'a mut File,
    counts: &'a mut Counts,
}
impl Read for Metered<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(bytes)?;
        self.counts.read_calls += 1;
        self.counts.read_bytes += count as u64;
        Ok(count)
    }
}
impl Write for Metered<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.file.write(bytes)?;
        self.counts.write_calls += 1;
        self.counts.write_bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn create(path: &Path, counts: &mut Counts) -> io::Result<File> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    counts.explicit_file_opens += 1;
    Ok(file)
}
fn sync(file: &File, counts: &mut Counts) -> io::Result<()> {
    file.sync_all()?;
    counts.successful_syncs += 1;
    Ok(())
}
fn create_bytes(path: &Path, bytes: &[u8], counts: &mut Counts) -> io::Result<File> {
    let mut file = create(path, counts)?;
    Metered {
        file: &mut file,
        counts,
    }
    .write_all(bytes)?;
    sync(&file, counts)?;
    Ok(file)
}
fn read_bytes(path: &Path, cap: usize, counts: &mut Counts) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    counts.explicit_file_opens += 1;
    let length = file.metadata()?.len();
    if length > cap as u64 {
        return Err(io::Error::other("candidate file exceeds its exact bound"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Metered {
        file: &mut file,
        counts,
    }
    .take(cap as u64 + 1)
    .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(io::Error::other("candidate file grew beyond its bound"));
    }
    Ok(bytes)
}
fn observe<T>(label: &str, action: impl FnOnce(&mut Counts) -> io::Result<T>) -> io::Result<T> {
    let mut counts = Counts::default();
    let started = Instant::now();
    let result = action(&mut counts);
    println!(
        "CHUNK_IO_SAMPLE {}",
        serde_json::json!({
            "label": label, "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
            "ok": result.is_ok(), "io": counts,
        })
    );
    result
}

// A request-local lineage only: it is constructed after a REAL complete reread.
// No audit result is cached for a later read, and no production type is exposed.
struct CanonicalObject {
    raw: RawBundle,
    bytes: Vec<u8>,
}
impl CanonicalObject {
    fn new(raw: RawBundle) -> Self {
        let bytes = objects::encode_disk(&raw).unwrap();
        assert!(
            objects::audit_disk_version(&bytes).unwrap() == raw.target_version().unwrap(),
            "prepared bytes must pass complete canonical custody auditing"
        );
        Self { raw, bytes }
    }
}
struct AuditedDisk(Vec<u8>);
fn audit(bytes: Vec<u8>, expected: &CanonicalObject) -> io::Result<AuditedDisk> {
    let version = objects::audit_disk_version(&bytes).map_err(io::Error::other)?;
    if version != expected.raw.target_version().map_err(io::Error::other)? {
        return Err(io::Error::other(
            "candidate returned a different object/head pair",
        ));
    }
    // Exact reconstruction is checked AFTER genuine canonical root validation.
    if bytes != expected.bytes {
        return Err(io::Error::other("candidate changed canonical object bytes"));
    }
    Ok(AuditedDisk(bytes))
}
fn write_single(path: &Path, raw: &RawBundle, counts: &mut Counts) -> io::Result<()> {
    let mut file = create(path, counts)?;
    {
        let mut output = BufWriter::with_capacity(
            16 * 1024,
            Metered {
                file: &mut file,
                counts,
            },
        );
        objects::write_disk(raw, &mut output)?;
        output.flush()?;
    }
    sync(&file, counts)
}
fn read_single(path: &Path, raw: &CanonicalObject, counts: &mut Counts) -> io::Result<AuditedDisk> {
    audit(
        read_bytes(path, peer_transport::MAX_FRAME_BYTES, counts)?,
        raw,
    )
}

#[derive(Clone)]
struct ChunkRef {
    id: [u8; 32],
    path: PathBuf,
}
struct Pool {
    path: PathBuf,
    next: usize,
}
impl Pool {
    fn put(&mut self, bytes: &[u8], counts: &mut Counts) -> io::Result<ChunkRef> {
        if self.next >= MAX_CREATED_CHUNKS || bytes.is_empty() || bytes.len() > CHUNK_BYTES {
            return Err(io::Error::other("bounded candidate chunk geometry"));
        }
        // Fixture-local counter IDs, not a proposed production addressing scheme.
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(self.next as u64).to_le_bytes());
        let path = self.path.join(format!("{:04}.chunk", self.next));
        self.next += 1;
        drop(create_bytes(&path, bytes, counts)?);
        Ok(ChunkRef { id, path })
    }
}
struct ChunkObject {
    canonical_bytes: usize,
    chunks: Vec<ChunkRef>,
    expected_manifest: Vec<u8>,
    manifest_path: PathBuf,
    // Retire writes ONLY this original creation handle, never a reopened path.
    manifest_creation_handle: File,
}
fn manifest(
    path: &Path,
    raw: &RawBundle,
    chunks: Vec<ChunkRef>,
    counts: &mut Counts,
) -> io::Result<ChunkObject> {
    let canonical_bytes = objects::disk_encoded_len(raw).map_err(io::Error::other)?;
    if chunks.len() != canonical_bytes.div_ceil(CHUNK_BYTES) || chunks.len() > MAX_CHUNKS {
        return Err(io::Error::other("bounded candidate manifest geometry"));
    }
    let ids: Vec<_> = chunks.iter().map(|chunk| chunk.id).collect();
    // Test metadata only. Reuse the pinned serializer, with no new accepting
    // parser/reopen contract: a read must match these owned expected bytes exactly.
    let expected_manifest = crate::wire::encode(&(
        canonical_bytes as u64,
        *raw.target_version().map_err(io::Error::other)?.object(),
        ids,
    ))?;
    let manifest_creation_handle = create_bytes(path, &expected_manifest, counts)?;
    Ok(ChunkObject {
        canonical_bytes,
        chunks,
        expected_manifest,
        manifest_path: path.to_owned(),
        manifest_creation_handle,
    })
}
struct ChunkWriter<'a> {
    pool: &'a mut Pool,
    base: Option<(&'a AuditedDisk, &'a ChunkObject)>,
    counts: &'a mut Counts,
    buffer: Vec<u8>,
    chunks: Vec<ChunkRef>,
    finished: bool,
}
impl ChunkWriter<'_> {
    fn emit(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let start = self.chunks.len() * CHUNK_BYTES;
        let end = start + self.buffer.len();
        let reused = self.base.and_then(|(audited, object)| {
            (audited.0.get(start..end) == Some(self.buffer.as_slice()))
                .then(|| object.chunks.get(self.chunks.len()).cloned())
                .flatten()
        });
        let chunk = if let Some(chunk) = reused {
            self.counts.reused_payload_bytes += self.buffer.len() as u64;
            chunk
        } else {
            self.pool.put(&self.buffer, self.counts)?
        };
        self.chunks.push(chunk);
        self.buffer.clear();
        Ok(())
    }
}
impl Write for ChunkWriter<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("candidate writer was already finished"));
        }
        let supplied = bytes.len();
        while !bytes.is_empty() {
            let take = bytes.len().min(CHUNK_BYTES - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == CHUNK_BYTES {
                self.emit()?;
            }
        }
        Ok(supplied)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.finished = true;
        Ok(())
    }
}
fn write_chunks(
    pool: &mut Pool,
    path: &Path,
    raw: &RawBundle,
    base: Option<(&AuditedDisk, &ChunkObject)>,
    counts: &mut Counts,
) -> io::Result<ChunkObject> {
    objects::disk_encoded_len(raw).map_err(io::Error::other)?;
    let mut writer = ChunkWriter {
        pool,
        base,
        counts,
        buffer: Vec::with_capacity(CHUNK_BYTES),
        chunks: Vec::new(),
        finished: false,
    };
    objects::write_disk(raw, &mut writer)?;
    writer.flush()?;
    let chunks = std::mem::take(&mut writer.chunks);
    drop(writer);
    manifest(path, raw, chunks, counts)
}
fn read_chunks(
    object: &ChunkObject,
    raw: &CanonicalObject,
    counts: &mut Counts,
) -> io::Result<AuditedDisk> {
    let actual_manifest = read_bytes(
        &object.manifest_path,
        object.expected_manifest.len(),
        counts,
    )?;
    if actual_manifest != object.expected_manifest {
        return Err(io::Error::other(
            "candidate manifest differs from its owned metadata",
        ));
    }
    let mut bytes = Vec::with_capacity(object.canonical_bytes);
    for chunk in &object.chunks {
        let expected = (object.canonical_bytes - bytes.len()).min(CHUNK_BYTES);
        let payload = read_bytes(&chunk.path, expected, counts)?;
        if payload.len() != expected {
            return Err(io::Error::other("missing candidate chunk bytes"));
        }
        bytes.extend_from_slice(&payload);
    }
    audit(bytes, raw)
}
fn retire_base(base: ChunkObject, keep: &[&ChunkObject], counts: &mut Counts) -> io::Result<usize> {
    let retained: BTreeSet<_> = keep
        .iter()
        .flat_map(|object| object.chunks.iter())
        .map(|chunk| chunk.path.clone())
        .collect();
    let mut file = base.manifest_creation_handle;
    file.seek(SeekFrom::Start(0))?;
    // An I/O ordering exercise, NOT a selected production retirement format or
    // crash/reopen proof. This inode was created by this fixture and retained.
    Metered {
        file: &mut file,
        counts,
    }
    .write_all(b"RETIRED\n")?;
    sync(&file, counts)?;
    drop(file);
    fs::remove_file(&base.manifest_path)?;
    counts.successful_unlinks += 1;
    let mut removed_chunks = 0;
    for chunk in base.chunks {
        if !retained.contains(&chunk.path) {
            fs::remove_file(chunk.path)?;
            counts.successful_unlinks += 1;
            removed_chunks += 1;
        }
    }
    Ok(removed_chunks)
}

struct Fixture {
    owner: Owner,
    base: CanonicalObject,
    target: CanonicalObject,
    plaintext: Vec<u8>,
}
fn bundle(data: &EncryptedSnapshot, index: &EncryptedSnapshot, nonce: u8) -> RawBundle {
    RawBundle {
        version: 2,
        nonce: [nonce; 32],
        data_head: data.commitment().encode().to_vec(),
        index_head: index.commitment().encode().to_vec(),
        data: data.encode(),
        index: index.encode(),
    }
}
fn fixture(root: &Path) -> Fixture {
    // Same public geometry as delta::tests::actual_million_row_images..., not
    // a semantic private-index Table. No FHE result is computed or claimed here.
    let owner = Owner::generate([67; 16]).unwrap();
    let mut plaintext = [7, 1, 0].repeat(1_000_000);
    plaintext[2_999_997..].copy_from_slice(&[42, 1, 0]);
    let data = owner
        .seal(
            Layout {
                schema: [3; 16],
                row_width: 3,
                rows_per_page: 256,
                row_count: 1_000_000,
            },
            &plaintext,
            custody_limits(),
        )
        .unwrap();
    let mut index_plaintext = vec![0; 34_017_824];
    index_plaintext[..112].copy_from_slice(&data.commitment().encode());
    let index = owner
        .seal(
            Layout {
                schema: [4; 16],
                row_width: 1,
                rows_per_page: 4096,
                row_count: 34_017_824,
            },
            &index_plaintext,
            custody_limits(),
        )
        .unwrap();
    assert_eq!(
        (data.encoded_len(), index.encoded_len()),
        (3_187_648, 34_416_624)
    );
    let base = bundle(&data, &index, 31);
    let mut next_data = data.clone();
    let mut next_index = index.clone();
    plaintext[2_999_997..].copy_from_slice(&[42, 2, 0]);
    let last = (data.commitment().layout().page_count().unwrap() - 1) as u64;
    owner
        .replace_page(
            &mut next_data,
            data.commitment(),
            last,
            &plaintext[last as usize * 768..],
            custody_limits(),
        )
        .unwrap();
    index_plaintext[..112].copy_from_slice(&next_data.commitment().encode());
    owner
        .replace_page(
            &mut next_index,
            index.commitment(),
            0,
            &index_plaintext[..4096],
            custody_limits(),
        )
        .unwrap();
    let expected = bundle(&next_data, &next_index, 32);
    let delta = StoreDeltaRequest::new(
        *base.target_version().unwrap().object(),
        data.commitment(),
        index.commitment(),
        &expected.target_version().unwrap(),
        &[
            (
                PageAddress {
                    image: PageImage::Data,
                    index: last,
                },
                next_data.lookup(last, custody_limits()).unwrap(),
            ),
            (
                PageAddress {
                    image: PageImage::Index,
                    index: 0,
                },
                next_index.lookup(0, custody_limits()).unwrap(),
            ),
        ],
    )
    .unwrap();
    let mut store = Store::open(&root.join("actual-delta"), 128 * 1024 * 1024).unwrap();
    store.put(base.clone()).unwrap();
    let stored = store.put_delta(delta).unwrap();
    let target = store.get(&stored.id).unwrap();
    assert_eq!(
        target, expected,
        "actual StoreDelta must reconstruct the exact target"
    );
    assert_eq!(
        store.get(base.target_version().unwrap().object()).unwrap(),
        base
    );
    Fixture {
        owner,
        base: CanonicalObject::new(base),
        target: CanonicalObject::new(target),
        plaintext,
    }
}
fn assert_owner_plaintext(fixture: &Fixture, audited: &AuditedDisk) {
    let checked = objects::audit_disk_images(&audited.0).unwrap();
    let (_, data, index) = checked.into_images();
    let head = data.commitment();
    for page in 0..head.layout().page_count().unwrap() {
        let verified = data
            .lookup(page as u64, custody_limits())
            .unwrap()
            .verify(head, page as u64, custody_limits())
            .unwrap();
        let plain = fixture.owner.decrypt(&verified).unwrap();
        let start = page * 768;
        assert_eq!(
            plain.as_bytes(),
            &fixture.plaintext[start..start + plain.as_bytes().len()]
        );
    }
    let verified = index
        .lookup(0, custody_limits())
        .unwrap()
        .verify(index.commitment(), 0, custody_limits())
        .unwrap();
    assert_eq!(
        &fixture.owner.decrypt(&verified).unwrap().as_bytes()[..112],
        &head.encode()
    );
}

#[test]
#[ignore = "PUBLIC NONSECRET opt-in real-filesystem I/O candidate; not SQL latency or production storage"]
fn million_row_chunk_io_reconstructs_and_audits_after_exact_delta_reuse_and_base_gc() {
    assert_eq!(
        std::env::var("DCS_CHUNK_IO_FEASIBILITY").as_deref(),
        Ok("1"),
        "explicit feasibility guard required"
    );
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dcs-public-chunk-io-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    println!(
        "CHUNK_IO_RUN {}",
        serde_json::json!({ "directory": root, "public_nonsecret": true,
        "scope": "generic CSTORE/actual StoreDelta; not SQL/FHE performance", "chunk_bytes": CHUNK_BYTES })
    );
    let fixture = fixture(&root);
    let payload_root = root.join("chunks");
    fs::create_dir(&payload_root).unwrap();
    let mut pool = Pool {
        path: payload_root,
        next: 0,
    };

    // Initial Full and a complete Copy use the same unchanged canonical writer.
    let baseline = root.join("single-base.object");
    observe("single-initial-write", |io| {
        write_single(&baseline, &fixture.base.raw, io)
    })
    .unwrap();
    observe("single-initial-read-audit", |io| {
        read_single(&baseline, &fixture.base, io)
    })
    .unwrap();
    let base = observe("chunk-initial-write", |io| {
        write_chunks(
            &mut pool,
            &root.join("base.manifest"),
            &fixture.base.raw,
            None,
            io,
        )
    })
    .unwrap();
    assert_eq!(base.chunks.len(), 574);
    let copy_path = root.join("single-copy.object");
    observe("single-copy-write", |io| {
        write_single(&copy_path, &fixture.target.raw, io)
    })
    .unwrap();
    observe("single-copy-read-audit", |io| {
        read_single(&copy_path, &fixture.target, io)
    })
    .unwrap();
    let copy = observe("chunk-copy-write", |io| {
        write_chunks(
            &mut pool,
            &root.join("copy.manifest"),
            &fixture.target.raw,
            None,
            io,
        )
    })
    .unwrap();
    observe("chunk-copy-read-audit", |io| {
        read_chunks(&copy, &fixture.target, io)
    })
    .unwrap();

    // The only reuse source is this fresh physical complete read and full audit.
    let audited_base = observe("chunk-base-read-audit-before-delta", |io| {
        read_chunks(&base, &fixture.base, io)
    })
    .unwrap();
    let target_path = root.join("single-delta-target.object");
    observe("single-delta-full-write", |io| {
        write_single(&target_path, &fixture.target.raw, io)
    })
    .unwrap();
    observe("single-delta-read-audit", |io| {
        read_single(&target_path, &fixture.target, io)
    })
    .unwrap();
    let before = pool.next;
    let target = observe("chunk-delta-write", |io| {
        write_chunks(
            &mut pool,
            &root.join("target.manifest"),
            &fixture.target.raw,
            Some((&audited_base, &base)),
            io,
        )
    })
    .unwrap();
    assert_eq!(
        pool.next - before,
        2,
        "actual target changes canonical chunks 0 and 48"
    );
    let changed: Vec<_> = target
        .chunks
        .iter()
        .zip(&base.chunks)
        .enumerate()
        .filter_map(|(index, (next, old))| (next.id != old.id).then_some(index))
        .collect();
    assert_eq!(changed, [0, 48]);
    drop(audited_base);
    let audited_target = observe("chunk-delta-read-audit", |io| {
        read_chunks(&target, &fixture.target, io)
    })
    .unwrap();
    assert_owner_plaintext(&fixture, &audited_target);

    // Corrupt a NEW private copy of the final index-tail chunk, never reopen an
    // existing file for writes. Genuine complete auditing must reject that image.
    let tail = &audited_target.0[573 * CHUNK_BYTES..];
    let mut bad_tail = tail.to_vec();
    *bad_tail.last_mut().unwrap() ^= 1;
    let mut corruption_io = Counts::default();
    let mut bad_refs = target.chunks.clone();
    *bad_refs.last_mut().unwrap() = pool.put(&bad_tail, &mut corruption_io).unwrap();
    let bad = manifest(
        &root.join("corrupt.manifest"),
        &fixture.target.raw,
        bad_refs,
        &mut corruption_io,
    )
    .unwrap();
    println!(
        "CHUNK_IO_PREPARATION {}",
        serde_json::json!({
            "label": "fresh-corrupted-tail-and-manifest", "io": corruption_io,
        })
    );
    assert!(
        observe("corrupt-unrequested-index-tail-read-audit", |io| {
            read_chunks(&bad, &fixture.target, io)
        })
        .is_err()
    );

    // All writes here still use the creation handle from this fresh owned run.
    let base_manifest = base.manifest_path.clone();
    assert_eq!(
        observe("owned-handle-retire-and-gc", |io| retire_base(
            base,
            &[&target, &copy, &bad],
            io
        ))
        .unwrap(),
        2
    );
    assert!(!base_manifest.exists());
    let after_gc = observe("target-full-read-audit-after-base-gc", |io| {
        read_chunks(&target, &fixture.target, io)
    })
    .unwrap();
    assert_owner_plaintext(&fixture, &after_gc);
    let stored_bytes: u64 = fs::read_dir(&root)
        .unwrap()
        .filter_map(|entry| {
            let meta = entry.unwrap().metadata().unwrap();
            meta.is_file().then_some(meta.len())
        })
        .sum();
    assert_eq!(pool.next, 1151);
    assert_eq!(fs::read_dir(&pool.path).unwrap().count(), pool.next - 2);
    let chunk_bytes: u64 = fs::read_dir(&pool.path)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    let source_store_bytes = fs::read_dir(root.join("actual-delta"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum::<u64>();
    assert!(stored_bytes + chunk_bytes + source_store_bytes < 512 * 1024 * 1024);
    println!(
        "CHUNK_IO_RESULT {}",
        serde_json::json!({
            "directory": root, "canonical_object_bytes": after_gc.0.len(), "references": target.chunks.len(),
            "created_chunk_files": pool.next, "root_file_eof_bytes": stored_bytes, "chunk_file_eof_bytes": chunk_bytes,
            "source_store_eof_bytes": source_store_bytes,
            "all_data_pages_owner_decrypted": true, "artifacts_retained": true,
            "not_measured": ["SQL latency", "peak RAM", "NTFS allocated metadata", "production crash/reopen or hostile namespace races"],
        })
    );
}
