//! Owned, append-only container candidate. No persistent parser or accepting API.
//! All successful reads physically reconstruct and audit the complete CSTORE pair.
use super::*;

const MAX_POOL_BYTES: u64 = 4 * peer_transport::MAX_FRAME_BYTES as u64;
const BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Serialize)]
struct Extent {
    offset: u64,
    length: u64,
}

struct Container {
    path: PathBuf,
    creation_handle: File,
    end: u64,
}

impl Container {
    fn create(path: &Path, counts: &mut Counts) -> io::Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            creation_handle: create(path, counts)?,
            end: 0,
        })
    }
}

struct Version {
    container: PathBuf,
    canonical_bytes: usize,
    extents: Vec<Extent>,
    manifest_offset: u64,
    expected_manifest: Vec<u8>,
}

// One-use reuse permission belongs to this physical reread and exact Version.
// It cannot be cloned, constructed through a public API or cached for later reads.
struct FreshBase<'a> {
    audited: AuditedDisk,
    version: &'a Version,
}

struct Writer<'a, W> {
    output: W,
    base: Option<FreshBase<'a>>,
    buffer: Vec<u8>,
    extents: Vec<Extent>,
    end: u64,
    reused: u64,
    finished: bool,
}

impl<W: Write> Writer<'_, W> {
    fn emit(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if self.extents.len() >= MAX_CHUNKS {
            return Err(io::Error::other("container extent limit"));
        }
        let start = self.extents.len() * CHUNK_BYTES;
        let end = start + self.buffer.len();
        let reused = self.base.as_ref().and_then(|base| {
            (base.audited.0.get(start..end) == Some(self.buffer.as_slice()))
                .then(|| base.version.extents.get(self.extents.len()).copied())
                .flatten()
        });
        let extent = if let Some(extent) = reused {
            if extent.length != self.buffer.len() as u64 {
                return Err(io::Error::other("reused extent has another length"));
            }
            self.reused += extent.length;
            extent
        } else {
            let next = self
                .end
                .checked_add(self.buffer.len() as u64)
                .filter(|next| *next <= MAX_POOL_BYTES)
                .ok_or_else(|| io::Error::other("container append bound"))?;
            self.output.write_all(&self.buffer)?;
            let extent = Extent {
                offset: self.end,
                length: self.buffer.len() as u64,
            };
            self.end = next;
            extent
        };
        self.extents.push(extent);
        self.buffer.clear();
        Ok(())
    }
}

impl<W: Write> Write for Writer<'_, W> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("container writer already finished"));
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
        self.output.flush()
    }
}

fn manifest_bytes(raw: &RawBundle, extents: &[Extent]) -> io::Result<Vec<u8>> {
    let canonical_bytes = objects::disk_encoded_len(raw).map_err(io::Error::other)?;
    if extents.len() != canonical_bytes.div_ceil(CHUNK_BYTES) || extents.len() > MAX_CHUNKS {
        return Err(io::Error::other("container manifest geometry"));
    }
    // This is owned test metadata, not an authenticated persistent addressing API.
    crate::wire::encode(&(
        b"DCS/IO/PACKED/v1",
        canonical_bytes as u64,
        *raw.target_version().map_err(io::Error::other)?.object(),
        extents,
    ))
}

fn finish_version(
    container: &mut Container,
    raw: &RawBundle,
    extents: Vec<Extent>,
    counts: &mut Counts,
) -> io::Result<Version> {
    let expected_manifest = manifest_bytes(raw, &extents)?;
    let manifest_offset = container.end;
    let end = manifest_offset
        .checked_add(expected_manifest.len() as u64)
        .filter(|end| *end <= MAX_POOL_BYTES)
        .ok_or_else(|| io::Error::other("container manifest exceeds bound"))?;
    container
        .creation_handle
        .seek(SeekFrom::Start(manifest_offset))?;
    Metered {
        file: &mut container.creation_handle,
        counts,
    }
    .write_all(&expected_manifest)?;
    sync(&container.creation_handle, counts)?;
    container.end = end;
    Ok(Version {
        container: container.path.clone(),
        canonical_bytes: objects::disk_encoded_len(raw).map_err(io::Error::other)?,
        extents,
        manifest_offset,
        expected_manifest,
    })
}

fn write_version(
    container: &mut Container,
    raw: &RawBundle,
    base: Option<FreshBase<'_>>,
    counts: &mut Counts,
) -> io::Result<Version> {
    let canonical_bytes = objects::disk_encoded_len(raw).map_err(io::Error::other)?;
    if base.as_ref().is_some_and(|base| {
        base.version.container != container.path || base.version.canonical_bytes != canonical_bytes
    }) {
        return Err(io::Error::other(
            "reuse source belongs to another container or geometry",
        ));
    }
    if container.creation_handle.metadata()?.len() != container.end {
        return Err(io::Error::other("container length changed before append"));
    }
    container
        .creation_handle
        .seek(SeekFrom::Start(container.end))?;
    let output = BufWriter::with_capacity(
        BUFFER_BYTES,
        Metered {
            file: &mut container.creation_handle,
            counts,
        },
    );
    let mut writer = Writer {
        output,
        base,
        buffer: Vec::with_capacity(CHUNK_BYTES),
        extents: Vec::new(),
        end: container.end,
        reused: 0,
        finished: false,
    };
    objects::write_disk(raw, &mut writer)?;
    writer.flush()?;
    let payload_end = writer.end;
    let reused = writer.reused;
    let extents = std::mem::take(&mut writer.extents);
    drop(writer);
    container.end = payload_end;
    let version = finish_version(container, raw, extents, counts)?;
    counts.reused_payload_bytes += reused;
    Ok(version)
}

fn read_version(
    container: &Container,
    version: &Version,
    expected: &CanonicalObject,
    counts: &mut Counts,
) -> io::Result<AuditedDisk> {
    if version.container != container.path
        || version.canonical_bytes > peer_transport::MAX_FRAME_BYTES
        || version.extents.len() != version.canonical_bytes.div_ceil(CHUNK_BYTES)
        || version.extents.len() > MAX_CHUNKS
        || version
            .manifest_offset
            .checked_add(version.expected_manifest.len() as u64)
            .is_none_or(|end| end > container.end)
    {
        return Err(io::Error::other("container read geometry"));
    }
    let mut file = File::open(&container.path)?;
    counts.explicit_file_opens += 1;
    if file.metadata()?.len() != container.end || container.end > MAX_POOL_BYTES {
        return Err(io::Error::other("unexpected container length"));
    }
    file.seek(SeekFrom::Start(version.manifest_offset))?;
    let mut manifest = vec![0; version.expected_manifest.len()];
    Metered {
        file: &mut file,
        counts,
    }
    .read_exact(&mut manifest)?;
    if manifest != version.expected_manifest {
        return Err(io::Error::other(
            "container manifest differs from owned metadata",
        ));
    }
    let mut bytes = vec![0; version.canonical_bytes];
    let mut position = 0_usize;
    let mut first = 0;
    while first < version.extents.len() {
        let start = version.extents[first].offset;
        let mut end = start;
        let mut last = first;
        while last < version.extents.len() && version.extents[last].offset == end {
            let extent = version.extents[last];
            let expected_length = (version.canonical_bytes - last * CHUNK_BYTES).min(CHUNK_BYTES);
            if extent.length != expected_length as u64 {
                return Err(io::Error::other("container extent length"));
            }
            end = end
                .checked_add(extent.length)
                .filter(|end| *end <= version.manifest_offset)
                .ok_or_else(|| io::Error::other("container extent exceeds payload boundary"))?;
            last += 1;
        }
        let count = usize::try_from(end - start).map_err(io::Error::other)?;
        let next = position
            .checked_add(count)
            .filter(|next| *next <= bytes.len())
            .ok_or_else(|| io::Error::other("container reconstruction bound"))?;
        file.seek(SeekFrom::Start(start))?;
        Metered {
            file: &mut file,
            counts,
        }
        .read_exact(&mut bytes[position..next])?;
        position = next;
        first = last;
    }
    if position != bytes.len() {
        return Err(io::Error::other("container reconstruction incomplete"));
    }
    audit(bytes, expected)
}

fn fresh_base<'a>(
    container: &Container,
    version: &'a Version,
    expected: &CanonicalObject,
    counts: &mut Counts,
) -> io::Result<FreshBase<'a>> {
    Ok(FreshBase {
        audited: read_version(container, version, expected, counts)?,
        version,
    })
}

fn retire_version(
    container: &mut Container,
    version: Version,
    counts: &mut Counts,
) -> io::Result<()> {
    if version.container != container.path || version.expected_manifest.len() < 8 {
        return Err(io::Error::other("retirement container mismatch"));
    }
    // Only our retained original creation handle is used for the marker write.
    container
        .creation_handle
        .seek(SeekFrom::Start(version.manifest_offset))?;
    Metered {
        file: &mut container.creation_handle,
        counts,
    }
    .write_all(b"RETIRED\n")?;
    sync(&container.creation_handle, counts)
}

fn append_bad_tail(
    container: &mut Container,
    version: &Version,
    audited: &AuditedDisk,
    expected: &CanonicalObject,
    counts: &mut Counts,
) -> io::Result<Version> {
    if version.container != container.path
        || container.creation_handle.metadata()?.len() != container.end
    {
        return Err(io::Error::other("corruption fixture container mismatch"));
    }
    let last = version.extents.len() - 1;
    let mut tail = audited.0[last * CHUNK_BYTES..].to_vec();
    *tail
        .last_mut()
        .ok_or_else(|| io::Error::other("missing tail"))? ^= 1;
    let offset = container.end;
    container.creation_handle.seek(SeekFrom::Start(offset))?;
    let mut extents = version.extents.clone();
    extents[last] = Extent {
        offset,
        length: tail.len() as u64,
    };
    let end = offset + tail.len() as u64;
    if end > MAX_POOL_BYTES {
        return Err(io::Error::other("corruption fixture bound"));
    }
    Metered {
        file: &mut container.creation_handle,
        counts,
    }
    .write_all(&tail)?;
    container.end = end;
    finish_version(container, &expected.raw, extents, counts)
}

#[test]
#[ignore = "PUBLIC NONSECRET opt-in packed-container I/O candidate; not SQL or production storage"]
fn million_row_container_reuses_delta_and_reclaims_retired_storage_after_full_audits() {
    assert_eq!(
        std::env::var("DCS_PACKED_IO_FEASIBILITY").as_deref(),
        Ok("1"),
        "explicit feasibility guard required"
    );
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "dcs-public-packed-io-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    println!(
        "PACKED_IO_RUN {}",
        serde_json::json!({"directory":root,"public_nonsecret":true,"scope":"generic CSTORE/actual StoreDelta; not SQL/FHE performance","chunk_bytes":CHUNK_BYTES})
    );
    let fixture = fixture(&root);
    let baseline = root.join("single-base.object");
    observe("single-initial-write", |io| {
        write_single(&baseline, &fixture.base.raw, io)
    })
    .unwrap();
    observe("single-initial-read-audit", |io| {
        read_single(&baseline, &fixture.base, io)
    })
    .unwrap();
    let (mut container, base) = observe("packed-initial-write", |io| {
        let mut container = Container::create(&root.join("base.container"), io)?;
        let version = write_version(&mut container, &fixture.base.raw, None, io)?;
        Ok((container, version))
    })
    .unwrap();
    assert_eq!(base.extents.len(), 574);
    observe("packed-initial-read-audit", |io| {
        read_version(&container, &base, &fixture.base, io)
    })
    .unwrap();
    let copy_path = root.join("single-copy.object");
    observe("single-copy-write", |io| {
        write_single(&copy_path, &fixture.target.raw, io)
    })
    .unwrap();
    observe("single-copy-read-audit", |io| {
        read_single(&copy_path, &fixture.target, io)
    })
    .unwrap();
    let (copy_container, copy) = observe("packed-copy-write", |io| {
        let mut container = Container::create(&root.join("copy.container"), io)?;
        let version = write_version(&mut container, &fixture.target.raw, None, io)?;
        Ok((container, version))
    })
    .unwrap();
    observe("packed-copy-read-audit", |io| {
        read_version(&copy_container, &copy, &fixture.target, io)
    })
    .unwrap();
    let audited_base = observe("packed-base-read-audit-before-delta", |io| {
        fresh_base(&container, &base, &fixture.base, io)
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
    let target = observe("packed-delta-write", |io| {
        write_version(&mut container, &fixture.target.raw, Some(audited_base), io)
    })
    .unwrap();
    let changed: Vec<_> = target
        .extents
        .iter()
        .zip(&base.extents)
        .enumerate()
        .filter_map(|(i, (a, b))| (a.offset != b.offset).then_some(i))
        .collect();
    assert_eq!(changed, [0, 48]);
    let audited_target = observe("packed-delta-read-audit", |io| {
        read_version(&container, &target, &fixture.target, io)
    })
    .unwrap();
    assert_owner_plaintext(&fixture, &audited_target);
    let foreign = observe(
        "packed-copy-fresh-read-before-cross-container-control",
        |io| fresh_base(&copy_container, &copy, &fixture.target, io),
    )
    .unwrap();
    let before_rejection = container.end;
    assert!(
        observe("packed-cross-container-reuse-rejected", |io| write_version(
            &mut container,
            &fixture.target.raw,
            Some(foreign),
            io
        ))
        .is_err()
    );
    assert_eq!(container.end, before_rejection);
    assert_eq!(
        container.creation_handle.metadata().unwrap().len(),
        before_rejection
    );
    let mut preparation = Counts::default();
    let bad = append_bad_tail(
        &mut container,
        &target,
        &audited_target,
        &fixture.target,
        &mut preparation,
    )
    .unwrap();
    println!(
        "PACKED_IO_PREPARATION {}",
        serde_json::json!({"label":"fresh-appended-corrupt-tail-and-manifest","io":preparation})
    );
    assert!(
        observe("packed-corrupt-unrequested-tail-read-audit", |io| {
            read_version(&container, &bad, &fixture.target, io)
        })
        .is_err()
    );
    let mut extents = target.extents.clone();
    extents.swap(0, 1);
    let mut preparation = Counts::default();
    let wrong_mapping = finish_version(
        &mut container,
        &fixture.target.raw,
        extents,
        &mut preparation,
    )
    .unwrap();
    println!(
        "PACKED_IO_PREPARATION {}",
        serde_json::json!({"label":"fresh-coherent-wrong-mapping-manifest","io":preparation})
    );
    assert!(
        observe("packed-coherent-wrong-mapping-read-audit", |io| {
            read_version(&container, &wrong_mapping, &fixture.target, io)
        })
        .is_err()
    );
    observe("packed-owned-handle-retire-base", |io| {
        retire_version(&mut container, base, io)
    })
    .unwrap();
    observe("packed-target-read-audit-after-base-retirement", |io| {
        read_version(&container, &target, &fixture.target, io)
    })
    .unwrap();
    let source = observe("packed-fresh-read-audit-before-compaction", |io| {
        read_version(&container, &target, &fixture.target, io)
    })
    .unwrap();
    let compact_raw = objects::decode_disk(&source.0).unwrap();
    assert_eq!(compact_raw, fixture.target.raw);
    let (compacted, retained) = observe("packed-compaction-full-write", |io| {
        let mut compacted = Container::create(&root.join("compacted.container"), io)?;
        let retained = write_version(&mut compacted, &compact_raw, None, io)?;
        Ok((compacted, retained))
    })
    .unwrap();
    let checked = observe("packed-compacted-read-audit-before-old-unlink", |io| {
        read_version(&compacted, &retained, &fixture.target, io)
    })
    .unwrap();
    assert_owner_plaintext(&fixture, &checked);
    let removed_bytes = container.end;
    observe("packed-unlink-retired-container", |io| {
        drop(container.creation_handle);
        fs::remove_file(&container.path)?;
        io.successful_unlinks += 1;
        Ok(())
    })
    .unwrap();
    let final_target = observe("packed-target-read-audit-after-old-unlink", |io| {
        read_version(&compacted, &retained, &fixture.target, io)
    })
    .unwrap();
    assert_owner_plaintext(&fixture, &final_target);
    assert_eq!(
        compacted.end,
        final_target.0.len() as u64 + retained.expected_manifest.len() as u64
    );
    let root_bytes: u64 = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum();
    let source_store_bytes: u64 = fs::read_dir(root.join("actual-delta"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(root_bytes + source_store_bytes < 512 * 1024 * 1024);
    println!(
        "PACKED_IO_RESULT {}",
        serde_json::json!({"directory":root,"canonical_object_bytes":final_target.0.len(),"references":retained.extents.len(),"manifest_bytes":retained.expected_manifest.len(),"removed_container_eof_bytes":removed_bytes,"retained_container_eof_bytes":compacted.end,"root_file_eof_bytes":root_bytes,"source_store_eof_bytes":source_store_bytes,"all_data_pages_owner_decrypted":true,"artifacts_retained":true,"not_measured":["SQL latency","peak RAM","device I/O or allocated metadata","production accounting, persistent reopen, power-loss or hostile namespace guarantees"]})
    );
}
