#[cfg(windows)]
#[path = "support/native_memory.rs"]
mod native_memory;
// Public non-secret fixture. Real crypto test is opt-in and requires an exclusive CPU lease.
// No seed, owner image or wrapping key is logged or written. Encrypted files are retained.
use compact_bfv_byte_limb_core::{
    Geometry, Owner as BfvOwner, PeerEvaluator, Predicate, QueryContext, SelectedField,
};
use compact_store::{Layout, LookupResponse, Owner as CompactOwner};
use sealed_owner_recovery_candidate::*;
use spiral_owner_state::OwnerState;
use spiral_rs::{
    client::{Client, PublicParameters, Query},
    params::Params,
    server::{load_db_from_seek, process_query},
};
use std::{io::Cursor, path::PathBuf};

fn fixture_directory() -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::current_dir()
        .unwrap()
        .join(".local")
        .join(format!(
            "public-owner-recovery-{now}-{}",
            std::process::id()
        ));
    std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
    std::fs::create_dir(&directory).unwrap();
    directory
}
fn write_new(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap(); // no fsync/crash-durability claim.
}
fn fetch(
    params: &Params,
    client: &Client<'_>,
    public: &PublicParameters<'_>,
    db: &[u64],
    slot: usize,
) -> Vec<u8> {
    let query = Query::deserialize(params, &client.generate_query(slot).serialize());
    let response = process_query(params, public, &query, db);
    let mut bytes = client.decode_response(&response);
    assert_eq!(bytes.len(), spiral_owner_state::RECORD_BYTES + 32);
    assert!(
        bytes[spiral_owner_state::RECORD_BYTES..]
            .iter()
            .all(|x| *x == 0)
    );
    bytes.truncate(spiral_owner_state::RECORD_BYTES);
    bytes
}

#[test]
#[ignore = "exclusive CPU/write lease: original disk pages + BFV rotations/product + real PIR"]
fn sealed_restore_uses_original_files_public_keys_and_pir_after_all_old_owners_drop() {
    #[cfg(windows)]
    native_memory::check("start");
    let directory = fixture_directory();
    let params = spiral_owner_state::profile_params();
    let pir_domain = [19u8; 32]; // public fixture domain, not a seed or a key.
    let pir = OwnerState::generate(&params, pir_domain).unwrap();
    let original_pir_public = PublicParameters::deserialize(&params, &pir.public_wire);
    let (bfv, bfv_setup) = BfvOwner::generate(Geometry::Rows256).unwrap();
    let bfv_wire = bfv_setup.to_bytes().unwrap();
    let original_bfv_peer = PeerEvaluator::from_public_setup(&bfv_setup).unwrap();
    let wrapping = WrappingKey::generate().unwrap(); // retained separately in RAM only.
    let binding = CheckpointBinding {
        bundle_id: [3; 32],
        checkpoint_id: [4; 32],
        generation: 7,
    };
    let mut owners = Vec::new();
    let mut metadata = Vec::new();
    let mut source_images = Vec::new();
    for table_id in 0u32..3 {
        let mut database = [0u8; 16];
        database[..4].copy_from_slice(&table_id.to_le_bytes());
        let owner = CompactOwner::generate(database).unwrap();
        let layout = Layout {
            schema: [1; 16],
            row_width: 3,
            rows_per_page: 4,
            row_count: 8,
        };
        // Explicitly public fixture; ages and boundary values are not secret participant data.
        let plain = [
            7, 255, 255, 8, 1, 1, 7, 0, 0, 9, 1, 0, 7, 2, 0, 8, 3, 0, 7, 4, 0, 9, 5, 0,
        ];
        let data = owner.seal(layout, &plain, snapshot_limits()).unwrap();
        let index = owner
            .seal(
                Layout {
                    schema: [2; 16],
                    ..layout
                },
                &[table_id as u8; 24],
                snapshot_limits(),
            )
            .unwrap();
        let data_bytes = data.encode();
        let index_bytes = index.encode();
        let data_file = format!("table-{table_id}-data.bin");
        let index_file = format!("table-{table_id}-index.bin");
        write_new(&directory.join(&data_file), &data_bytes);
        write_new(&directory.join(&index_file), &index_bytes);
        metadata.push(TableMetadata {
            table_id,
            data_file,
            index_file,
            data_bytes: data_bytes.len() as u64,
            index_bytes: index_bytes.len() as u64,
            data_head: data.commitment().clone(),
            index_head: index.commitment().clone(),
        });
        source_images.push((data, index));
        owners.push(owner);
    }
    let tables: Vec<_> = owners
        .iter()
        .zip(metadata.iter())
        .map(|(owner, metadata)| TableCheckpoint {
            metadata: metadata.clone(),
            owner,
        })
        .collect();
    let sealed = seal_checkpoint(
        &wrapping,
        binding,
        &tables,
        &bfv,
        OriginalPublic {
            bfv: &bfv_wire,
            pir: &pir.public_wire,
        },
        &pir.owner,
        pir_domain,
    )
    .unwrap();
    write_new(&directory.join("owner-checkpoint.sealed"), &sealed.wire);
    write_new(&directory.join("original-bfv-public.bin"), &bfv_wire);
    write_new(&directory.join("original-pir-public.bin"), &pir.public_wire);
    let original_pir_wire = pir.public_wire;
    let record_cases = [
        (0usize, 0usize, 0u64),
        (255usize, 0usize, 1u64),
        (511usize, 1usize, 0u64),
    ];
    let mut records =
        vec![0u8; spiral_owner_state::RECORD_SLOTS * spiral_owner_state::RECORD_BYTES];
    for (slot, which, page) in record_cases {
        let snapshot = if which == 0 {
            &source_images[0].0
        } else {
            &source_images[0].1
        };
        let proof = snapshot.lookup(page, snapshot_limits()).unwrap().encode();
        let start = slot * spiral_owner_state::RECORD_BYTES;
        records[start..start + 4].copy_from_slice(&(proof.len() as u32).to_le_bytes());
        records[start + 4..start + 4 + proof.len()].copy_from_slice(&proof);
    }
    let native_db = load_db_from_seek(&params, &mut Cursor::new(records));
    let original_middle = fetch(
        &params,
        &pir.client,
        &original_pir_public,
        native_db.as_slice(),
        255,
    );
    drop(tables);
    drop(owners);
    drop(source_images);
    drop(bfv);
    drop(bfv_setup);
    drop(pir.client);
    drop(pir.owner);
    // There are now no original live owners, client or plaintext secret backup buffers.
    // Original PUBLIC peer/setup and actual encrypted files/native cache are intentionally retained.

    let restored = restore_checkpoint(
        &wrapping,
        &sealed.anchor,
        &sealed.wire,
        OriginalPublic {
            bfv: &bfv_wire,
            pir: &original_pir_wire,
        },
        &params,
        &directory,
    )
    .unwrap();

    assert_eq!(restored.bfv_public().to_bytes().unwrap(), bfv_wire);
    assert_eq!(restored.pir().public.serialize(), original_pir_wire);
    assert_eq!(restored.tables().len(), 3);
    for table in restored.tables() {
        let (data, index) = table.read_original_snapshots(&directory).unwrap();
        assert_eq!(data.commitment(), &table.metadata().data_head);
        assert_eq!(index.commitment(), &table.metadata().index_head);
        for (snapshot, head, expected) in [
            (
                &data,
                &table.metadata().data_head,
                vec![7, 255, 255, 8, 1, 1, 7, 0, 0, 9, 1, 0],
            ),
            (
                &index,
                &table.metadata().index_head,
                vec![table.metadata().table_id as u8; 12],
            ),
        ] {
            let page = snapshot
                .lookup(0, snapshot_limits())
                .unwrap()
                .verify(head, 0, snapshot_limits())
                .unwrap();
            assert_eq!(table.owner().decrypt(&page).unwrap().as_bytes(), expected);
        }
    }
    for (slot, which, page) in record_cases {
        let record = fetch(
            &params,
            &restored.pir().client,
            &original_pir_public,
            native_db.as_slice(),
            slot,
        );
        if slot == 255 {
            assert_eq!(record, original_middle);
        }
        let length = u32::from_le_bytes(record[..4].try_into().unwrap()) as usize;
        assert!(length <= spiral_owner_state::RECORD_BYTES - 4);
        let response = LookupResponse::decode(&record[4..4 + length], snapshot_limits()).unwrap();
        #[cfg(windows)]
        native_memory::check("after_restore_and_pir");
        let table = &restored.tables()[0];
        let head = if which == 0 {
            &table.metadata().data_head
        } else {
            &table.metadata().index_head
        };
        let verified = response.verify(head, page, snapshot_limits()).unwrap();
        assert_eq!(
            table.owner().decrypt(&verified).unwrap().as_bytes().len(),
            12
        );
    }
    #[cfg(windows)]
    native_memory::check("after_restore_and_pir");
    let table = &restored.tables()[0];
    let (data, _) = table.read_original_snapshots(&directory).unwrap();
    let verified = data
        .lookup(0, snapshot_limits())
        .unwrap()
        .verify(&table.metadata().data_head, 0, snapshot_limits())
        .unwrap();
    let plain = table.owner().decrypt(&verified).unwrap();
    let fields: Vec<_> = plain
        .as_bytes()
        .as_chunks::<3>()
        .0
        .iter()
        .map(|row| SelectedField {
            age: row[0],
            amount: u16::from_le_bytes([row[1], row[2]]),
            active: true,
        })
        .collect();
    let prepared = restored
        .bfv_owner()
        .prepare(
            QueryContext::new(
                [8; 16],
                table.metadata().data_head.encode(),
                table.metadata().index_head.encode(),
            ),
            &fields,
            Predicate::Equal(7),
        )
        .unwrap();
    let evaluation = original_bfv_peer.evaluate(&prepared.request).unwrap();
    assert!(evaluation.stats.rotations > 0);
    assert!(evaluation.stats.ct_ct_multiplications > 0); // original relinearization key actually used.
    let aggregate = restored
        .bfv_owner()
        .decrypt_unverified(prepared.pending, &evaluation.output)
        .unwrap();
    assert_eq!((aggregate.count, aggregate.sum), (2, 65535));

    let wrong_key = WrappingKey::generate().unwrap();
    assert!(matches!(
        restore_checkpoint(
            &wrong_key,
            &sealed.anchor,
            &sealed.wire,
            OriginalPublic {
                bfv: &bfv_wire,
                pir: &original_pir_wire
            },
            &params,
            &directory
        ),
        Err(RecoveryError::Authentication)
    ));
    for offset in [OUTER_HEADER_BYTES, sealed.wire.len() - 1] {
        let mut corrupt = sealed.wire.clone();
        corrupt[offset] ^= 1;
        assert!(matches!(
            restore_checkpoint(
                &wrapping,
                &sealed.anchor,
                &corrupt,
                OriginalPublic {
                    bfv: &bfv_wire,
                    pir: &original_pir_wire
                },
                &params,
                &directory
            ),
            Err(RecoveryError::Authentication)
        ));
    }
    let mut wrong_public = bfv_wire.clone();
    wrong_public[0] ^= 1;
    assert!(matches!(
        restore_checkpoint(
            &wrapping,
            &sealed.anchor,
            &sealed.wire,
            OriginalPublic {
                bfv: &wrong_public,
                pir: &original_pir_wire
            },
            &params,
            &directory
        ),
        Err(RecoveryError::PublicIdentity)
    ));
    let mut current_anchor = sealed.anchor.clone();
    current_anchor.binding.generation += 1;
    assert!(matches!(
        restore_checkpoint(
            &wrapping,
            &current_anchor,
            &sealed.wire,
            OriginalPublic {
                bfv: &bfv_wire,
                pir: &original_pir_wire
            },
            &params,
            &directory
        ),
        Err(RecoveryError::Checkpoint)
    ));
    let mut wrong_heads = sealed.anchor.clone();
    wrong_heads.catalog_digest[0] ^= 1;
    assert!(matches!(
        restore_checkpoint(
            &wrapping,
            &wrong_heads,
            &sealed.wire,
            OriginalPublic {
                bfv: &bfv_wire,
                pir: &original_pir_wire
            },
            &params,
            &directory
        ),
        Err(RecoveryError::Checkpoint)
    ));
    // A valid OLD anchor deliberately still restores: anti-rollback authority is EXTERNAL.
    // The fixture files are retained unchanged; no reseal/regeneration or destructive cleanup.
    for table in restored.tables() {
        let (data, index) = table.read_original_snapshots(&directory).unwrap();
        assert_eq!(data.encode().len() as u64, table.metadata().data_bytes);
        assert_eq!(index.encode().len() as u64, table.metadata().index_bytes);
    }
    #[cfg(windows)]
    native_memory::check("complete");
}
