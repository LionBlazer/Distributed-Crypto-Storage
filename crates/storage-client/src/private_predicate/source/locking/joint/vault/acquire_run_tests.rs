//! PUBLIC NONSECRET authorities. One genuine input16 setup is shared; each
//! hostile phase chain has its own actual authenticated WAL and exclusive open.
use super::super::super::acquire::AcquireState;
use super::*;

fn compute_record(template: &Snapshot, generation: u64) -> Snapshot {
    Snapshot {
        managed: None,
        phase: OwnerVaultPhase::AcquireComputePrepared,
        generation,
        pending: template.pending,
        stamp: template.stamp,
        idle: Zeroizing::new(*template.idle),
        candidate: None,
        block: None,
        checkpoint: None,
        outcome: None,
        acquire: Some(template.acquire.as_ref().unwrap().copy().unwrap()),
    }
}
fn append(vault: &mut OwnerVault, record: &Snapshot) {
    let lease = vault
        .wal
        .budget
        .reserve(Wal::record_bytes(record).unwrap())
        .unwrap();
    drop(vault.wal.append(record, lease).unwrap());
}

#[test]
fn authenticated_acquire_runs_reject_reordered_or_changed_originals_without_repair_or_poison() {
    // Arrange ONE actual Source/BFV/Ready/input16/Life/Link collection. The old
    // bank comes from genuine Begin completion, never a fabricated held Registry.
    let (rig, opening) = Rig::new_inner(true);
    let mut original = rig.create(opening);
    let (cursor, begin) = begin(&rig, &mut original);
    let completed = original
        .complete_control(cursor, &rig.owner, rig.fetched(), &begin.checkpoint)
        .unwrap();
    original.acknowledge(completed.cursor()).unwrap();
    let work = compute(&rig, &mut original);
    let template = compute_record(&original.saved, 0);
    let before = parent(&original.history, &rig.binding).unwrap();
    drop(work);
    drop(original);
    let replay = [
        OwnerVaultReplay {
            checkpoint: &rig.boot.checkpoint,
            block: &rig.boot.block,
        },
        OwnerVaultReplay {
            checkpoint: &begin.checkpoint,
            block: &begin.block,
        },
    ];

    for case in 0..13u8 {
        let identity = [0xc0 + case; 32];
        let pins = OwnerVaultPins::new(
            rig.binding.clone(),
            OwnerVaultIdentity::new(identity).unwrap(),
        );
        let opening =
            state::restore_idle(template.idle.as_ref(), &rig.owner, rig.fetched(), &before)
                .unwrap();
        // A healthy independently checked prefix must create successfully before
        // the fixture owner appends a canonical, valid-AEAD false phase record.
        let mut vault = OwnerVault::create_new(
            rig.quota(),
            pins,
            authority(),
            &rig.owner,
            rig.fetched(),
            &replay,
            opening,
        )
        .unwrap();
        let path = rig
            .quota()
            .control_file(vault.pins.file_id(), protocol_storage::ControlFile::Wal);
        let first = compute_record(&template, 0);
        let fake = vault.ingress.retain_public_blob(&[0x53; 256]).unwrap();
        let mut catalog = compute_record(&template, 0);
        let mut bytes = catalog.acquire.as_ref().unwrap().encode().unwrap();
        let end = bytes.len();
        bytes[end - 40..end - 8].copy_from_slice(fake.sha256());
        bytes[end - 8..].copy_from_slice(&fake.bytes().to_le_bytes());
        catalog.acquire = Some(AcquireState::decode(&bytes).unwrap());
        match case {
            0 => append(&mut vault, &catalog), // Catalog cannot replace Compute.
            1 => {
                append(&mut vault, &first);
                append(&mut vault, &first);
            }
            2 => {
                append(&mut vault, &first);
                append(&mut vault, &catalog);
                append(&mut vault, &catalog);
            }
            _ => {
                match case {
                    3 => bytes[end - 40 - 20 * 40 + 3 * 40] ^= 1, // Source reference.
                    4 => bytes[end - 40 - 20 * 40 + 17 * 40] ^= 1, // Last input proof.
                    5 => bytes[8] ^= 1,                           // Original backup fingerprint.
                    6 => {
                        bytes[end
                            - 40
                            - 20 * 40
                            - super::super::super::super::JOINT_RECOVERY_BYTES
                            + 120] ^= 1
                    }
                    7 => bytes[40] ^= 1, // Exact original parent/context stamp.
                    8 => catalog.generation += 1,
                    9 => catalog.pending[31] ^= 1,
                    10 => {
                        let length_at = 8 + 64 + IDLE_BYTES;
                        let length =
                            u32::from_le_bytes(bytes[length_at..length_at + 4].try_into().unwrap())
                                as usize;
                        let root = length_at + 4 + length;
                        let value = u64::from_le_bytes(bytes[root..root + 8].try_into().unwrap());
                        bytes[root..root + 8].copy_from_slice(&u64::from(value == 0).to_le_bytes());
                    }
                    11 => catalog.stamp[31] ^= 1,
                    12 => {
                        let length_at = 8 + 64 + IDLE_BYTES;
                        let length =
                            u32::from_le_bytes(bytes[length_at..length_at + 4].try_into().unwrap())
                                as usize;
                        let start = length_at + 4;
                        let request = JointRequest::decode(&bytes[start..start + length]).unwrap();
                        let mut inner = request.inner().clone();
                        inner.nonce[31] ^= 1;
                        let spec = rig.binding.application_descriptor().source_spec().unwrap();
                        inner.query = registry200_journal::intent_query(
                            &spec,
                            inner.genesis,
                            inner.parent,
                            inner.nonce,
                            inner.enrollment,
                            registry200_journal::Operation::Transition,
                        );
                        let app = JointApplication::new(
                            rig.binding.application_descriptor().clone(),
                            rig.binding.journal_genesis(),
                        )
                        .unwrap();
                        let changed = JointRequest::new(&app, Lane::Acquire, inner)
                            .unwrap()
                            .encode()
                            .unwrap();
                        assert_eq!(changed.len(), length);
                        bytes[start..start + length].copy_from_slice(&changed);
                    }
                    _ => unreachable!(),
                }
                catalog.acquire = Some(AcquireState::decode(&bytes).unwrap());
                append(&mut vault, &first);
                append(&mut vault, &catalog);
            }
        }
        drop(bytes);
        drop(vault);
        let extent = std::fs::metadata(&path).unwrap().len();
        let used = rig.quota().usage().unwrap().total_bytes();
        let result = OwnerVault::open_existing_acquire(
            rig.quota(),
            OwnerVaultPins::new(
                rig.binding.clone(),
                OwnerVaultIdentity::new(identity).unwrap(),
            ),
            authority(),
            &rig.owner,
            rig.fetched(),
            &replay,
            &rig.backups.as_ref().unwrap().material(),
        );
        if case < 3 {
            assert!(
                matches!(result, Err(OwnerVaultError::Encoding)),
                "phase order case {case}"
            );
        } else {
            assert!(
                matches!(result, Err(OwnerVaultError::Pins)),
                "original identity case {case}"
            );
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            extent,
            "no tail repair {case}"
        );
        assert_eq!(
            rig.quota().usage().unwrap().total_bytes(),
            used,
            "no new retained artifact {case}"
        );
        drop(rig.quota().control_budget().reserve(0).unwrap());
    }
}
