//! PUBLIC NONSECRET fixture keys/rows only. All objects and backups stay in RAM.
//! No user credential/file/OS-vault/network access and no simulated Source proof.
use super::*;
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use compact_store::{Commitment, Limits};
use p3_field::PrimeCharacteristicRing;
use peer_runtime::RawBundle;

const DATABASE: [u8; 16] = [0x21; 16];
const DOMAIN: [u8; 16] = [0x42; 16];
const KEY: [u8; 32] = [0x63; 32];
const MASTER: [u8; 32] = [0x74; 32];
const RECORD_ID: [u8; 32] = [0x85; 32];
const ROWS: [PlainRow; 4] = [
    PlainRow {
        age: 255,
        amount: 0,
    },
    PlainRow {
        age: 0,
        amount: 65535,
    },
    PlainRow {
        age: 255,
        amount: 1,
    },
    PlainRow {
        age: 1,
        amount: 128,
    },
];
struct Fixture {
    owner: SourceOwner,
    heads: ReadHeads,
    bundle: RawBundle,
    object: [u8; 32],
    identity: SourceStateIdentity,
}
impl Fixture {
    fn new() -> Self {
        let owner = SourceOwner::new(DATABASE, DOMAIN, Zeroizing::new(KEY)).unwrap();
        let table = owner
            .seal_partition(
                &TableId::from_bytes([0x96; 32]).unwrap(),
                &ROWS,
                RowIds::generate(4).unwrap(),
            )
            .unwrap();
        let heads = table.read_heads();
        let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
        let object = *bundle.target_version().unwrap().object();
        let key = {
            let loaded = owner
                .load(FetchedSource {
                    object,
                    bundle: &bundle,
                    heads: &heads,
                })
                .unwrap();
            source::statement::encode_digest(loaded.draft.key_commitment)
        };
        let identity = SourceStateIdentity::new(RECORD_ID, key).unwrap();
        Self {
            owner,
            heads,
            bundle,
            object,
            identity,
        }
    }
    fn fetched(&self) -> FetchedSource<'_> {
        FetchedSource {
            object: self.object,
            bundle: &self.bundle,
            heads: &self.heads,
        }
    }
}
fn authority() -> SourceStateAuthority {
    SourceStateAuthority::new(Zeroizing::new(MASTER))
}
fn changed_head(head: &Commitment, offset: usize) -> Commitment {
    let mut bytes = head.encode();
    bytes[offset] ^= 1;
    Commitment::decode(&bytes, Limits::default()).unwrap()
}

#[test]
fn encrypted_source_restore_opens_all_originals_and_preserves_ckey_after_owner_drop() {
    let f = Fixture::new();
    let master = authority();
    let record = f
        .owner
        .backup_private_state(&f.identity, f.fetched(), &master)
        .unwrap();
    let again = f
        .owner
        .backup_private_state(&f.identity, f.fetched(), &master)
        .unwrap();
    assert_eq!(record.as_bytes().len(), SOURCE_STATE_BYTES);
    assert_eq!(SOURCE_STATE_BYTES, 488);
    assert_eq!(SOURCE_STATE_HEADER_BYTES, 368);
    assert_ne!(
        record.as_bytes(),
        again.as_bytes(),
        "fresh wrapping nonce, same Source opening"
    );
    assert_eq!(&record.as_bytes()[80..192], &f.heads.data().encode());
    assert_eq!(&record.as_bytes()[192..304], &f.heads.index().encode());
    let Fixture {
        owner,
        heads,
        bundle,
        object,
        identity,
    } = f;
    drop(owner); // No SourceOwner/Table/LoadedSource survives from before backup.
    let parsed = EncryptedSourceState::from_bytes(record.as_bytes()).unwrap();
    let restored = SourceOwner::restore_private_state(
        &identity,
        FetchedSource {
            object,
            bundle: &bundle,
            heads: &heads,
        },
        &master,
        &parsed,
    )
    .unwrap();
    let loaded = restored
        .load(FetchedSource {
            object,
            bundle: &bundle,
            heads: &heads,
        })
        .unwrap();
    assert_eq!(
        loaded.originals.as_slice(),
        &ROWS.map(|r| bfv_query_core::CoefficientRow {
            age: r.age,
            amount: r.amount
        })
    );
    assert_eq!(loaded.plain.len(), 2348);
    assert_eq!(
        loaded.draft.heads,
        [heads.data().encode(), heads.index().encode()]
    );
    assert_eq!(
        source::statement::encode_digest(loaded.draft.key_commitment),
        identity.key_commitment
    );
}

#[test]
fn source_state_requires_external_authority_record_object_both_full_heads_table_and_ckey() {
    let f = Fixture::new();
    let master = authority();
    let record = f
        .owner
        .backup_private_state(&f.identity, f.fetched(), &master)
        .unwrap();
    let wrong_master = SourceStateAuthority::new(Zeroizing::new([0x75; 32]));
    assert!(
        SourceOwner::restore_private_state(&f.identity, f.fetched(), &wrong_master, &record)
            .is_err()
    );
    let mut record_id = RECORD_ID;
    record_id[31] ^= 1;
    let wrong_record = SourceStateIdentity::new(record_id, f.identity.key_commitment).unwrap();
    assert!(
        SourceOwner::restore_private_state(&wrong_record, f.fetched(), &master, &record).is_err()
    );
    let mut object = f.object;
    object[31] ^= 1;
    assert!(
        SourceOwner::restore_private_state(
            &f.identity,
            FetchedSource {
                object,
                bundle: &f.bundle,
                heads: &f.heads
            },
            &master,
            &record
        )
        .is_err()
    );
    for which in 0..2 {
        for offset in [8, 24, 56, 111] {
            let data = if which == 0 {
                changed_head(f.heads.data(), offset)
            } else {
                f.heads.data().clone()
            };
            let index = if which == 1 {
                changed_head(f.heads.index(), offset)
            } else {
                f.heads.index().clone()
            };
            let heads =
                ReadHeads::new(*f.heads.table_id(), &data, &index, Limits::default()).unwrap();
            assert!(
                SourceOwner::restore_private_state(
                    &f.identity,
                    FetchedSource {
                        object: f.object,
                        bundle: &f.bundle,
                        heads: &heads
                    },
                    &master,
                    &record
                )
                .is_err()
            );
        }
    }
    let wrong_table = ReadHeads::new(
        TableId::from_bytes([0x97; 32]).unwrap(),
        f.heads.data(),
        f.heads.index(),
        Limits::default(),
    )
    .unwrap();
    assert!(
        SourceOwner::restore_private_state(
            &f.identity,
            FetchedSource {
                object: f.object,
                bundle: &f.bundle,
                heads: &wrong_table
            },
            &master,
            &record
        )
        .is_err()
    );
    let mut key = source::statement::decode_digest(f.identity.key_commitment).unwrap();
    key[3] += Val::ONE;
    let wrong_key =
        SourceStateIdentity::new(RECORD_ID, source::statement::encode_digest(key)).unwrap();
    assert!(
        f.owner
            .backup_private_state(&wrong_key, f.fetched(), &master)
            .is_err()
    );
    assert!(SourceOwner::restore_private_state(&wrong_key, f.fetched(), &master, &record).is_err());
    let wrong_source = SourceOwner::new(DATABASE, DOMAIN, Zeroizing::new([0x64; 32])).unwrap();
    assert!(
        wrong_source
            .backup_private_state(&f.identity, f.fetched(), &master)
            .is_err()
    );
    // Both paths must actually re-audit the supplied complete in-memory image.
    let mut damaged = f.bundle.clone();
    *damaged.index.last_mut().unwrap() ^= 1;
    assert!(
        f.owner
            .backup_private_state(
                &f.identity,
                FetchedSource {
                    object: f.object,
                    bundle: &damaged,
                    heads: &f.heads
                },
                &master
            )
            .is_err()
    );
    assert!(
        SourceOwner::restore_private_state(
            &f.identity,
            FetchedSource {
                object: f.object,
                bundle: &damaged,
                heads: &f.heads
            },
            &master,
            &record
        )
        .is_err()
    );
}

#[test]
fn exact_source_record_grammar_rejects_tampering_truncation_tails_aliases_and_other_roles() {
    let f = Fixture::new();
    let master = authority();
    let record = f
        .owner
        .backup_private_state(&f.identity, f.fetched(), &master)
        .unwrap();
    for at in [
        0, 8, 10, 11, 15, 16, 47, 48, 79, 80, 192, 304, 335, 336, 359, 360, 364, 367, 368, 487,
    ] {
        let mut bytes = record.as_bytes().to_vec();
        bytes[at] ^= 1;
        if let Ok(bad) = EncryptedSourceState::from_bytes(&bytes) {
            assert!(
                SourceOwner::restore_private_state(&f.identity, f.fetched(), &master, &bad)
                    .is_err(),
                "tamper {at}"
            );
        }
    }
    for end in [0, 8, 367, 368, 487] {
        assert!(EncryptedSourceState::from_bytes(&record.as_bytes()[..end]).is_err());
    }
    let mut trailing = record.as_bytes().to_vec();
    trailing.push(0);
    assert!(EncryptedSourceState::from_bytes(&trailing).is_err());
    assert!(EncryptedSourceState::from_bytes(&vec![0; SOURCE_STATE_BYTES + 1]).is_err());
    let mut other_role = record.as_bytes().to_vec();
    other_role[..8].copy_from_slice(b"BFVOPS01");
    assert!(EncryptedSourceState::from_bytes(&other_role).is_err());
    let mut alias = record.as_bytes().to_vec();
    alias[304..312].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(EncryptedSourceState::from_bytes(&alias).is_err());
    assert!(SourceStateIdentity::new(RECORD_ID, alias[304..336].try_into().unwrap()).is_err());
}

#[test]
fn authenticated_private_payload_still_requires_original_key_table_and_canonical_exact_salt() {
    let f = Fixture::new();
    let master = authority();
    let record = f
        .owner
        .backup_private_state(&f.identity, f.fetched(), &master)
        .unwrap();
    let plain = codec::open(
        codec::Pins::new(&f.identity, f.object, &f.heads).unwrap(),
        &master,
        &record,
    )
    .unwrap();
    for case in 0..6 {
        // The test wrapping key is PUBLIC NONSECRET. These are genuine AEAD
        // records of hostile payloads, not a fake authentication/proof callback.
        let mut bad = Zeroizing::new(*plain);
        match case {
            0 => bad[0] ^= 1,
            1 => bad[8] ^= 1,
            2 => {
                let old = u64::from_le_bytes(bad[40..48].try_into().unwrap());
                bad[40..48].copy_from_slice(&((old + 1) % Val::ORDER_U64).to_le_bytes());
            }
            3 => bad[40..48].copy_from_slice(&Val::ORDER_U64.to_le_bytes()),
            4 => bad[64..72].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => bad[103] ^= 1,
        }
        let sealed = codec::seal(
            codec::Pins::new(&f.identity, f.object, &f.heads).unwrap(),
            &master,
            &bad,
        )
        .unwrap();
        assert!(
            SourceOwner::restore_private_state(&f.identity, f.fetched(), &master, &sealed).is_err(),
            "authenticated payload {case}"
        );
    }
    for boundary in [0, Val::ORDER_U64 - 1] {
        let mut plain = Zeroizing::new(*plain);
        for word in plain[40..72].as_chunks_mut::<8>().0 {
            *word = boundary.to_le_bytes();
        }
        let opening = private_opening(&plain, f.heads.table_id().as_bytes()).unwrap();
        assert_eq!(*opening.key_salt, [boundary; 4]); // Canonical preflight only, no Ckey/proof grant.
    }
}

#[test]
fn restored_source_produces_actual_canonical_source_proof_after_original_owner_drop() {
    use registry200_proof::admission::CanonicalSource;
    let f = Fixture::new();
    let master = authority();
    let record = f
        .owner
        .backup_private_state(&f.identity, f.fetched(), &master)
        .unwrap();
    let Fixture {
        owner,
        heads,
        bundle,
        object,
        identity,
    } = f;
    drop(owner);
    let restored = SourceOwner::restore_private_state(
        &identity,
        FetchedSource {
            object,
            bundle: &bundle,
            heads: &heads,
        },
        &master,
        &record,
    )
    .unwrap();
    let (claim, witness) =
        {
            let loaded = restored
                .load(FetchedSource {
                    object,
                    bundle: &bundle,
                    heads: &heads,
                })
                .unwrap();
            let salt = crate::private_predicate::random_salt()
                .unwrap()
                .map(Val::from_u64);
            let mut claim = loaded.draft;
            claim.request = [0xA7; 32];
            claim.open_commitment = source::commitment::digest(
                &source::commitment::opening_fields(&claim, salt, &loaded.plain),
            );
            let witness = restored.source_witness(salt, &loaded.originals);
            (CanonicalSource::checked_claim(&claim).unwrap(), witness)
        };
    // This is the existing genuine SDK producer, including its actual self-
    // verification. No acceptance callback, native row oracle or dummy proof.
    let evidence = source::prove(&claim, &witness).unwrap();
    drop(witness);
    drop(restored);
    assert_eq!(evidence.statement().values(), claim.claim().values());
    assert_eq!(evidence.statement().heads, claim.claim().heads);
    assert_eq!(
        source::statement::encode_digest(evidence.statement().key_commitment),
        identity.key_commitment
    );
    assert!(!evidence.as_bytes().is_empty());
    assert!(evidence.as_bytes().len() <= registry200_proof::wire::frame::MAX_SOURCE_BYTES);
}
