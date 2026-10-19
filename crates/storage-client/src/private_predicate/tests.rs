//! PUBLIC NONSECRET rows and AEAD keys; no private predicate proof is simulated.
use super::*;
use bfv_query_core::{CoefficientRow, Geometry, KeyScope, Owner, ProofEpochStage};
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use compact_store::Limits;
use peer_runtime::RawBundle;
use zeroize::Zeroizing;

const DATABASE: [u8; 16] = [0x21; 16];
const DOMAIN: [u8; 16] = [0x42; 16];
const KEY: [u8; 32] = [0x63; 32];
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

fn compiled(sql: &str) -> Result<CompiledPrivatePredicate, registry200_proof::BackendError> {
    CompiledPrivatePredicate::compile(sql, Zeroizing::new([0x84; 32]), [0xa5; 32])
}

fn stored_originals() -> (SourceOwner, ReadHeads, RawBundle, [u8; 32]) {
    let owner = SourceOwner::new(DATABASE, DOMAIN, Zeroizing::new(KEY)).unwrap();
    let table = owner
        .seal_partition(
            &TableId::from_bytes([0xc6; 32]).unwrap(),
            &ROWS,
            RowIds::generate(4).unwrap(),
        )
        .unwrap();
    let heads = table.read_heads();
    let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    let object = *bundle.target_version().unwrap().object();
    drop(table);
    (owner, heads, bundle, object)
}

#[test]
fn compiler_accepts_complete_age_amount_selects_without_reading_rows() {
    for sql in [
        "SELECT age, amount FROM records",
        "SELECT age, amount FROM records WHERE age = 255",
        "SELECT age, amount FROM records WHERE age BETWEEN 0 AND 1 OR age = 255",
        "SELECT age, amount FROM records WHERE FALSE",
    ] {
        assert!(compiled(sql).is_ok(), "{sql}");
    }
}

#[test]
fn compiler_rejects_locking_mutations_aggregates_projection_and_windows() {
    for sql in [
        "SELECT age, amount FROM records FOR UPDATE",
        "SELECT age, amount FROM records FOR UPDATE SKIP LOCKED",
        "UPDATE records SET amount = amount + 1 WHERE age = 1",
        "INSERT INTO records (age, amount) VALUES (1, 2)",
        "SELECT COUNT(*) FROM records",
        "SELECT age FROM records",
        "SELECT amount, age FROM records",
        "SELECT age, amount FROM records LIMIT 0",
        "SELECT age, amount FROM records OFFSET 1",
    ] {
        assert!(compiled(sql).is_err(), "{sql}");
    }
}

#[test]
fn compiler_requires_a_nonzero_private_blind_distinct_from_public_nonce() {
    let sql = "SELECT age, amount FROM records WHERE age = 1";
    for blind in [[0; 32], [0xa5; 32]] {
        assert!(matches!(
            CompiledPrivatePredicate::compile(sql, Zeroizing::new(blind), [0xa5; 32]),
            Err(registry200_proof::BackendError::Shape)
        ));
    }
    assert!(compiled(sql).is_ok());
}

#[test]
fn fetched_source_restores_every_original_and_the_complete_index() {
    // The original Table is gone; only actual sealed bytes and independent pins remain.
    let (owner, heads, bundle, object) = stored_originals();
    let loaded = owner
        .load(FetchedSource {
            object,
            bundle: &bundle,
            heads: &heads,
        })
        .unwrap();

    assert_eq!(
        loaded.originals.as_slice(),
        &ROWS.map(|row| CoefficientRow {
            age: row.age,
            amount: row.amount,
        })
    );
    assert_eq!(loaded.plain.len(), 2348);
    assert_eq!(
        loaded.draft.heads,
        [heads.data().encode(), heads.index().encode()]
    );
    assert_eq!(loaded.draft.packets[0], bundle.data[112..]);
    assert_eq!(loaded.draft.packets[1], bundle.index[112..]);
    loaded.draft.reaudit().unwrap();
}

#[test]
fn fetched_source_requires_independent_pins_key_domain_and_complete_image_tails() {
    let (owner, heads, bundle, object) = stored_originals();
    let (_, other_heads, _, _) = stored_originals();
    let wrong_table = ReadHeads::new(
        TableId::from_bytes([0xc7; 32]).unwrap(),
        heads.data(),
        heads.index(),
        Limits::default(),
    )
    .unwrap();
    let wrong_data_head = ReadHeads::new(
        *heads.table_id(),
        other_heads.data(),
        heads.index(),
        Limits::default(),
    )
    .unwrap();
    let wrong_index_head = ReadHeads::new(
        *heads.table_id(),
        heads.data(),
        other_heads.index(),
        Limits::default(),
    )
    .unwrap();
    let mut wrong_object = object;
    wrong_object[31] ^= 1;
    assert!(matches!(
        owner.load(FetchedSource {
            object: wrong_object,
            bundle: &bundle,
            heads: &heads,
        }),
        Err(crate::Error::InvalidInput(_))
    ));
    for other in [&wrong_data_head, &wrong_index_head, &wrong_table] {
        assert!(
            owner
                .load(FetchedSource {
                    object,
                    bundle: &bundle,
                    heads: other
                })
                .is_err()
        );
    }
    for other in [
        SourceOwner::new(DATABASE, DOMAIN, Zeroizing::new([0x64; 32])).unwrap(),
        SourceOwner::new([0x22; 16], DOMAIN, Zeroizing::new(KEY)).unwrap(),
        SourceOwner::new(DATABASE, [0x43; 16], Zeroizing::new(KEY)).unwrap(),
    ] {
        assert!(matches!(
            other.load(FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads
            }),
            Err(crate::Error::Cryptography(_))
        ));
    }
    for image in 0..2 {
        let mut damaged = bundle.clone();
        let bytes = if image == 0 {
            &mut damaged.data
        } else {
            &mut damaged.index
        };
        *bytes.last_mut().unwrap() ^= 1;
        assert!(matches!(
            owner.load(FetchedSource {
                object,
                bundle: &damaged,
                heads: &heads
            }),
            Err(crate::Error::Cryptography(_))
        ));
    }
    assert!(
        owner
            .load(FetchedSource {
                object,
                bundle: &bundle,
                heads: &heads
            })
            .is_ok()
    );
}

#[test]
fn produce_preflights_actual_custody_before_requiring_a_ready_epoch() {
    let (source, heads, bundle, object) = stored_originals();
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: DATABASE,
                bfv_key_domain: [0xe7; 16],
                epoch: 1,
            },
        )
        .unwrap();
    let mut epoch = handle.proof_epoch(&setup).unwrap();
    let compiled = compiled("SELECT age, amount FROM records WHERE age = 255").unwrap();
    let mut produce = |bundle: &RawBundle, object| {
        source.produce(
            BfvContext {
                owner: &owner,
                setup: &setup,
                anchor: handle.public_anchor(),
            },
            &mut epoch,
            FetchedSource {
                object,
                bundle,
                heads: &heads,
            },
            &compiled,
            [0xf8; 16],
        )
    };

    let mut wrong_object = object;
    wrong_object[0] ^= 1;
    assert!(
        matches!(produce(&bundle, wrong_object), Err(crate::Error::InvalidInput(message))
        if message.contains("independently pinned"))
    );
    let mut damaged = bundle.clone();
    *damaged.index.last_mut().unwrap() ^= 1;
    assert!(matches!(
        produce(&damaged, object),
        Err(crate::Error::Cryptography(_))
    ));
    let mut oversized = bundle.clone();
    oversized.data.push(0);
    assert!(
        matches!(produce(&oversized, object), Err(crate::Error::InvalidInput(message))
        if message.contains("exact canonical N4"))
    );

    // Correct source bytes reach the explicit stage refusal, without a Key proof.
    assert!(
        matches!(produce(&bundle, object), Err(crate::Error::InvalidInput(message))
        if message == "Owner proof epoch must already be Ready")
    );
    assert_eq!(epoch.stage(), ProofEpochStage::AwaitingKey);
}
