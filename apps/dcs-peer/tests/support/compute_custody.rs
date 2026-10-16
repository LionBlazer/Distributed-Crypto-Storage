//! Actual compute RPCs re-audit both complete files before using an installed setup.
use super::*;
use peer_runtime::RemoteError;
use std::io;

fn source(owner: &backend::Owner) -> (RawBundle, compact_query::TableId) {
    let table = owner
        .seal(
            &[
                PlainRow {
                    age: 17,
                    amount: 10,
                },
                PlainRow {
                    age: 18,
                    amount: 20,
                },
                PlainRow {
                    age: 42,
                    amount: 30,
                },
            ],
            1,
            Limits::default(),
        )
        .unwrap();
    let raw = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
    assert_eq!(
        raw.target_version()
            .unwrap()
            .data_head()
            .layout()
            .rows_per_page,
        1
    );
    (raw, *table.table_id())
}

fn assert_remote(error: io::Error, expected: fn(&RemoteError) -> bool) {
    let remote = error.get_ref().and_then(|source| source.downcast_ref());
    assert!(
        remote.is_some_and(expected),
        "Unexpected RPC failure: {error}"
    );
}

#[test]
fn prove_and_evaluate_reject_unrequested_tail_corruption_and_reaudit_exact_repairs() {
    let authority = Authority::new();
    let identity = authority.identity();
    let connector = Connector::new(&identity, &authority.der).unwrap();
    let process = Process::start(&authority, identity.fingerprint(), 1, None);
    let remote = process.remote(&connector);
    // Explicitly non-secret generated fixture. Query results still come from FHE.
    let (owner, public) = backend::Owner::generate(*b"COMPUTE-AUDIT001").unwrap();
    let Response::Setup(setup) = remote
        .call(Request::InstallSetup(
            public.encode_public_setup_for_experiment().unwrap(),
        ))
        .unwrap()
    else {
        panic!("Installed real setup");
    };
    drop(public);
    let (raw, table_id) = source(&owner);
    let version = raw.target_version().unwrap();
    let object = *version.object();
    let table = owner
        .restore_table_for_experiment(
            &raw.data,
            &raw.index,
            &table_id,
            version.data_head(),
            version.index_head(),
            Limits::default(),
        )
        .unwrap();
    remote.call(Request::Store(raw.clone())).unwrap();
    let prepared = owner
        .prepare_provable_select(
            &table,
            AgeRange {
                lower: 18,
                upper: 18,
            }
            .try_into()
            .unwrap(),
            backend::RowProjection::AgeAmount,
            256,
            Limits::default(),
        )
        .unwrap();
    let filename: String = object.iter().map(|byte| format!("{byte:02x}")).collect();
    let path = process.directory.join(filename + ".object2");
    let original = fs::read(&path).unwrap();
    // The last data page is outside the selected age; the index tail contains IDs.
    // Neither may be skipped by compute admission, even after an earlier success.
    let data_tail =
        40 + 34 + 3 * 8 + raw.data_head.len() + raw.index_head.len() + raw.data.len() - 1;
    for offset in [data_tail, original.len() - 1] {
        let mut corrupted = original.clone();
        corrupted[offset] ^= 1;
        fs::write(&path, &corrupted).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), original.len() as u64);
        for prove in [true, false] {
            let make = |setup| {
                if prove {
                    Request::Prove {
                        object,
                        setup,
                        operation: Operation::Select,
                        ciphertext: prepared.request().to_vec(),
                    }
                } else {
                    Request::Evaluate {
                        object,
                        setup,
                        operation: Operation::Select,
                        ciphertext: prepared.request().to_vec(),
                    }
                }
            };
            // Custody precedes even a missing setup; no metadata/cache shortcut.
            for candidate in [setup, [0; 32]] {
                assert_remote(
                    remote
                        .call(make(candidate))
                        .err()
                        .expect("Compute admission must reject this request"),
                    |error| matches!(error, RemoteError::Integrity),
                );
            }
        }
        assert!(
            !remote
                .status()
                .unwrap()
                .objects
                .iter()
                .find(|info| info.id == object)
                .unwrap()
                .available
        );
        fs::write(&path, &original).unwrap();
        let Response::Proved(proved) = remote
            .call(Request::Prove {
                object,
                setup,
                operation: Operation::Select,
                ciphertext: prepared.request().to_vec(),
            })
            .unwrap()
        else {
            panic!("Genuine arithmetic proof");
        };
        owner
            .check_select_proof(
                &table.read_heads(),
                &prepared,
                &proved.output,
                &proved.proof,
            )
            .unwrap();
        assert!(
            remote
                .status()
                .unwrap()
                .objects
                .iter()
                .find(|info| info.id == object)
                .unwrap()
                .available
        );
        let legacy = owner
            .prepare_exact_select_for_experiment(
                &table,
                AgeRange {
                    lower: 18,
                    upper: 18,
                },
                backend::RowProjection::AgeAmount,
                256,
                Limits::default(),
            )
            .unwrap();
        let Response::UnverifiedCiphertext(output) = remote
            .call(Request::Evaluate {
                object,
                setup,
                operation: Operation::Select,
                ciphertext: legacy.request().to_vec(),
            })
            .unwrap()
        else {
            panic!("Legacy encrypted output remains explicitly unverified");
        };
        let rows = owner
            .complete_exact_select_unverified_for_experiment(&table, legacy, &output)
            .unwrap();
        assert_eq!(
            rows.rows
                .iter()
                .map(|row| (row.age, row.amount))
                .collect::<Vec<_>>(),
            vec![(Some(18), Some(20))]
        );
    }
    // Either independently valid custody image must match the request. Custody
    // of a mixed pair alone does not establish the owner's table/index invariant.
    let (other, _) = source(&owner);
    for data in [true, false] {
        let mut mixed = raw.clone();
        mixed.nonce = other.nonce;
        if data {
            mixed.data_head = other.data_head.clone();
            mixed.data = other.data.clone();
        } else {
            mixed.index_head = other.index_head.clone();
            mixed.index = other.index.clone();
        }
        let mixed_object = *mixed.target_version().unwrap().object();
        remote.call(Request::Store(mixed)).unwrap();
        assert_remote(
            remote
                .call(Request::Prove {
                    object: mixed_object,
                    setup,
                    operation: Operation::Select,
                    ciphertext: prepared.request().to_vec(),
                })
                .err()
                .expect("Compute admission must reject this request"),
            |error| matches!(error, RemoteError::Integrity),
        );
        assert!(
            remote
                .status()
                .unwrap()
                .objects
                .iter()
                .find(|info| info.id == mixed_object)
                .unwrap()
                .available
        );
    }
    let Response::Proved(proved) = remote
        .call(Request::Prove {
            object,
            setup,
            operation: Operation::Select,
            ciphertext: prepared.request().to_vec(),
        })
        .unwrap()
    else {
        panic!("Original object remains usable");
    };
    let result = owner
        .complete_proved_select(&table, prepared, &proved.output, &proved.proof)
        .unwrap();
    assert_eq!(
        result
            .rows()
            .iter()
            .map(|row| (row.age, row.amount))
            .collect::<Vec<_>>(),
        vec![(Some(18), Some(20))]
    );
}
