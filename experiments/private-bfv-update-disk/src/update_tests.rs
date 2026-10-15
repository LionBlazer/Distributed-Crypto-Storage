// Included inside update::tests. All rows/contexts are public non-secret fixtures.
use compact_bfv_byte_limb_core::UnverifiedUpdatedValues;
fn memory_fixture(
    data_rows: &[PlainRow],
    index_rows: &[PlainRow],
) -> (disk::CatalogEntry, disk::LoadedTable) {
    let owner = Owner::generate([91; 16]).unwrap();
    let packed: Vec<_> = data_rows
        .iter()
        .flat_map(|r| [r.age, r.amount as u8, (r.amount >> 8) as u8])
        .collect();
    let data = owner
        .seal(
            Layout {
                schema: SCHEMA,
                row_width: 3,
                rows_per_page: PAGE_ROWS as u32,
                row_count: data_rows.len() as u64,
            },
            &packed,
            Limits::default(),
        )
        .unwrap();
    let index = padded_index_codec::build(&owner, index_rows, data.commitment()).unwrap();
    let cached = disk::capture_owner_header(&owner, &index, data.commitment()).unwrap();
    let entry = disk::CatalogEntry {
        id: 0,
        owner,
        data_path: "public-unused-data.bin".into(),
        index_path: "public-unused-index.bin".into(),
        data_head: data.commitment().clone(),
        index_head: index.commitment().clone(),
        data_len: data.encoded_len(),
        index_len: index.encoded_len(),
        cached,
    };
    (
        entry,
        disk::LoadedTable {
            id: 0,
            data,
            index,
            ntt: None,
        },
    )
}
fn values(rows: Vec<UpdatedAmount>) -> UnverifiedUpdateOutcome {
    UnverifiedUpdateOutcome::Values(UnverifiedUpdatedValues {
        rows,
        proof: ProofStatus::Unavailable,
    })
}
#[test]
fn local_oracle_rejects_in_bounds_wrong_amount_missing_rows_and_false_overflow() {
    let fields = [
        SelectedField {
            age: 250,
            amount: 10,
            active: true,
        },
        SelectedField {
            age: 250,
            amount: 20,
            active: true,
        },
    ];
    assert!(
        check_answer(
            &fields,
            1,
            values(vec![
                UpdatedAmount {
                    slot: 0,
                    amount: 10,
                    low_limb_sum: 10,
                    high_limb_sum: 0
                },
                UpdatedAmount {
                    slot: 1,
                    amount: 21,
                    low_limb_sum: 21,
                    high_limb_sum: 0
                }
            ])
        )
        .is_err()
    );
    assert!(
        check_answer(
            &fields,
            1,
            values(vec![UpdatedAmount {
                slot: 0,
                amount: 11,
                low_limb_sum: 11,
                high_limb_sum: 0
            }])
        )
        .is_err()
    );
    assert!(
        check_answer(
            &fields,
            1,
            UnverifiedUpdateOutcome::Overflow {
                proof: ProofStatus::Unavailable
            }
        )
        .is_err()
    );
    let overflow = [SelectedField {
        age: 250,
        amount: 65535,
        active: true,
    }];
    assert!(
        check_answer(
            &overflow,
            1,
            values(vec![UpdatedAmount {
                slot: 0,
                amount: 0,
                low_limb_sum: 0,
                high_limb_sum: 0
            }])
        )
        .is_err()
    );
    assert!(
        check_answer(
            &overflow,
            1,
            UnverifiedUpdateOutcome::Overflow {
                proof: ProofStatus::Unavailable
            }
        )
        .unwrap()
        .is_none()
    );
}
#[test]
fn compact_staging_preserves_all_index_suffix_plaintext_and_live_snapshot_until_publication() {
    let fields = [
        PlainRow {
            age: 250,
            amount: 255,
        },
        PlainRow {
            age: 250,
            amount: 256,
        },
        PlainRow {
            age: 249,
            amount: 65535,
        },
    ];
    let (entry, loaded) = memory_fixture(&fields, &fields);
    let original_data = loaded.data.encode();
    let original_index = loaded.index.encode();
    let page = loaded.data.lookup(0, Limits::default()).unwrap();
    let page = page.verify(&entry.data_head, 0, Limits::default()).unwrap();
    let old_nonce = page.nonce();
    let input = selection::Selection {
        selected: vec![0, 1],
        fields: fields
            .iter()
            .take(2)
            .map(|f| SelectedField {
                age: f.age,
                amount: f.amount,
                active: true,
            })
            .collect(),
        page: Some(0),
        plaintext: Some(entry.owner.decrypt(&page).unwrap()),
    };
    let rows = vec![
        UpdatedAmount {
            slot: 0,
            amount: 256,
            low_limb_sum: 256,
            high_limb_sum: 0,
        },
        UpdatedAmount {
            slot: 1,
            amount: 257,
            low_limb_sum: 1,
            high_limb_sum: 1,
        },
    ];
    let staged = stage(&entry, &loaded, &input, &rows).unwrap();
    assert_eq!(loaded.data.encode(), original_data);
    assert_eq!(loaded.index.encode(), original_index);
    assert_ne!(staged.data.commitment(), &entry.data_head);
    assert_ne!(staged.index.commitment(), &entry.index_head);
    let new_page = staged.data.lookup(0, Limits::default()).unwrap();
    let new_page = new_page
        .verify(staged.data.commitment(), 0, Limits::default())
        .unwrap();
    assert_ne!(new_page.nonce(), old_nonce);
    assert_eq!(
        entry.owner.decrypt(&new_page).unwrap().as_bytes(),
        &[250, 0, 1, 250, 1, 1, 249, 255, 255]
    );
    let old = loaded
        .index
        .lookup(0, padded_index_codec::index_limits())
        .unwrap();
    let old = old
        .verify(&entry.index_head, 0, padded_index_codec::index_limits())
        .unwrap();
    let old = entry.owner.decrypt(&old).unwrap();
    let new = staged
        .index
        .lookup(0, padded_index_codec::index_limits())
        .unwrap();
    let new = new
        .verify(
            staged.index.commitment(),
            0,
            padded_index_codec::index_limits(),
        )
        .unwrap();
    let new = entry.owner.decrypt(&new).unwrap();
    assert_eq!(&old.as_bytes()[112..], &new.as_bytes()[112..]);
    assert_eq!(&new.as_bytes()[..112], &staged.data.commitment().encode());
    assert!(
        staged
            .cached
            .restore(staged.data.commitment(), staged.index.commitment())
            .is_ok()
    );
    assert!(
        staged
            .cached
            .restore(&entry.data_head, &entry.index_head)
            .is_err()
    );
}
#[test]
fn authenticated_semantically_wrong_index_rejects_update_selection_before_fhe_but_preserves_full_read_path()
 {
    let rows = [
        PlainRow {
            age: 250,
            amount: 10,
        },
        PlainRow {
            age: 249,
            amount: 20,
        },
    ];
    let wrong = [
        PlainRow {
            age: 250,
            amount: 10,
        },
        PlainRow {
            age: 250,
            amount: 20,
        },
    ];
    let (entry, loaded) = memory_fixture(&rows, &wrong);
    let params = spiral_owner_state::profile_params();
    let mut client = Client::init(&params);
    let public = client.generate_keys();
    let pir = Pir {
        params: &params,
        client: &client,
        public: &public,
    };
    let (bfv, setup) = BfvOwner::generate(Geometry::Rows256).unwrap();
    let evaluator = PeerEvaluator::from_public_setup(&setup).unwrap();
    let count = Cell::new(0);
    let data = Store {
        id: 0,
        snapshot: &loaded.data,
        head: &entry.data_head,
        db: None,
        limits: Limits::default(),
    };
    let index = Store {
        id: 1,
        snapshot: &loaded.index,
        head: &entry.index_head,
        db: None,
        limits: padded_index_codec::index_limits(),
    };
    let session = Session {
        owner: &entry.owner,
        bfv: &bfv,
        evaluator: &evaluator,
        pir: &pir,
        data: &data,
        index: &index,
        cached: &entry.cached,
        preparations: &count,
        replacement_wire: None,
    };
    let plan = Plan {
        kernel: KernelMode::ExactIndex,
        access: Access::Visible,
        profile: Profile::Fixed256,
        header: HeaderMode::Uncached,
        query: QuerySpec::Equal(250),
        query_id: [1; 16],
    };
    assert!(selection::select(plan, &session, &mut Stages::default()).is_err());
    assert_eq!(count.get(), 0);
    let full = read(
        Plan {
            kernel: KernelMode::FullPredicate,
            ..plan
        },
        &session,
    )
    .unwrap();
    assert_eq!((full.actual.count, full.actual.sum), (1, 10));
    assert_eq!(count.get(), 1);
}
#[test]
fn stale_context_is_rejected_before_staging_against_new_trusted_head() {
    let rows = [PlainRow {
        age: 250,
        amount: 10,
    }];
    let (mut entry, mut loaded) = memory_fixture(&rows, &rows);
    let context = QueryContext::new([1; 16], entry.data_head.encode(), entry.index_head.encode());
    entry.data_head = entry
        .owner
        .replace_page(
            &mut loaded.data,
            &entry.data_head,
            0,
            &[250, 11, 0],
            Limits::default(),
        )
        .unwrap();
    assert!(current_context(&context, &entry).is_err());
}
struct OwnedTestDirectory(std::path::PathBuf);
impl OwnedTestDirectory {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "public-bfv-update-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for OwnedTestDirectory {
    fn drop(&mut self) {
        for name in ["data.bin", "index.bin", "catalog.jsonl"] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(self.0.join("fail-index"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
#[test]
fn partial_index_write_failure_invalidates_cache_aborts_and_does_not_publish_trusted_heads() {
    let directory = OwnedTestDirectory::new();
    let rows = [PlainRow {
        age: 250,
        amount: 10,
    }];
    let (mut entry, loaded) = memory_fixture(&rows, &rows);
    entry.data_path = directory.0.join("data.bin");
    entry.index_path = directory.0.join("index.bin");
    disk::write_new(&entry.data_path, &loaded.data.encode()).unwrap();
    disk::write_new(&entry.index_path, &loaded.index.encode()).unwrap();
    let old_data = entry.data_head.clone();
    let old_index = entry.index_head.clone();
    let mut catalog = vec![entry];
    disk::persist_catalog(&directory.0, &catalog).unwrap();
    let mut loader = disk::Loader::new(1).unwrap();
    loader.current = Some(loaded);
    let fail = directory.0.join("fail-index");
    std::fs::create_dir(&fail).unwrap();
    catalog[0].index_path = fail;
    let params = spiral_owner_state::profile_params();
    let mut client = Client::init(&params);
    let public = client.generate_keys();
    let pir = Pir {
        params: &params,
        client: &client,
        public: &public,
    };
    let (bfv, setup) = BfvOwner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let preparations = Cell::new(0);
    let diagnostic_preparations = Cell::new(0);
    let env = Environment {
        directory: &directory.0,
        bfv: &bfv,
        evaluator: &peer,
        pir: &pir,
        preparations: &preparations,
        diagnostic_preparations: &diagnostic_preparations,
    };
    let plan = Plan {
        kernel: KernelMode::ExactIndex,
        access: Access::Visible,
        profile: Profile::Fixed256,
        header: HeaderMode::Cached,
        query: QuerySpec::Equal(250),
        query_id: [1; 16],
    };
    let error = execute(
        &mut catalog,
        &mut loader,
        0,
        plan,
        1,
        &env,
        OutputMode::Honest,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("Partial disk write possible"));
    assert!(loader.current.is_none());
    assert_eq!(catalog[0].data_head, old_data);
    assert_eq!(catalog[0].index_head, old_index);
    assert_eq!(preparations.get(), 1);
    let partial = EncryptedSnapshot::decode(
        &std::fs::read(&catalog[0].data_path).unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_ne!(
        partial.commitment(),
        &old_data,
        "Document actual partial I/O rather than assert rollback"
    );
}

#[test]
fn successful_visible_update_commits_both_heads_reopens_and_rejects_old_output_with_same_query_id()
{
    let directory = OwnedTestDirectory::new();
    let rows = [
        PlainRow {
            age: 250,
            amount: 255,
        },
        PlainRow {
            age: 250,
            amount: 256,
        },
        PlainRow {
            age: 249,
            amount: 65535,
        },
    ];
    let (mut entry, loaded) = memory_fixture(&rows, &rows);
    entry.data_path = directory.0.join("data.bin");
    entry.index_path = directory.0.join("index.bin");
    disk::write_new(&entry.data_path, &loaded.data.encode()).unwrap();
    disk::write_new(&entry.index_path, &loaded.index.encode()).unwrap();
    let old_data = entry.data_head.clone();
    let old_index = entry.index_head.clone();
    let mut catalog = vec![entry];
    disk::persist_catalog(&directory.0, &catalog).unwrap();
    let mut loader = disk::Loader::new(1).unwrap();
    let params = spiral_owner_state::profile_params();
    let mut client = Client::init(&params);
    let public = client.generate_keys();
    let pir = Pir {
        params: &params,
        client: &client,
        public: &public,
    };
    let (bfv, setup) = BfvOwner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let preparations = Cell::new(0);
    let diagnostic_preparations = Cell::new(0);
    let env = Environment {
        directory: &directory.0,
        bfv: &bfv,
        evaluator: &peer,
        pir: &pir,
        preparations: &preparations,
        diagnostic_preparations: &diagnostic_preparations,
    };
    let plan = Plan {
        kernel: KernelMode::ExactIndex,
        access: Access::Visible,
        profile: Profile::Fixed256,
        header: HeaderMode::Uncached,
        query: QuerySpec::Equal(250),
        query_id: [1; 16],
    };
    let operation = execute(
        &mut catalog,
        &mut loader,
        0,
        plan,
        1,
        &env,
        OutputMode::Honest,
    )
    .unwrap();
    assert!(operation.committed);
    assert_eq!(operation.selected, 2);
    assert_eq!(operation.input_amounts, vec![255, 256]);
    let updated: Vec<_> = operation
        .output_rows
        .unwrap()
        .into_iter()
        .map(|r| r.amount)
        .collect();
    assert_eq!(updated, vec![256, 257]);
    assert_ne!(catalog[0].data_head, old_data);
    assert_ne!(catalog[0].index_head, old_index);
    assert_eq!(preparations.get(), 2);
    assert_eq!(diagnostic_preparations.get(), 1);
    assert_eq!(operation.stages.readiness.unwrap().event, "TableMiss");
    assert_eq!(loader.counters.invalidations, 1);
    let reopened = loader.current.as_ref().unwrap();
    assert_eq!(reopened.data.commitment(), &catalog[0].data_head);
    assert_eq!(reopened.index.commitment(), &catalog[0].index_head);
    let page = reopened.data.lookup(0, Limits::default()).unwrap();
    let page = page
        .verify(&catalog[0].data_head, 0, Limits::default())
        .unwrap();
    assert_eq!(
        catalog[0].owner.decrypt(&page).unwrap().as_bytes(),
        &[250, 0, 1, 250, 1, 1, 249, 255, 255]
    );
}

#[test]
fn public_echo_wire_after_genuine_peer_addition_is_decryptable_but_never_authorizes_writeback() {
    let (owner, setup) = BfvOwner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = [SelectedField {
        age: 250,
        amount: 10,
        active: true,
    }];
    let prepared = owner
        .prepare_indexed_update_for_experiment(
            QueryContext::new([1; 16], [2; 112], [3; 112]),
            &fields,
            1,
        )
        .unwrap();
    let honest = peer.evaluate_indexed_update(&prepared.request).unwrap();
    assert_eq!(honest.stats.ciphertext_additions, 1);
    let forged = update_controls::public_echo(&prepared.request).unwrap();
    let decoded = owner
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &forged)
        .unwrap();
    assert!(check_answer(&fields, 1, decoded).is_err());
}
