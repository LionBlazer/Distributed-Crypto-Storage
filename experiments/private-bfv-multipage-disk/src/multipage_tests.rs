//! Public fixtures; actual compact authentication, callback boundaries and genuine PIR/BFV.
use super::*;

fn seal_rows(owner: &Owner, rows: &[PlainRow]) -> EncryptedSnapshot {
    let packed: Vec<_> = rows
        .iter()
        .flat_map(|r| [r.age, r.amount as u8, (r.amount >> 8) as u8])
        .collect();
    owner
        .seal(
            Layout {
                schema: SCHEMA,
                row_width: ROW_BYTES,
                rows_per_page: PAGE_ROWS as u32,
                row_count: rows.len() as u64,
            },
            &packed,
            Limits::default(),
        )
        .unwrap()
}
struct Recording<'a> {
    image: &'a EncryptedSnapshot,
    calls: RefCell<Vec<u64>>,
    replacement: Option<(u64, &'a [u8])>,
}
impl PageSource for Recording<'_> {
    fn commitment(&self) -> &Commitment {
        self.image.commitment()
    }
    fn lookup_wire(&self, page: u64, limits: Limits) -> IndexResult<Vec<u8>> {
        self.calls.borrow_mut().push(page);
        if let Some((target, wire)) = self.replacement
            && target == page
        {
            return Ok(wire.to_vec());
        }
        Ok(self.image.lookup(page, limits)?.encode())
    }
}
fn decoded_selection(
    owner: &Owner,
    image: &dyn PageSource,
    data: &Commitment,
    query: QuerySpec,
) -> IndexResult<Vec<u64>> {
    let header = padded_index_codec::check_binding(owner, image, data)?;
    let (counts, offsets) = header.metadata();
    posting_page_preflight(&header, query.selection_range()?)?;
    padded_index_codec::select_from_header(
        owner,
        image,
        data,
        query.selection_range()?,
        256,
        &mut 0,
        IndexHeader::from_cached(counts, offsets),
    )
}

#[test]
fn honest_two_byte_varints_cross_both_page_boundaries_and_keep_all256_ordinals() {
    let owner = Owner::generate([81; 16]).unwrap();
    let rows = public_rows(12_000, 0);
    let data = seal_rows(&owner, &rows);
    let index = padded_index_codec::build(&owner, &rows, data.commitment()).unwrap();
    let header = padded_index_codec::check_binding(&owner, &index, data.commitment()).unwrap();
    let (_, offsets) = header.metadata();
    assert_eq!(INDEX_HEADER_BYTES + offsets[230] as usize, 4095);
    assert_eq!(INDEX_HEADER_BYTES + offsets[250] as usize, 8191);
    let plain = |page| {
        let wire = index
            .lookup(page, padded_index_codec::index_limits())
            .unwrap();
        let verified = wire
            .verify(index.commitment(), page, padded_index_codec::index_limits())
            .unwrap();
        owner.decrypt(&verified).unwrap()
    };
    assert_eq!(
        (plain(0).as_bytes()[4095], plain(1).as_bytes()[0]),
        (0x8b, 0x0f)
    );
    assert_eq!(
        (plain(1).as_bytes()[4095], plain(2).as_bytes()[0]),
        (0x89, 0x2f)
    );
    for (query, expected, pages) in [
        (
            QuerySpec::Equal(230),
            (1931..=2186).collect::<Vec<u64>>(),
            vec![0, 1],
        ),
        (
            QuerySpec::ClosedRange {
                lower: 250,
                upper: 251,
            },
            (6025..=6280).collect(),
            vec![1, 2],
        ),
    ] {
        let source = Recording {
            image: &index,
            calls: RefCell::default(),
            replacement: None,
        };
        assert_eq!(
            decoded_selection(&owner, &source, data.commitment(), query).unwrap(),
            expected
        );
        // First0 is the header. Subsequent calls are real posting pages, not reused header bytes.
        assert_eq!(&source.calls.borrow()[1..], pages);
        assert_eq!(data_page_preflight(&expected).unwrap().len(), 2);
    }
}

#[test]
fn corrupt_wrong_page_and_stale_second_posting_never_return_a_partial_selection() {
    let owner = Owner::generate([82; 16]).unwrap();
    let rows = public_rows(12_000, 1);
    let data = seal_rows(&owner, &rows);
    let index = padded_index_codec::build(&owner, &rows, data.commitment()).unwrap();
    let old = index
        .lookup(1, padded_index_codec::index_limits())
        .unwrap()
        .encode();
    let wrong = index
        .lookup(0, padded_index_codec::index_limits())
        .unwrap()
        .encode();
    let mut corrupt = old.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for wire in [&wrong, &corrupt] {
        let source = Recording {
            image: &index,
            calls: RefCell::default(),
            replacement: Some((1, wire)),
        };
        assert!(
            decoded_selection(&owner, &source, data.commitment(), QuerySpec::Equal(230)).is_err()
        );
        assert_eq!(*source.calls.borrow(), [0, 0, 1]);
    }
    let mut current = index.clone();
    let verified = index
        .lookup(1, padded_index_codec::index_limits())
        .unwrap()
        .verify(index.commitment(), 1, padded_index_codec::index_limits())
        .unwrap();
    let bytes = owner.decrypt(&verified).unwrap();
    let expected = current.commitment().clone();
    owner
        .replace_page(
            &mut current,
            &expected,
            1,
            bytes.as_bytes(),
            padded_index_codec::index_limits(),
        )
        .unwrap();
    let source = Recording {
        image: &current,
        calls: RefCell::default(),
        replacement: Some((1, &old)),
    };
    assert!(decoded_selection(&owner, &source, data.commitment(), QuerySpec::Equal(230)).is_err());
    assert_eq!(*source.calls.borrow(), [0, 0, 1]);
}

#[test]
fn full_visible_private_paths_keep_fixed_dummy_shape_and_fail_before_bfv_on_bad_inputs() {
    native::configure("combined").unwrap();
    let params = spiral_owner_state::profile_params();
    let mut client = Client::init(&params);
    let public = client.generate_keys();
    let pir = Pir {
        params: &params,
        client: &client,
        public: &public,
    };
    let owner = Owner::generate([83; 16]).unwrap();
    let rows = public_rows(12_000, 0);
    let data = seal_rows(&owner, &rows);
    let index = padded_index_codec::build(&owner, &rows, data.commitment()).unwrap();
    let cached = disk::capture_owner_header(&owner, &index, data.commitment()).unwrap();
    let pair = native::prepare_pair(&data, &index, &params).unwrap();
    let data_store = Store {
        id: 0,
        snapshot: &data,
        head: data.commitment(),
        db: Some(&pair.data),
        limits: Limits::default(),
    };
    let index_store = Store {
        id: 1,
        snapshot: &index,
        head: index.commitment(),
        db: Some(&pair.index),
        limits: padded_index_codec::index_limits(),
    };
    let (bfv, setup) = BfvOwner::generate(Geometry::Rows256).unwrap();
    let evaluator = PeerEvaluator::from_public_setup(&setup).unwrap();
    let preparations = Cell::new(0);
    let session = Session {
        owner: &owner,
        bfv: &bfv,
        evaluator: &evaluator,
        pir: &pir,
        data: &data_store,
        index: &index_store,
        cached: &cached,
        preparations: &preparations,
        replacement_wire: None,
    };
    for access in [Access::Visible, Access::Private] {
        for profile in [Profile::AddressOnly, Profile::Fixed256] {
            for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                for query in [
                    QuerySpec::Equal(230),
                    QuerySpec::ClosedRange {
                        lower: 250,
                        upper: 251,
                    },
                    QuerySpec::Equal(245),
                    QuerySpec::Equal(247),
                ] {
                    let result = read(
                        Plan {
                            kernel: KernelMode::ExactIndex,
                            access,
                            profile,
                            header,
                            query,
                            query_id: nonce().unwrap(),
                        },
                        &session,
                    )
                    .unwrap();
                    let expected: Vec<_> = rows
                        .iter()
                        .enumerate()
                        .filter(|(_, row)| query.contains(row.age))
                        .collect();
                    assert_eq!(result.actual.count as usize, expected.len());
                    assert_eq!(
                        result.actual.sum,
                        expected
                            .iter()
                            .map(|(_, row)| u32::from(row.amount))
                            .sum::<u32>()
                    );
                    assert_eq!(
                        result.selected,
                        expected.iter().map(|(i, _)| *i as u64).collect::<Vec<_>>()
                    );
                    assert_eq!(
                        result.actual.proof,
                        compact_bfv_byte_limb_core::ProofStatus::Unavailable
                    );
                    let stages = result.stages;
                    if matches!(profile, Profile::Fixed256) {
                        assert_eq!((stages.posting.calls, stages.data.calls), (2, 2));
                    }
                    if matches!(
                        query,
                        QuerySpec::Equal(230)
                            | QuerySpec::ClosedRange {
                                lower: 250,
                                upper: 251
                            }
                    ) {
                        assert_eq!((stages.real_posting_pages, stages.real_data_pages), (2, 2));
                    }
                    assert_eq!(
                        stages.posting.calls,
                        stages.real_posting_pages + stages.dummy_posting_fetches
                    );
                    assert_eq!(
                        stages.data.calls,
                        stages.real_data_pages + stages.dummy_data_fetches
                    );
                    if matches!(access, Access::Private) {
                        assert_eq!(
                            stages.posting.request_bytes,
                            stages.posting.calls * (params.query_bytes() + 33)
                        );
                        assert_eq!(
                            stages.data.request_bytes,
                            stages.data.calls * (params.query_bytes() + 33)
                        );
                    }
                }
                let before = preparations.get();
                for query in [QuerySpec::Equal(249), QuerySpec::Equal(240)] {
                    assert!(
                        read(
                            Plan {
                                kernel: KernelMode::ExactIndex,
                                access,
                                profile,
                                header,
                                query,
                                query_id: nonce().unwrap()
                            },
                            &session
                        )
                        .is_err()
                    );
                    assert_eq!(preparations.get(), before);
                }
            }
        }
    }
    // The actual transport wrapper rejects a third distinct page BEFORE sending it.
    let source = source(Access::Private, &index_store, &pir);
    drop(source.plain(&owner, 0).unwrap());
    drop(source.plain(&owner, 1).unwrap());
    assert!(source.fetch(2).is_err());
    assert_eq!(source.stats.borrow().calls, 2);
    let old_index_head = index.commitment().clone();
    let mut changed = index.clone();
    let verified = changed
        .lookup(1, padded_index_codec::index_limits())
        .unwrap()
        .verify(&old_index_head, 1, padded_index_codec::index_limits())
        .unwrap();
    let bytes = owner.decrypt(&verified).unwrap();
    owner
        .replace_page(
            &mut changed,
            &old_index_head,
            1,
            bytes.as_bytes(),
            padded_index_codec::index_limits(),
        )
        .unwrap();
    assert!(
        cached
            .restore(data.commitment(), changed.commitment())
            .is_err()
    );
    let changed_store = Store {
        id: 1,
        snapshot: &changed,
        head: changed.commitment(),
        db: None,
        limits: padded_index_codec::index_limits(),
    };
    let before = preparations.get();
    let stale_header = Session {
        index: &changed_store,
        ..session
    };
    let stale_plan = Plan {
        kernel: KernelMode::ExactIndex,
        access: Access::Visible,
        profile: Profile::Fixed256,
        header: HeaderMode::Cached,
        query: QuerySpec::Equal(230),
        query_id: nonce().unwrap(),
    };
    assert!(read(stale_plan, &stale_header).is_err());
    assert_eq!(preparations.get(), before);
    let current_header = disk::capture_owner_header(&owner, &changed, data.commitment()).unwrap();
    let old_wire = index
        .lookup(1, padded_index_codec::index_limits())
        .unwrap()
        .encode();
    let stale_second_page = Session {
        index: &changed_store,
        cached: &current_header,
        replacement_wire: Some((1, 1, &old_wire)),
        ..session
    };
    assert!(read(stale_plan, &stale_second_page).is_err());
    assert_eq!(preparations.get(), before);
    let mut wrong_rows = rows.clone();
    wrong_rows[1931].age = 231;
    let wrong_index = padded_index_codec::build(&owner, &wrong_rows, data.commitment()).unwrap();
    let wrong_header = disk::capture_owner_header(&owner, &wrong_index, data.commitment()).unwrap();
    let wrong_store = Store {
        id: 1,
        snapshot: &wrong_index,
        head: wrong_index.commitment(),
        db: None,
        limits: padded_index_codec::index_limits(),
    };
    let bad = Session {
        index: &wrong_store,
        cached: &wrong_header,
        ..session
    };
    let before = preparations.get();
    assert!(
        read(
            Plan {
                kernel: KernelMode::ExactIndex,
                access: Access::Visible,
                profile: Profile::AddressOnly,
                header: HeaderMode::Cached,
                query: QuerySpec::Equal(231),
                query_id: nonce().unwrap()
            },
            &bad
        )
        .is_err()
    );
    assert_eq!(preparations.get(), before);
}
