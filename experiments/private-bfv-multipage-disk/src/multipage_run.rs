use super::*;
pub(super) fn run() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|v| v == "counter-diagnostic") {
        for round in 0..8 {
            let begin = Instant::now();
            let full = resources::sample();
            let full_ms = ms(begin);
            let begin = Instant::now();
            let memory = resources::memory_sample();
            let memory_ms = ms(begin);
            println!(
                "{}",
                json!({"experiment":"disk-counter-cost","round":round,
                "full_sample_ms":full_ms,"memory_only_sample_ms":memory_ms,
                "full":full,"memory_only":memory})
            );
        }
        return Ok(());
    }
    let count: usize = args.get(1).map(|v| v.parse()).transpose()?.unwrap_or(3);
    let samples: usize = args.get(2).map(|v| v.parse()).transpose()?.unwrap_or(1);
    let threads: usize = args.get(3).map(|v| v.parse()).transpose()?.unwrap_or(8);
    let ids: Vec<usize> = args
        .get(4)
        .map(String::as_str)
        .unwrap_or("0,1,2")
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let budget: u64 = args
        .get(5)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(64 * 1024 * 1024);
    let directory =
        std::path::PathBuf::from(args.get(6).ok_or("Supply new ignored dataset directory")?);
    native::configure(args.get(7).map(String::as_str).unwrap_or("combined"))?;
    if !(3..=2000).contains(&count)
        || !(1..=2).contains(&samples)
        || !(1..=8).contains(&threads)
        || ids.len() < 2
        || ids.iter().any(|id| *id >= count)
        || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
    {
        return Err("Invalid bounded disk experiment arguments".into());
    }
    if (count as u64)
        .checked_mul(6 * 1024 * 1024)
        .is_none_or(|v| v > budget)
    {
        return Err("Dataset preflight rejected before any canonical write".into());
    }
    std::fs::create_dir(&directory)?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let monitor = resources::Monitor::start(disk::MEMORY_LIMIT);
    let setup = Instant::now();
    let params = spiral_owner_state::profile_params();
    let key_start = Instant::now();
    let original = spiral_owner_state::OwnerState::generate(&params, [0x44; 32])?;
    let image = original.owner.encode_secret_for_experiment();
    let pir_wire_bytes = original.public_wire.len();
    disk::write_new(
        &directory.join("shared-pir-public.bin"),
        &original.public_wire,
    )?;
    let restored = spiral_owner_state::OwnerState::restore(
        &params,
        [0x44; 32],
        image.as_ref(),
        &original.public_wire,
    )?;
    drop(image);
    drop(original);
    let _pir_owner = restored.owner;
    let pir_client = restored.client;
    let pir_public = restored.public;
    let pir_restore_ms = ms(key_start);
    let pir_public_ram: usize = pir_public
        .v_packing
        .iter()
        .chain(pir_public.v_expansion_left.iter().flatten())
        .chain(pir_public.v_expansion_right.iter().flatten())
        .chain(pir_public.v_conversion.iter().flatten())
        .map(|m| m.data.len() * 8)
        .sum();
    let key_start = Instant::now();
    let (bfv_owner, public_setup) = BfvOwner::generate(Geometry::Rows256)?;
    let bfv_secret_count = bfv_owner.secret_key_serialized_bytes();
    let bfv_keygen_ms = ms(key_start);
    let bfv_counts = public_setup.byte_counts()?;
    let bfv_wire = public_setup.to_bytes()?;
    let bfv_wire_bytes = bfv_wire.len();
    disk::write_new(&directory.join("shared-bfv-public.bin"), &bfv_wire)?;
    drop(public_setup);
    let key_start = Instant::now();
    let public_setup = PublicSetup::from_bytes(&bfv_wire)?;
    drop(bfv_wire);
    let evaluator = PeerEvaluator::from_public_setup(&public_setup)?;
    drop(public_setup);
    runtime_profile_gate(&bfv_owner, &evaluator)?;
    let bfv_restore_ms = ms(key_start);
    let pir = Pir {
        params: &params,
        client: &pir_client,
        public: &pir_public,
    };
    let catalog = disk::build_catalog(&directory, count, budget)?;
    let mut loader = disk::Loader::new(1)?;
    let shared = SharedBytes {
        public_wire: pir_wire_bytes + bfv_wire_bytes,
        owner_counts: spiral_owner_state::OWNER_STATE_BYTES + bfv_secret_count,
        pir_public_ram,
    };
    println!(
        "{}",
        json!({
         "experiment":"multipage-setup","experiment_package":"private-bfv-multipage-disk","same_full_keyset":true,"new_fixed256_schedule":"2posting+2data+optional_header","fresh_new_generation_only":true,"baseline_main_sha256":"D5D8F003BA3CB4606994237DFEEBAF5C2613F795BE33229C9519A5D3114BBC07",
         "tables":count,"supplied_table_ids":ids,"max_canonical_bytes":budget,"samples":samples,
         "bfv_profile":bfv_owner.profile(),"bfv_public_bytes":bfv_counts,
         "bfv_secret_serialized_count":bfv_secret_count,"pir_owner_image_bytes":spiral_owner_state::OWNER_STATE_BYTES,
         "pir_public_wire_bytes":pir_wire_bytes,"bfv_keygen_ms":bfv_keygen_ms,
         "bfv_public_restore_ms":bfv_restore_ms,"pir_setup_restore_ms":pir_restore_ms,
         "setup_ms":ms(setup),"initial_loaded_tables":0,"setup_private_cache_preparations":0,
         "accounting":disk_accounting(&directory,&catalog,&loader,shared)?,
         "rayon_threads":threads,"maximum_sampled_threads":monitor.maximum_sampled_threads(),
         "server_schedule":native::name(),"cache_backend":"spiral-cache-core/pinned-parallel-trials","owner_online":true,"network_measured":false,"durable_fsync":false,"computation_proof":false,
        })
    );
    let preparations = Cell::new(0);
    let mut previous = HashMap::<(usize, &'static str), [u8; 32]>::new();
    let mut shapes = HashMap::<String, (usize, usize, usize)>::new();
    for sample in 0..samples {
        for case in CASES {
            for profile in [Profile::AddressOnly, Profile::Fixed256] {
                for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                    let accesses = if sample.is_multiple_of(2) {
                        [Access::Private, Access::Visible]
                    } else {
                        [Access::Visible, Access::Private]
                    };
                    for access in accesses {
                        for &id in &ids {
                            for repeat in 0..2 {
                                // Distinct IDs preserve a true capacity-one miss followed by hit.
                                let result = loader.execute(
                                    &catalog[id],
                                    Plan {
                                        kernel: KernelMode::ExactIndex,
                                        access,
                                        profile,
                                        header,
                                        query: case.query,
                                        query_id: nonce()?,
                                    },
                                    &bfv_owner,
                                    &evaluator,
                                    &pir,
                                    &preparations,
                                )?;
                                assert_eq!(
                                    result.load.event,
                                    if repeat == 0 { "TableMiss" } else { "TableHit" }
                                );
                                let (ordinals, sum) = oracle(id, case.query); // Public fixture oracle AFTER timer.
                                assert_eq!(ordinals.len(), case.count);
                                assert_eq!(result.query.selected, ordinals);
                                assert_eq!(
                                    (result.query.actual.count, result.query.actual.sum),
                                    (case.count as u32, sum)
                                );
                                assert_eq!(
                                    result.query.actual.proof,
                                    compact_bfv_byte_limb_core::ProofStatus::Unavailable
                                );
                                let fingerprint: [u8; 32] =
                                    sha2::Sha256::digest(&result.query.ciphertext_payload).into();
                                if let Some(old) = previous.insert((id, case.name), fingerprint) {
                                    assert_ne!(old, fingerprint);
                                }
                                let stages = &result.query.stages;
                                assert_eq!(
                                    stages.posting.calls,
                                    stages.real_posting_pages + stages.dummy_posting_fetches
                                );
                                assert_eq!(
                                    stages.data.calls,
                                    stages.real_data_pages + stages.dummy_data_fetches
                                );
                                if case.name == "eq256_two_posting_two_data"
                                    || case.name == "range256_two_posting_two_data"
                                {
                                    assert_eq!(
                                        (stages.real_posting_pages, stages.real_data_pages),
                                        (2, 2)
                                    );
                                }
                                let requests = stages.header.request_bytes
                                    + stages.posting.request_bytes
                                    + stages.data.request_bytes
                                    + stages.bfv_request_bytes;
                                let responses = stages.header.response_bytes
                                    + stages.posting.response_bytes
                                    + stages.data.response_bytes
                                    + stages.bfv_response_bytes;
                                let rpcs = stages.header.calls
                                    + stages.posting.calls
                                    + stages.data.calls
                                    + 1;
                                if matches!(profile, Profile::Fixed256) {
                                    assert_eq!((stages.posting.calls, stages.data.calls), (2, 2));
                                    let key = format!("{access:?}/{header:?}");
                                    if let Some(old) =
                                        shapes.insert(key, (requests, responses, rpcs))
                                    {
                                        assert_eq!(
                                            old,
                                            (requests, responses, rpcs),
                                            "NEW Fixed256 shape varies across cardinalities"
                                        );
                                    }
                                }
                                println!(
                                    "{}",
                                    json!({"experiment":"multipage-read","sample":sample,"case":case.name,"public_query_kind":case.query.kind(),
                                    "table_id":id,"access":format!("{access:?}"),"profile":format!("{profile:?}"),"header":format!("{header:?}"),"repeat":repeat,
                                    "whole_local_ms":result.whole_ms,"query_only_nested_ms":result.query.total_ms,"load":result.load,
                                    "query_stages":result.query.stages,"aggregate":result.query.actual,"correct":true,"fresh_ciphertexts":true,
                                    "request_bytes":requests,"response_bytes":responses,"wire_bytes":requests+responses,"sequential_rpcs":rpcs,
                                    "loader":loader.ledger(),"resources":resources::sample(),"maximum_sampled_threads":monitor.maximum_sampled_threads(),
                                    "new_fixed_schedule":"2posting+2data+optional_header","public_fixture_only":true,
                                    "application_cache_miss_not_physical_cold_guarantee":true,"network_measured":false,"computation_proof":false})
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    let environment = ControlEnvironment {
        bfv: &bfv_owner,
        evaluator: &evaluator,
        pir: &pir,
        preparations: &preparations,
    };
    let rejections = reject_controls(&catalog, &mut loader, ids[0], ids[1], &environment)?;
    // Retained genuine encrypted-predicate arithmetic control, separate from exact-index timings.
    let full = loader.execute(
        &catalog[ids[0]],
        Plan {
            kernel: KernelMode::FullPredicate,
            access: Access::Visible,
            profile: Profile::Fixed256,
            header: HeaderMode::Cached,
            query: QuerySpec::Equal(246),
            query_id: nonce()?,
        },
        &bfv_owner,
        &evaluator,
        &pir,
        &preparations,
    )?;
    assert_eq!(
        (full.query.actual.count, full.query.actual.sum),
        (1, 100 + (ids[0] % 1000) as u32)
    );
    println!(
        "{}",
        json!({"experiment":"multipage-full-predicate-control","whole_local_ms":full.whole_ms,"load":full.load,"stages":full.query.stages,"correct":true})
    );
    println!(
        "{}",
        json!({"experiment":"multipage-complete","completed":true,"matrix_queries":samples*CASES.len()*8*ids.len()*2,
        "peer_evaluated_preparations":preparations.get(),"negative_controls":rejections,"accounting":disk_accounting(&directory,&catalog,&loader,shared)?,
        "maximum_sampled_threads":monitor.maximum_sampled_threads(),"owner_online":true,"complete_owner_restart":false,
        "network_measured":false,"durable_fsync":false,"computation_proof":false})
    );
    Ok(())
}

struct ControlEnvironment<'a, 'p> {
    bfv: &'a BfvOwner,
    evaluator: &'a PeerEvaluator,
    pir: &'a Pir<'p>,
    preparations: &'a Cell<usize>,
}
fn reject_controls(
    catalog: &[disk::CatalogEntry],
    loader: &mut disk::Loader,
    id: usize,
    other: usize,
    env: &ControlEnvironment<'_, '_>,
) -> ProbeResult<usize> {
    let mut rejected = 0;
    for access in [Access::Visible, Access::Private] {
        for profile in [Profile::AddressOnly, Profile::Fixed256] {
            for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                for (label, query, expected) in [
                    ("three_data_pages", QuerySpec::Equal(249), "PageBudget"),
                    (
                        "complete_count_over256",
                        QuerySpec::Equal(240),
                        "SelectionBudget",
                    ),
                ] {
                    let before = env.preparations.get();
                    let begin = Instant::now();
                    let error = loader
                        .execute(
                            &catalog[id],
                            Plan {
                                kernel: KernelMode::ExactIndex,
                                access,
                                profile,
                                header,
                                query,
                                query_id: nonce()?,
                            },
                            env.bfv,
                            env.evaluator,
                            env.pir,
                            env.preparations,
                        )
                        .err()
                        .ok_or("Budget control unexpectedly reached a BFV result")?;
                    let whole_ms = ms(begin);
                    assert!(error.to_string().contains(expected));
                    assert_eq!(before, env.preparations.get());
                    rejected += 1;
                    println!(
                        "{}",
                        json!({"experiment":"multipage-rejection","case":label,
                        "access":format!("{access:?}"),"profile":format!("{profile:?}"),"header":format!("{header:?}"),
                        "whole_local_ms":whole_ms,"before_fresh_bfv":true,"error":error.to_string()})
                    );
                }
            }
        }
    }
    loader.ensure(&catalog[id], Access::Private, env.pir.params)?;
    let (data0, mut damaged_data1, index0, mut damaged_index1) = {
        let loaded = loader
            .current
            .as_ref()
            .ok_or("Missing fault-control table")?;
        (
            loaded.data.lookup(0, Limits::default())?.encode(),
            loaded.data.lookup(1, Limits::default())?.encode(),
            loaded
                .index
                .lookup(0, padded_index_codec::index_limits())?
                .encode(),
            loaded
                .index
                .lookup(1, padded_index_codec::index_limits())?
                .encode(),
        )
    };
    *damaged_data1.last_mut().ok_or("Empty data wire")? ^= 1;
    *damaged_index1.last_mut().ok_or("Empty index wire")? ^= 1;
    for access in [Access::Visible, Access::Private] {
        for (label, replacement) in [
            ("corrupt_second_data_page", (0, 1, damaged_data1.as_slice())),
            ("wrong_index_for_second_data_page", (0, 1, data0.as_slice())),
            (
                "corrupt_second_posting_page",
                (1, 1, damaged_index1.as_slice()),
            ),
            (
                "wrong_index_for_second_posting_page",
                (1, 1, index0.as_slice()),
            ),
        ] {
            let before = env.preparations.get();
            let begin = Instant::now();
            loader.ensure(&catalog[id], access, env.pir.params)?;
            let loaded = loader
                .current
                .as_ref()
                .ok_or("Missing loaded fault table")?;
            let data = Store {
                id: 0,
                snapshot: &loaded.data,
                head: &catalog[id].data_head,
                db: loaded.ntt.as_ref().map(|pair| &pair.data),
                limits: Limits::default(),
            };
            let index = Store {
                id: 1,
                snapshot: &loaded.index,
                head: &catalog[id].index_head,
                db: loaded.ntt.as_ref().map(|pair| &pair.index),
                limits: padded_index_codec::index_limits(),
            };
            let session = Session {
                owner: &catalog[id].owner,
                bfv: env.bfv,
                evaluator: env.evaluator,
                pir: env.pir,
                data: &data,
                index: &index,
                cached: &catalog[id].cached,
                preparations: env.preparations,
                replacement_wire: Some(replacement),
            };
            assert!(
                read(
                    Plan {
                        kernel: KernelMode::ExactIndex,
                        access,
                        profile: Profile::Fixed256,
                        header: HeaderMode::Cached,
                        query: QuerySpec::Equal(230),
                        query_id: nonce()?
                    },
                    &session
                )
                .is_err()
            );
            assert_eq!(before, env.preparations.get());
            rejected += 1;
            println!(
                "{}",
                json!({"experiment":"multipage-rejection","case":label,"access":format!("{access:?}"),
                "whole_local_ms":ms(begin),"before_fresh_bfv":true,"target_is_second_real_page":true})
            );
        }
    }
    // Independent head-pair mismatch, not accepted merely because counts/offsets look valid.
    assert!(
        catalog[other]
            .cached
            .restore(&catalog[id].data_head, &catalog[id].index_head)
            .is_err()
    );
    rejected += 1;
    println!(
        "{}",
        json!({"experiment":"multipage-rejection","case":"wrong_trusted_cached_head_pair","before_fresh_bfv":true})
    );
    Ok(rejected)
}
