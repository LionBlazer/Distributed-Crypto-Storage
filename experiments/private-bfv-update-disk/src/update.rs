//! Owner-online experiment composition only; no storage policy is added to the BFV library.
use crate::*;
use compact_bfv_byte_limb_core::{
    IndexedUpdateStats, ProofStatus, UnverifiedUpdateOutcome, UpdatedAmount,
};
use std::{collections::HashMap, path::Path};
use zeroize::Zeroizing;

pub(crate) struct Environment<'a> {
    pub directory: &'a Path,
    pub bfv: &'a BfvOwner,
    pub evaluator: &'a PeerEvaluator,
    pub pir: &'a Pir<'a>,
    pub preparations: &'a Cell<usize>,
    pub diagnostic_preparations: &'a Cell<usize>,
}
#[derive(Clone, Copy)]
pub(crate) enum OutputMode {
    Honest,
    PublicEcho,
}
#[derive(Default, Serialize)]
pub(crate) struct UpdateStages {
    pub input_load: disk::LoadStages,
    pub selection: Stages,
    pub prepare_serialize_ms: f64,
    pub freshness_ms: f64,
    pub peer: Option<IndexedUpdateStats>,
    pub answer_decode_decrypt_ms: f64,
    pub local_oracle_ms: f64,
    pub compact_stage_ms: f64,
    pub image_encode_ms: f64,
    pub data_write_ms: f64,
    pub index_write_ms: f64,
    pub catalog_write_flush_ms: f64,
    pub publish_invalidate_ms: f64,
    pub update_commit_invalidate_ms: f64,
    pub stale_output_gate_ms: f64,
    pub reopen_native_readiness_ms: f64,
    pub readiness: Option<disk::LoadStages>,
    pub subsequent_exact_read_ms: f64,
    pub subsequent_read: Option<Stages>,
    pub post_read_validation_ms: f64,
    pub total_ms: f64,
    pub request_bytes: usize,
    pub response_bytes: usize,
}
pub(crate) struct Operation {
    pub committed: bool,
    pub outcome: &'static str,
    pub selected: usize,
    pub stages: UpdateStages,
    pub ciphertext_digest: [u8; 32],
    pub input_amounts: Vec<u16>,
    pub output_rows: Option<Vec<UpdatedAmount>>,
}
pub(crate) fn current_context(
    context: &QueryContext,
    entry: &disk::CatalogEntry,
) -> ProbeResult<()> {
    if context.data_head() != entry.data_head.encode()
        || context.index_head() != entry.index_head.encode()
    {
        return Err("Trusted live head changed before UPDATE completion/staging".into());
    }
    Ok(())
}
/// This local oracle runs ONLY after actual peer evaluation and owner completion in execute().
pub(crate) fn check_answer(
    fields: &[SelectedField],
    delta: u16,
    outcome: UnverifiedUpdateOutcome,
) -> ProbeResult<Option<Vec<UpdatedAmount>>> {
    let overflow = fields
        .iter()
        .filter(|f| f.active)
        .any(|f| f.amount.checked_add(delta).is_none());
    match outcome {
        UnverifiedUpdateOutcome::Overflow {
            proof: ProofStatus::Unavailable,
        } if overflow => Ok(None),
        UnverifiedUpdateOutcome::Values(values) if !overflow => {
            let expected_count = fields.iter().filter(|f| f.active).count();
            if values.proof != ProofStatus::Unavailable || values.rows.len() != expected_count {
                return Err("Local oracle rejected UPDATE shape".into());
            }
            for ((slot, field), row) in fields
                .iter()
                .enumerate()
                .filter(|(_, f)| f.active)
                .zip(&values.rows)
            {
                let value = field
                    .amount
                    .checked_add(delta)
                    .ok_or("Unexpected local overflow")?;
                let low = (field.amount & 255) + (delta & 255);
                let high = (field.amount >> 8) + (delta >> 8);
                if (row.slot, row.amount, row.low_limb_sum, row.high_limb_sum)
                    != (slot, value, low, high)
                {
                    return Err(
                        "Local experiment oracle rejected unverified UPDATE arithmetic".into(),
                    );
                }
            }
            Ok(Some(values.rows))
        }
        _ => Err("Local oracle rejected false overflow or partial UPDATE success".into()),
    }
}
struct Staged {
    data: EncryptedSnapshot,
    index: EncryptedSnapshot,
    cached: CachedHeader,
}
fn stage(
    entry: &disk::CatalogEntry,
    loaded: &disk::LoadedTable,
    input: &selection::Selection,
    rows: &[UpdatedAmount],
) -> ProbeResult<Staged> {
    if loaded.data.commitment() != &entry.data_head
        || loaded.index.commitment() != &entry.index_head
    {
        return Err("Stale loaded state before staging".into());
    }
    selection::validate_ordinals(&input.selected, entry.data_head.layout().row_count)?;
    if input.selected.len() != rows.len() {
        return Err("All selected rows must be staged together".into());
    }
    let page = input.page.ok_or("No real page for nonempty UPDATE")?;
    let mut bytes = Zeroizing::new(
        input
            .plaintext
            .as_ref()
            .ok_or("No authenticated old plaintext")?
            .as_bytes()
            .to_vec(),
    );
    let mut mutable_bytes = vec![false; bytes.len()];
    for row in rows {
        let ordinal = *input
            .selected
            .get(row.slot)
            .ok_or("Invalid returned slot")?;
        let offset = (ordinal as usize % PAGE_ROWS) * 3;
        let target = bytes
            .get_mut(offset..offset + 3)
            .ok_or("Returned ordinal outside staged page")?;
        if target[0] != input.fields[row.slot].age
            || u16::from_le_bytes([target[1], target[2]]) != input.fields[row.slot].amount
        {
            return Err("Authenticated original changed before replacement".into());
        }
        target[1..3].copy_from_slice(&row.amount.to_le_bytes());
        mutable_bytes[offset + 1] = true;
        mutable_bytes[offset + 2] = true;
    }
    let original_bytes = input.plaintext.as_ref().unwrap().as_bytes();
    if bytes
        .iter()
        .zip(original_bytes)
        .enumerate()
        .any(|(offset, (new, old))| !mutable_bytes[offset] && new != old)
    {
        return Err("Amount UPDATE changed an age or nonselected data byte".into());
    }
    let mut data = loaded.data.clone();
    let new_data = entry.owner.replace_pages(
        &mut data,
        &entry.data_head,
        &[(page, bytes.as_slice())],
        Limits::default(),
    )?;
    let old_page = loaded.index.lookup(0, padded_index_codec::index_limits())?;
    let verified = old_page.verify(&entry.index_head, 0, padded_index_codec::index_limits())?;
    let original = entry.owner.decrypt(&verified)?;
    if original.as_bytes().get(..compact_store::MANIFEST_BYTES)
        != Some(&entry.data_head.encode()[..])
    {
        return Err("Old index page0 has wrong data binding".into());
    }
    let mut header = Zeroizing::new(original.as_bytes().to_vec());
    header[..compact_store::MANIFEST_BYTES].copy_from_slice(&new_data.encode());
    if header[compact_store::MANIFEST_BYTES..]
        != original.as_bytes()[compact_store::MANIFEST_BYTES..]
    {
        return Err("Rebind changed index posting/header suffix".into());
    }
    let mut index = loaded.index.clone();
    entry.owner.replace_page(
        &mut index,
        &entry.index_head,
        0,
        &header,
        padded_index_codec::index_limits(),
    )?;
    let rebound = index.lookup(0, padded_index_codec::index_limits())?;
    let rebound = rebound.verify(index.commitment(), 0, padded_index_codec::index_limits())?;
    let rebound = entry.owner.decrypt(&rebound)?;
    if rebound.as_bytes()[compact_store::MANIFEST_BYTES..]
        != original.as_bytes()[compact_store::MANIFEST_BYTES..]
    {
        return Err("Resealed index suffix differs".into());
    }
    if (data.encoded_len(), index.encoded_len()) != (entry.data_len, entry.index_len) {
        return Err("Canonical image growth during amount-only UPDATE".into());
    }
    let cached = disk::capture_owner_header(&entry.owner, &index, data.commitment())?;
    Ok(Staged {
        data,
        index,
        cached,
    })
}
pub(crate) fn execute(
    catalog: &mut [disk::CatalogEntry],
    loader: &mut disk::Loader,
    id: usize,
    plan: Plan,
    delta: u16,
    env: &Environment<'_>,
    output_mode: OutputMode,
) -> ProbeResult<Operation> {
    let whole = Instant::now();
    if !matches!(plan.kernel, KernelMode::ExactIndex) {
        return Err("UPDATE requires explicit complete exact-index selection".into());
    }
    let entry = catalog
        .get(id)
        .filter(|e| e.id == id)
        .ok_or("Unknown supplied table")?;
    let mut stages = UpdateStages {
        input_load: loader.ensure(entry, plan.access, env.pir.params)?,
        ..UpdateStages::default()
    };
    let old_data = entry.data_head.clone();
    let old_index = entry.index_head.clone();
    let old_catalog_len = std::fs::metadata(env.directory.join("catalog.jsonl"))?.len();
    let input = {
        let loaded = loader.current.as_ref().ok_or("Loaded table unavailable")?;
        let data = Store {
            id: 0,
            snapshot: &loaded.data,
            head: &entry.data_head,
            db: loaded.ntt.as_ref().map(|p| &p.data),
            limits: Limits::default(),
        };
        let index = Store {
            id: 1,
            snapshot: &loaded.index,
            head: &entry.index_head,
            db: loaded.ntt.as_ref().map(|p| &p.index),
            limits: padded_index_codec::index_limits(),
        };
        let session = Session {
            owner: &entry.owner,
            bfv: env.bfv,
            evaluator: env.evaluator,
            pir: env.pir,
            data: &data,
            index: &index,
            cached: &entry.cached,
            preparations: env.preparations,
            replacement_wire: None,
        };
        selection::select(plan, &session, &mut stages.selection)?
    };
    check_exact_selected_ages(plan.query, &input.fields, input.selected.len())?;
    selection::validate_ordinals(&input.selected, entry.data_head.layout().row_count)?;
    let context = QueryContext::new(plan.query_id, old_data.encode(), old_index.encode());
    current_context(&context, entry)?;
    let begin = Instant::now();
    env.preparations.set(env.preparations.get() + 1);
    let prepared =
        env.bfv
            .prepare_indexed_update_for_experiment(context.clone(), &input.fields, delta)?;
    stages.prepare_serialize_ms = ms(begin);
    stages.request_bytes = prepared.request.len();
    let begin = Instant::now();
    let ciphertext_digest = sha2::Sha256::digest(prepared.ciphertext_payload_bytes()?).into();
    stages.freshness_ms = ms(begin);
    // There is no fixture oracle or updated-answer computation before this real addition.
    let evaluated = env.evaluator.evaluate_indexed_update(&prepared.request)?;
    if evaluated.stats.ciphertext_additions != 1
        || evaluated.stats.ct_ct_multiplications != 0
        || evaluated.stats.rotations != 0
        || evaluated.stats.multiplicative_depth != 0
    {
        return Err("UPDATE peer did not perform bounded ciphertext addition".into());
    }
    let output = match output_mode {
        OutputMode::Honest => evaluated.output,
        OutputMode::PublicEcho => crate::update_controls::public_echo(&prepared.request)?,
    };
    stages.response_bytes = output.len();
    stages.peer = Some(evaluated.stats);
    current_context(&context, &catalog[id])?;
    let begin = Instant::now();
    let outcome = env
        .bfv
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &output)?;
    stages.answer_decode_decrypt_ms = ms(begin);
    let begin = Instant::now();
    let checked = check_answer(&input.fields, delta, outcome)?;
    stages.local_oracle_ms = ms(begin);
    let Some(rows) = checked else {
        if catalog[id].data_head != old_data || catalog[id].index_head != old_index {
            return Err("Overflow unexpectedly mutated trusted heads".into());
        }
        stages.update_commit_invalidate_ms = ms(whole);
        stages.total_ms = ms(whole);
        return Ok(Operation {
            committed: false,
            outcome: "GlobalOverflowNoCommit",
            selected: input.selected.len(),
            stages,
            ciphertext_digest,
            input_amounts: input.fields.iter().map(|f| f.amount).collect(),
            output_rows: None,
        });
    };
    current_context(&context, &catalog[id])?;
    let changed = rows
        .iter()
        .any(|row| row.amount != input.fields[row.slot].amount);
    let begin = Instant::now();
    if changed {
        disk::admit("before_update_ciphertext_staging", id, 32 * 1024 * 1024)?;
        let staged = stage(
            &catalog[id],
            loader.current.as_ref().ok_or("Missing old loaded state")?,
            &input,
            &rows,
        )?;
        stages.compact_stage_ms = ms(begin);
        current_context(&context, &catalog[id])?;
        let begin = Instant::now();
        let data_image = staged.data.encode();
        let index_image = staged.index.encode();
        stages.image_encode_ms = ms(begin);
        let write_result = (|| -> ProbeResult<()> {
            let begin = Instant::now();
            disk::write_replacement(&catalog[id].data_path, &data_image)?;
            stages.data_write_ms = ms(begin);
            let begin = Instant::now();
            disk::write_replacement(&catalog[id].index_path, &index_image)?;
            stages.index_write_ms = ms(begin);
            let begin = Instant::now();
            disk::persist_catalog_at_heads(
                env.directory,
                catalog,
                id,
                staged.data.commitment(),
                staged.index.commitment(),
            )?;
            stages.catalog_write_flush_ms = ms(begin);
            if std::fs::metadata(env.directory.join("catalog.jsonl"))?.len() != old_catalog_len {
                return Err("Catalog length changed after fixed-head rewrite".into());
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            loader.invalidate(id);
            return Err(format!(
                "Partial disk write possible; cache invalidated and run aborted: {error}"
            )
            .into());
        }
        let begin = Instant::now();
        catalog[id].data_head = staged.data.commitment().clone();
        catalog[id].index_head = staged.index.commitment().clone();
        catalog[id].cached = staged.cached;
        loader.invalidate(id);
        stages.publish_invalidate_ms = ms(begin);
        drop(data_image);
        drop(index_image);
        drop(staged.data);
        drop(staged.index);
    } else {
        // Explicit empty/delta-zero policy: real FHE, no writes/revisions; force fresh disk validation.
        stages.compact_stage_ms = ms(begin);
        loader.invalidate(id);
    }
    stages.update_commit_invalidate_ms = ms(whole);
    if loader.current.is_some() {
        return Err("Old loaded snapshots/native pair survived invalidation".into());
    }
    let begin = Instant::now();
    if changed {
        assert!(current_context(&context, &catalog[id]).is_err());
        let updated_fields: Vec<_> = rows
            .iter()
            .map(|row| SelectedField {
                amount: row.amount,
                ..input.fields[row.slot]
            })
            .collect();
        env.diagnostic_preparations
            .set(env.diagnostic_preparations.get() + 1);
        let replay = env.bfv.prepare_indexed_update_for_experiment(
            QueryContext::new(
                context.query_id(),
                catalog[id].data_head.encode(),
                catalog[id].index_head.encode(),
            ),
            &updated_fields,
            delta,
        )?;
        if env
            .bfv
            .decrypt_indexed_update_unverified_for_experiment(replay.pending, &output)
            .is_ok()
        {
            return Err("Stale old UPDATE response accepted under new heads".into());
        }
        if catalog[id].cached.restore(&old_data, &old_index).is_ok() {
            return Err("New cached header accepted old head pair".into());
        }
    }
    stages.stale_output_gate_ms = ms(begin);
    let begin = Instant::now();
    let readiness = loader.ensure(&catalog[id], plan.access, env.pir.params)?;
    if readiness.event != "TableMiss" {
        return Err("Post-update validation must reopen fresh canonical images".into());
    }
    stages.reopen_native_readiness_ms = ms(begin);
    stages.readiness = Some(readiness);
    let read_plan = Plan {
        query_id: nonce()?,
        kernel: KernelMode::ExactIndex,
        ..plan
    };
    let subsequent = loader.execute(
        &catalog[id],
        read_plan,
        env.bfv,
        env.evaluator,
        env.pir,
        env.preparations,
    )?;
    stages.subsequent_exact_read_ms = subsequent.whole_ms;
    let begin = Instant::now();
    let expected_sum: u32 = rows.iter().map(|row| u32::from(row.amount)).sum();
    if subsequent.query.selected != input.selected
        || (subsequent.query.actual.count, subsequent.query.actual.sum)
            != (rows.len() as u32, expected_sum)
        || subsequent.query.actual.proof != ProofStatus::Unavailable
    {
        return Err("Fresh genuine exact read disagrees with committed UPDATE".into());
    }
    if (
        std::fs::metadata(&catalog[id].data_path)?.len(),
        std::fs::metadata(&catalog[id].index_path)?.len(),
    ) != (catalog[id].data_len as u64, catalog[id].index_len as u64)
    {
        return Err("Canonical files grew after UPDATE".into());
    }
    stages.post_read_validation_ms = ms(begin);
    stages.subsequent_read = Some(subsequent.query.stages);
    stages.total_ms = ms(whole);
    Ok(Operation {
        committed: changed,
        outcome: if changed { "Committed" } else { "NoOpNoReseal" },
        selected: input.selected.len(),
        stages,
        ciphertext_digest,
        input_amounts: input.fields.iter().map(|f| f.amount).collect(),
        output_rows: Some(rows),
    })
}

pub(crate) fn run() -> ProbeResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let count: usize = args.get(1).map(|v| v.parse()).transpose()?.unwrap_or(3);
    let cycles: usize = args.get(2).map(|v| v.parse()).transpose()?.unwrap_or(100);
    let threads: usize = args.get(3).map(|v| v.parse()).transpose()?.unwrap_or(8);
    let target: usize = args.get(4).map(|v| v.parse()).transpose()?.unwrap_or(0);
    let budget: u64 = args
        .get(5)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(64 * 1024 * 1024);
    let directory = std::path::PathBuf::from(
        args.get(6)
            .ok_or("Supply fresh owned ignored run directory")?,
    );
    native::configure(args.get(7).map(String::as_str).unwrap_or("combined"))?;
    if !(3..=2000).contains(&count)
        || !(1..=100).contains(&cycles)
        || !(1..=8).contains(&threads)
        || target >= count
        || (count as u64)
            .checked_mul(6 * 1024 * 1024)
            .is_none_or(|bytes| bytes > budget)
    {
        return Err("Bounded update experiment preflight failed".into());
    }
    std::fs::create_dir(&directory)?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let monitor = resources::Monitor::start(disk::MEMORY_LIMIT);
    let setup_time = Instant::now();
    let params = spiral_owner_state::profile_params();
    let initial = spiral_owner_state::OwnerState::generate(&params, [0x45; 32])?;
    let pir_wire_bytes = initial.public_wire.len();
    disk::write_new(
        &directory.join("shared-pir-public.bin"),
        &initial.public_wire,
    )?;
    let secret_image = initial.owner.encode_secret_for_experiment();
    let restored = spiral_owner_state::OwnerState::restore(
        &params,
        [0x45; 32],
        secret_image.as_ref(),
        &initial.public_wire,
    )?;
    drop(secret_image);
    drop(initial);
    let _owner_state = restored.owner;
    let pir_client = restored.client;
    let pir_public = restored.public;
    let pir_public_ram: usize = pir_public
        .v_packing
        .iter()
        .chain(pir_public.v_expansion_left.iter().flatten())
        .chain(pir_public.v_expansion_right.iter().flatten())
        .chain(pir_public.v_conversion.iter().flatten())
        .map(|m| m.data.len() * 8)
        .sum();
    let (bfv, setup) = BfvOwner::generate(Geometry::Rows256)?;
    let secret_count = bfv.secret_key_serialized_bytes();
    let bfv_counts = setup.byte_counts()?;
    let wire = setup.to_bytes()?;
    let bfv_wire_bytes = wire.len();
    disk::write_new(&directory.join("shared-bfv-public.bin"), &wire)?;
    drop(setup);
    let setup = PublicSetup::from_bytes(&wire)?;
    drop(wire);
    let evaluator = PeerEvaluator::from_public_setup(&setup)?;
    drop(setup);
    runtime_profile_gate(&bfv, &evaluator)?;
    let pir = Pir {
        params: &params,
        client: &pir_client,
        public: &pir_public,
    };
    let mut catalog = disk::build_catalog(&directory, count, budget)?;
    let mut loader = disk::Loader::new(1)?;
    let shared = SharedBytes {
        public_wire: pir_wire_bytes + bfv_wire_bytes,
        owner_counts: spiral_owner_state::OWNER_STATE_BYTES + secret_count,
        pir_public_ram,
    };
    println!(
        "{}",
        json!({"experiment":"update-disk-setup","tables":count,"supplied_table_id":target,"cycles":cycles,"setup_ms":ms(setup_time),"bfv_profile":bfv.profile(),"bfv_public_bytes":bfv_counts,"accounting":disk_accounting(&directory,&catalog,&loader,shared)?,"owner_online":true,"complete_owner_restart":false,"durable_fsync":false,"network_measured":false,"computation_proof":false,"server_schedule":native::name(),"rayon_threads":threads})
    );
    let preparations = Cell::new(0);
    let diagnostic_preparations = Cell::new(0);
    let env = Environment {
        directory: &directory,
        bfv: &bfv,
        evaluator: &evaluator,
        pir: &pir,
        preparations: &preparations,
        diagnostic_preparations: &diagnostic_preparations,
    };
    // Retain all eight complete read cases and all explicit access/profile/header combinations.
    for access in [Access::Visible, Access::Private] {
        for profile in [Profile::AddressOnly, Profile::Fixed256] {
            for header in [HeaderMode::Cached, HeaderMode::Uncached] {
                for case in CASES {
                    let plan = Plan {
                        kernel: KernelMode::ExactIndex,
                        access,
                        profile,
                        header,
                        query: case.query,
                        query_id: nonce()?,
                    };
                    let result = loader.execute(
                        &catalog[target],
                        plan,
                        &bfv,
                        &evaluator,
                        &pir,
                        &preparations,
                    )?;
                    let (expected, sum) = oracle(target, case.query);
                    if result.query.selected != expected
                        || (result.query.actual.count, result.query.actual.sum)
                            != (expected.len() as u32, sum)
                    {
                        return Err("Initial eight-case exact read regression".into());
                    }
                    println!(
                        "{}",
                        json!({"experiment":"update-disk-read-control","case":case.name,"public_query_kind":case.query.kind(),"query_only_ms":result.query.total_ms,"access":format!("{access:?}"),"profile":format!("{profile:?}"),"header":format!("{header:?}"),"whole_ms":result.whole_ms,"load":result.load,"stages":result.query.stages,"ciphertext_digest":format!("{:x}",sha2::Sha256::digest(result.query.ciphertext_payload))})
                    );
                }
            }
        }
    }
    // A genuine encrypted-predicate read on the identical retained keyset remains an explicit control.
    let full = loader.execute(
        &catalog[target],
        Plan {
            kernel: KernelMode::FullPredicate,
            access: Access::Private,
            profile: Profile::Fixed256,
            header: HeaderMode::Cached,
            query: QuerySpec::Equal(250),
            query_id: nonce()?,
        },
        &bfv,
        &evaluator,
        &pir,
        &preparations,
    )?;
    if (full.query.actual.count, full.query.actual.sum) != (1, 100 + (target % 1000) as u32) {
        return Err("FullPredicate retained control mismatch".into());
    }
    update_controls::before_commits(&mut catalog, &mut loader, target, &env)?;
    let mut mode_counts = HashMap::<String, usize>::new();
    let mut committed = 0usize;
    let mut previous = None;
    for cycle in 0..cycles {
        let access = if cycle % 2 == 0 {
            Access::Private
        } else {
            Access::Visible
        };
        let header = if (cycle / 2) % 2 == 0 {
            HeaderMode::Cached
        } else {
            HeaderMode::Uncached
        };
        let profile = if (cycle / 4) % 2 == 0 {
            Profile::Fixed256
        } else {
            Profile::AddressOnly
        };
        let plan = Plan {
            kernel: KernelMode::ExactIndex,
            access,
            profile,
            header,
            query: QuerySpec::Equal(250),
            query_id: nonce()?,
        };
        let result = execute(
            &mut catalog,
            &mut loader,
            target,
            plan,
            1,
            &env,
            OutputMode::Honest,
        )?;
        if !result.committed || result.selected != 1 {
            return Err("Every main cycle must commit one actual BFV UPDATE".into());
        }
        if previous.replace(result.ciphertext_digest) == Some(result.ciphertext_digest) {
            return Err("Repeated UPDATE ciphertext payload".into());
        }
        committed += 1;
        *mode_counts
            .entry(format!("{access:?}/{profile:?}/{header:?}"))
            .or_default() += 1;
        println!(
            "{}",
            json!({"experiment":"update-disk-cycle","cycle":cycle,"outcome":result.outcome,"selected":result.selected,"access":format!("{access:?}"),"profile":format!("{profile:?}"),"header":format!("{header:?}"),"stages":result.stages,"public_fixture_input_amounts":result.input_amounts,"public_fixture_updated_rows":result.output_rows,"canonical_no_growth":true,"catalog_no_growth":true,"proof":"Unavailable","local_oracle":true})
        );
    }
    update_controls::after_commits(&mut catalog, &mut loader, target, &env)?;
    println!(
        "{}",
        json!({"experiment":"update-disk-complete","main_committed_cycles":committed,"mode_counts":mode_counts,"peer_evaluated_preparations_including_fresh_reads":preparations.get(),"diagnostic_replay_preparations":diagnostic_preparations.get(),"accounting":disk_accounting(&directory,&catalog,&loader,shared)?,"maximum_sampled_threads":monitor.maximum_sampled_threads(),"no_persistent_expanded_overlays":true,"no_crash_atomic_commit":true,"complete_owner_restart":false,"bfv_outputs_unverified":true})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("update_tests.rs");
}
