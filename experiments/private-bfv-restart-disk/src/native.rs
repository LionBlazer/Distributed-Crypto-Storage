//! Injection seam for reviewed native-equivalent cache and server helpers.
use crate::expansion_schedule::Schedule;
use crate::{EncryptedSnapshot, Params, ProbeResult, PublicParameters, Query, ms, records};
use serde::Serialize;
use spiral_rs::aligned_memory::AlignedMemory64;
use std::sync::OnceLock;
static SCHEDULE: OnceLock<Schedule> = OnceLock::new();
use std::time::Instant;
#[derive(Default, Serialize)]
pub(crate) struct PrepStages {
    pub data_records_ms: f64,
    pub index_records_ms: f64,
    pub pair_ntt_ms: f64,
    pub total_ms: f64,
    pub cache_backend: &'static str,
    pub temporary_record_buffers_bytes: usize,
    pub represented_data_proof_bytes: usize,
    pub represented_index_proof_bytes: usize,
}
pub(crate) struct CachePair {
    pub data: AlignedMemory64,
    pub index: AlignedMemory64,
    pub stages: PrepStages,
}
pub(crate) fn prepare_pair(
    data: &EncryptedSnapshot,
    index: &EncryptedSnapshot,
    params: &Params,
) -> ProbeResult<CachePair> {
    if *params != spiral_cache_core::profile_params() {
        return Err("Cache helper profile drift".into());
    }
    let all = Instant::now();
    let start = Instant::now();
    let (data_records, data_proof) = records(data, params, crate::Limits::default());
    let data_records_ms = ms(start);
    let start = Instant::now();
    let (index_records, index_proof) =
        records(index, params, crate::padded_index_codec::index_limits());
    let index_records_ms = ms(start);
    let buffers = data_records.len() + index_records.len();
    let start = Instant::now();
    let (data_cache, index_cache) =
        spiral_cache_core::load_pair(params, &data_records, &index_records)?;
    let pair_ntt_ms = ms(start);
    drop(data_records);
    drop(index_records);
    Ok(CachePair {
        data: data_cache,
        index: index_cache,
        stages: PrepStages {
            data_records_ms,
            index_records_ms,
            pair_ntt_ms,
            total_ms: ms(all),
            cache_backend: "spiral-cache-core/pinned-parallel-trials",
            temporary_record_buffers_bytes: buffers,
            represented_data_proof_bytes: data_proof,
            represented_index_proof_bytes: index_proof,
        },
    })
}
pub(crate) fn process(
    params: &Params,
    public: &PublicParameters,
    query: &Query,
    db: &[u64],
) -> Vec<u8> {
    crate::expansion_schedule::evaluate(
        params,
        public,
        query,
        db,
        *SCHEDULE.get().expect("Server schedule not configured"),
    )
}
pub(crate) fn configure(mode: &str) -> ProbeResult<()> {
    let [parallel, combined] = Schedule::pair_order(0);
    let [official, _, expansion, _] = Schedule::all_order(0);
    let schedule = match mode {
        "official" => official,
        "parallel" => parallel,
        "expansion" => expansion,
        "combined" => combined,
        _ => return Err("Unknown public server schedule".into()),
    };
    SCHEDULE
        .set(schedule)
        .map_err(|_| "Server schedule already configured".into())
}
pub(crate) fn name() -> &'static str {
    match SCHEDULE.get() {
        Some(Schedule::Official) => "Official",
        Some(Schedule::TrialsOnly) => "TrialsOnly",
        Some(Schedule::ExpansionOnly) => "ExpansionOnly",
        Some(Schedule::Combined) => "Combined",
        None => "Unconfigured",
    }
}
