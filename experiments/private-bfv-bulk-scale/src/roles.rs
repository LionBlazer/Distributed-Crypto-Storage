//! Owner-only exact selection vs public-only bulk/BFV peer. Neither owns an answer cache.
use crate::{
    ProbeResult,
    bulk_wire::{HEADER_BYTES, Header, MAX_IMAGE_BYTES, WireError},
    fixture::{Case, PAGE_ROWS},
    resources,
};
use compact_query::{
    AgeRange, Table,
    bfv::{self, EvaluationStats, UnverifiedAggregate},
};
use compact_store::{Commitment, Limits};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustedTable {
    pub table_id: u32,
    pub logical_id: compact_query::TableId,
    pub data_head: Commitment,
    pub index_head: Commitment,
    pub data_len: usize,
    pub index_len: usize,
}
impl TrustedTable {
    pub fn capture(table_id: u32, table: &Table) -> ProbeResult<Self> {
        if table.commitment().layout().rows_per_page != PAGE_ROWS {
            return Err("Unexpected data page geometry".into());
        }
        let value = Self {
            table_id,
            logical_id: *table.table_id(),
            data_head: table.commitment().clone(),
            index_head: table.index_commitment().clone(),
            data_len: table.canonical_data_bytes(),
            index_len: table.encrypted_index_bytes(),
        };
        value.header([0; 16]).response_len()?;
        Ok(value)
    }
    pub fn header(&self, request_id: [u8; 16]) -> Header {
        Header {
            table_id: self.table_id,
            request_id,
            data_head: self.data_head.encode(),
            index_head: self.index_head.encode(),
            data_len: self.data_len,
            index_len: self.index_len,
        }
    }
    fn agrees(&self, header: &Header) -> bool {
        self.header(header.request_id) == *header
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) enum Mode {
    Disk,
    Resident,
}
pub(crate) struct OwnerTable {
    owner: bfv::Owner,
    pub trusted: TrustedTable,
}
/// Only ciphertext files/cache, current public descriptor and Arc-backed PUBLIC BFV material.
pub(crate) struct DiskPeer {
    pub evaluator: bfv::Evaluator,
    pub trusted: TrustedTable,
    data_path: PathBuf,
    index_path: PathBuf,
    resident: Option<(Vec<u8>, Vec<u8>)>,
}
#[derive(Default)]
pub(crate) struct Counters {
    pub prepare_calls: Cell<usize>,
    pub prepare_successes: Cell<usize>,
    pub peer_evaluations: Cell<usize>,
    pub owner_completions: Cell<usize>,
}
#[derive(Serialize)]
pub(crate) struct Stages {
    pub bulk_request_encode_ms: f64,
    pub peer_response_read_copy_encode_ms: f64,
    pub owner_full_frame_decode_root_and_binding_ms: f64,
    pub owner_exact_select_auth_fresh_encrypt_ms: f64,
    pub owner_completion_ms: f64,
    pub diagnostic_payload_hash_ms: f64,
    pub peer: EvaluationStats,
    pub bulk_request_bytes: usize,
    pub bulk_response_bytes: usize,
    pub bfv_request_bytes: usize,
    pub bfv_response_bytes: usize,
}
pub(crate) struct ReadResult {
    pub whole_ms: f64,
    pub stages: Stages,
    pub actual: UnverifiedAggregate,
    pub selected_rows: usize,
    pub payload_sha256: [u8; 32],
}
fn ms(timer: Instant) -> f64 {
    timer.elapsed().as_secs_f64() * 1000.0
}
pub(crate) fn data_limits() -> Limits {
    Limits {
        max_image_bytes: MAX_IMAGE_BYTES,
        ..Limits::default()
    }
}
fn read_exact_file(path: &Path, expected: usize) -> ProbeResult<Vec<u8>> {
    let mut file = checked_file(path, expected)?;
    let mut bytes = vec![0u8; expected];
    read_exact_tail(&mut file, &mut bytes)?;
    Ok(bytes)
}
fn checked_file(path: &Path, expected: usize) -> ProbeResult<File> {
    if !(112..=MAX_IMAGE_BYTES).contains(&expected) {
        return Err(WireError::Limit.into());
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected as u64 {
        return Err("Canonical held-file length/type mismatch".into());
    }
    Ok(file)
}
fn read_exact_tail(file: &mut File, out: &mut [u8]) -> ProbeResult<()> {
    file.read_exact(out)?;
    if file.read(&mut [0u8; 1])? != 0 {
        return Err("Canonical file grew beyond bound".into());
    }
    Ok(())
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> ProbeResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}
impl DiskPeer {
    pub fn new(
        evaluator: bfv::Evaluator,
        trusted: TrustedTable,
        data_path: PathBuf,
        index_path: PathBuf,
    ) -> Self {
        Self {
            evaluator,
            trusted,
            data_path,
            index_path,
            resident: None,
        }
    }
    pub fn preload_resident(&mut self) -> ProbeResult<()> {
        resources::guard(32 * 1024 * 1024)?;
        self.resident = Some((
            read_exact_file(&self.data_path, self.trusted.data_len)?,
            read_exact_file(&self.index_path, self.trusted.index_len)?,
        ));
        Ok(())
    }
    pub fn clear_resident(&mut self) {
        self.resident = None
    }
    pub fn resident_bytes(&self) -> usize {
        self.resident
            .as_ref()
            .map_or(0, |(data, index)| data.len() + index.len())
    }
    pub fn respond(&self, request: &[u8], mode: Mode) -> ProbeResult<Vec<u8>> {
        let header = Header::parse_request(request)?;
        if !self.trusted.agrees(&header) {
            return Err(WireError::Binding.into());
        }
        let size = header.response_len()?;
        // Held file metadata is checked before the response allocation. No selected address is supplied.
        let files = if matches!(mode, Mode::Disk) {
            Some((
                checked_file(&self.data_path, header.data_len)?,
                checked_file(&self.index_path, header.index_len)?,
            ))
        } else {
            None
        };
        let mut wire = header.response_header()?;
        wire.resize(size, 0);
        let (data, index) = wire[HEADER_BYTES..].split_at_mut(header.data_len);
        match mode {
            Mode::Disk => {
                let (mut data_file, mut index_file) = files.ok_or("Missing held files")?;
                read_exact_tail(&mut data_file, data)?;
                read_exact_tail(&mut index_file, index)?;
            }
            Mode::Resident => {
                let (saved_data, saved_index) = self
                    .resident
                    .as_ref()
                    .ok_or("Resident ciphertext mode not initialized")?;
                if saved_data.len() != data.len() || saved_index.len() != index.len() {
                    return Err(WireError::Shape.into());
                }
                data.copy_from_slice(saved_data);
                index.copy_from_slice(saved_index);
            }
        }
        Ok(wire)
    }
}
impl OwnerTable {
    pub fn new(owner: bfv::Owner, trusted: TrustedTable) -> Self {
        Self { owner, trusted }
    }
    pub fn profile(&self) -> bfv::ParameterProfile {
        self.owner.profile()
    }
    pub fn secret_key_count(&self) -> usize {
        self.owner.secret_key_serialized_bytes()
    }
    pub fn open_response(&self, pending: &Header, wire: &[u8]) -> ProbeResult<Table> {
        if !self.trusted.agrees(pending) {
            return Err(WireError::Binding.into());
        }
        let (data, index) = pending.split_response(wire)?;
        // Real canonical decode recomputes BOTH full roots, then schema/index AEAD binding.
        Ok(self.owner.restore_table_for_experiment(
            data,
            index,
            &self.trusted.logical_id,
            &self.trusted.data_head,
            &self.trusted.index_head,
            data_limits(),
        )?)
    }
    pub fn execute(
        &self,
        peer: &DiskPeer,
        mode: Mode,
        case: Case,
        counters: &Counters,
    ) -> ProbeResult<ReadResult> {
        let all = Instant::now();
        resources::guard(64 * 1024 * 1024)?;
        let start = Instant::now();
        let mut request_id = [0u8; 16];
        getrandom::getrandom(&mut request_id).map_err(|_| "OS randomness unavailable")?;
        let pending = self.trusted.header(request_id);
        let request = pending.request()?;
        let bulk_request_encode_ms = ms(start);
        let start = Instant::now();
        let response = peer.respond(&request, mode)?;
        let peer_response_read_copy_encode_ms = ms(start);
        let start = Instant::now();
        let table = self.open_response(&pending, &response)?;
        let owner_full_frame_decode_root_and_binding_ms = ms(start);
        let start = Instant::now();
        counters.prepare_calls.set(counters.prepare_calls.get() + 1);
        let prepared = self.owner.prepare_exact_aggregate_for_experiment(
            &table,
            AgeRange::equal(case.age),
            256,
            data_limits(),
        )?;
        counters
            .prepare_successes
            .set(counters.prepare_successes.get() + 1);
        let selected_rows = prepared.selected_rows();
        let owner_exact_select_auth_fresh_encrypt_ms = ms(start);
        let bfv_request_bytes = prepared.request().len();
        counters
            .peer_evaluations
            .set(counters.peer_evaluations.get() + 1);
        let evaluated = peer
            .evaluator
            .evaluate_exact_aggregate(prepared.request())?;
        let bfv_response_bytes = evaluated.output.len();
        if evaluated.stats.ct_ct_multiplications != 0
            || evaluated.stats.rotations != 8
            || evaluated.stats.multiplicative_depth != 0
        {
            return Err("Exact eight-rotation kernel profile changed".into());
        }
        let start = Instant::now();
        if !self.trusted.agrees(&pending) {
            return Err(WireError::Binding.into());
        }
        let actual = self
            .owner
            .complete_exact_aggregate_unverified_for_experiment(
                &table,
                prepared,
                &evaluated.output,
            )?;
        counters
            .owner_completions
            .set(counters.owner_completions.get() + 1);
        let owner_completion_ms = ms(start);
        let start = Instant::now();
        let payload_sha256 = Sha256::digest(&response[HEADER_BYTES..]).into();
        let diagnostic_payload_hash_ms = ms(start);
        let stages = Stages {
            bulk_request_encode_ms,
            peer_response_read_copy_encode_ms,
            owner_full_frame_decode_root_and_binding_ms,
            owner_exact_select_auth_fresh_encrypt_ms,
            owner_completion_ms,
            diagnostic_payload_hash_ms,
            peer: evaluated.stats,
            bulk_request_bytes: request.len(),
            bulk_response_bytes: response.len(),
            bfv_request_bytes,
            bfv_response_bytes,
        };
        drop(evaluated.output);
        drop(table);
        drop(response);
        drop(request);
        Ok(ReadResult {
            whole_ms: ms(all),
            stages,
            actual,
            selected_rows,
            payload_sha256,
        })
    }
}
