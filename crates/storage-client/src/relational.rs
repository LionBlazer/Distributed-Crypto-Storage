//! Typed, owner-indexed encrypted relations. No imported plaintext is retained by
//! the session and no peer has a decryption key. Every accepted SELECT byte comes
//! from a genuine proved BFV projection of authenticated source cells.
mod agreement;
mod index;

use super::{Error, Participant, Result, ShardInfo, install};
use crate::query_rpc::{ProofJob, Requests};
use bfv_query_core::{Geometry, PublicUpdateEvaluator, QueryContext};
use compact_store::{EncryptedSnapshot, Layout, Limits};
use peer_runtime::{Bundle, JobVerifier, Operation, Request, Response};
use relational_types::{ImportedDatabase, Row, TableSchema, Value};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};
use version_journal::{
    Freshness, Genesis, HeadPair, HeadRef, Journal, ProtocolProfile, ShardState,
};
use zeroize::Zeroizing;

const PAGE_BYTES: u32 = 16 * 1024;
const MAX_TABLE_BYTES: usize = 8 * 1024 * 1024;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidInput(message.to_string())
}
fn crypto(message: impl std::fmt::Display) -> Error {
    Error::Cryptography(message.to_string())
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(crypto)?;
    Ok(bytes)
}
fn limits() -> Limits {
    Limits {
        max_rows: MAX_TABLE_BYTES as u64,
        ..Limits::default()
    }
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(crypto)
}
fn schema_id(schema: &TableSchema, index: bool) -> Result<[u8; 16]> {
    let mut bytes = json(schema)?;
    bytes.extend_from_slice(if index {
        b"typed-index-v2"
    } else {
        b"typed-data-v1"
    });
    Ok(version_journal::hash(&bytes)[..16]
        .try_into()
        .expect("fixed hash"))
}
fn seal(owner: &compact_store::Owner, schema: [u8; 16], bytes: &[u8]) -> Result<EncryptedSnapshot> {
    owner
        .seal(
            Layout {
                schema,
                row_width: 1,
                rows_per_page: PAGE_BYTES,
                row_count: bytes.len() as u64,
            },
            bytes,
            limits(),
        )
        .map_err(crypto)
}

#[derive(Clone, Serialize, Deserialize)]
struct Cell {
    offset: usize,
    length: usize,
}
#[derive(Serialize, Deserialize)]
struct Posting {
    value: Value,
    rows: Vec<usize>,
}
#[derive(Serialize, Deserialize)]
struct PrivateIndex {
    format: u32,
    schema: TableSchema,
    cells: Vec<Vec<Cell>>,
    columns: Vec<Vec<Posting>>,
    data_bytes: usize,
    catalog_objects: Vec<relational_types::SchemaObject>,
    import_notices: Vec<String>,
}
struct Relation {
    schema: TableSchema,
    shard: ShardInfo,
}

/// The complete accepted result, including the independently checked read head.
#[derive(Debug)]
pub struct Selected {
    pub columns: Vec<String>,
    pub rows: Vec<Row>,
    pub version: HeadRef,
    pub proof_blocks: usize,
    pub elapsed: std::time::Duration,
}

/// An imported typed catalog is an immutable, authorized encrypted genesis.
/// SQL mutations of this catalog require separate typed transition circuits;
/// unsupported syntax fails before network execution, never runs in plaintext.
pub struct RelationalSession {
    name: String,
    owner: compact_store::Owner,
    fhe: bfv_query_core::Owner,
    evaluator: PublicUpdateEvaluator,
    setup: Vec<u8>,
    setup_id: [u8; 32],
    participants: Vec<Participant>,
    relations: Vec<Relation>,
    journal: Journal,
    verifier: JobVerifier,
    floor: HeadRef,
}

impl RelationalSession {
    pub fn import(
        database: ImportedDatabase,
        mut participants: Vec<Participant>,
        profile: ProtocolProfile,
    ) -> Result<Self> {
        profile.validate().map_err(crypto)?;
        relational_types::validate_database(&database).map_err(invalid)?;
        if database.tables.is_empty()
            || database.tables.len() > profile.max_shards as usize
            || participants.is_empty()
        {
            return Err(invalid(
                "Import needs tables, reachable peers and a contract admitting every table",
            ));
        }
        participants.sort_by_key(|p| p.id);
        if participants.windows(2).any(|p| p[0].id == p[1].id) {
            return Err(invalid("Duplicate participant identity"));
        }
        let database_id = random()?;
        let owner = compact_store::Owner::generate(database_id).map_err(crypto)?;
        let (fhe, public) = bfv_query_core::Owner::generate(Geometry::Rows256).map_err(crypto)?;
        let parameters = public.update_parameters().map_err(crypto)?;
        let evaluator = PublicUpdateEvaluator::from_parameters(&parameters).map_err(crypto)?;
        let verifier = JobVerifier::new(parameters).map_err(crypto)?;
        let setup = public.to_bytes().map_err(crypto)?;
        let setup_id = version_journal::hash(&setup);
        // Validate and seal the complete import before writing to any peer.
        let mut sealed = Vec::new();
        for (slot, table) in database.tables.into_iter().enumerate() {
            let (bytes, mut index) = PrivateIndex::build(table)?;
            if slot == 0 {
                index.catalog_objects = database.objects.clone();
                index.import_notices = database.notices.clone();
            }
            let data = seal(&owner, schema_id(&index.schema, false)?, &bytes)?;
            let encoded_index = Zeroizing::new(json(&index)?);
            let encrypted_index = seal(&owner, schema_id(&index.schema, true)?, &encoded_index)?;
            let bundle = Bundle {
                data_head: data.commitment().encode().to_vec(),
                index_head: encrypted_index.commitment().encode().to_vec(),
                data: data.encode(),
                index: encrypted_index.encode(),
            };
            let relation = Relation {
                schema: index.schema,
                shard: ShardInfo {
                    id: (slot + 1) as u64,
                    object: bundle.id(),
                    holders: Vec::new(),
                    rows: index.cells.len(),
                    data_head: data.commitment().clone(),
                    index_head: encrypted_index.commitment().clone(),
                },
            };
            sealed.push((relation, bundle));
        }
        for participant in &participants {
            if install(&participant.remote, &setup)? != setup_id {
                return Err(crypto("Wrong public setup acknowledgement"));
            }
        }
        let mut relations = Vec::new();
        for (slot, (mut relation, bundle)) in sealed.into_iter().enumerate() {
            for offset in 0..participants.len().min(2) {
                let participant = &participants[(slot + offset) % participants.len()];
                match participant.remote.call(Request::Store(bundle.clone()))? {
                    Response::Stored(info) if info.id == relation.shard.object => {
                        relation.shard.holders.push(participant.id)
                    }
                    _ => return Err(crypto("Wrong encrypted relation acknowledgement")),
                }
            }
            relations.push(relation);
        }
        let signer = ed25519_dalek::SigningKey::from_bytes(&random()?);
        let genesis = Genesis {
            network_id: random()?,
            database: database_id,
            owner: signer.verifying_key().to_bytes(),
            application_commitment: verifier.application_commitment(),
            timestamp: agreement::now().saturating_sub(1),
            profile,
            initial_shards: relations
                .iter()
                .map(|r| ShardState {
                    id: r.shard.id,
                    heads: HeadPair {
                        data: r.shard.data_head.encode(),
                        index: r.shard.index_head.encode(),
                    },
                })
                .collect(),
        };
        let journal = Journal::new(genesis).map_err(crypto)?;
        let floor = journal.genesis_head();
        let mut session = Self {
            name: database.name,
            owner,
            fhe,
            evaluator,
            setup,
            setup_id,
            participants,
            relations,
            journal,
            verifier,
            floor,
        };
        session.initialize()?;
        Ok(session)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn schemas(&self) -> Vec<TableSchema> {
        self.relations.iter().map(|r| r.schema.clone()).collect()
    }
    pub fn shards(&self) -> Vec<ShardInfo> {
        self.relations.iter().map(|r| r.shard.clone()).collect()
    }
    pub fn version(&self) -> HeadRef {
        self.floor
    }
    pub fn rows(&self) -> usize {
        self.relations.iter().map(|r| r.shard.rows).sum()
    }
    pub fn replace_participant(&mut self, participant: Participant) -> Result<()> {
        if install(&participant.remote, &self.setup)? != self.setup_id {
            return Err(crypto("Wrong setup"));
        }
        self.initialize_peer(&participant)?;
        if let Some(old) = self
            .participants
            .iter_mut()
            .find(|p| p.id == participant.id)
        {
            *old = participant;
        } else {
            self.participants.push(participant);
        }
        Ok(())
    }
    pub fn copy_shard(&mut self, shard: u64, target: Participant) -> Result<()> {
        self.replace_participant(target.clone())?;
        let relation = self
            .relations
            .iter_mut()
            .find(|r| r.shard.id == shard)
            .ok_or_else(|| invalid("Unknown table shard"))?;
        for source in &self.participants {
            if relation.shard.holders.contains(&source.id)
                && matches!(target.remote.call(Request::Copy { source: source.remote.endpoint().clone(), object: relation.shard.object }), Ok(Response::Stored(info)) if info.id == relation.shard.object)
            {
                if !relation.shard.holders.contains(&target.id) {
                    relation.shard.holders.push(target.id);
                }
                return Ok(());
            }
        }
        Err(Error::UnavailableShard(shard))
    }
    fn fetch(
        &self,
        relation: &Relation,
        requests: &Requests,
    ) -> Result<(EncryptedSnapshot, EncryptedSnapshot)> {
        for peer in &self.participants {
            if !relation.shard.holders.contains(&peer.id) {
                continue;
            }
            let bundle = match requests.call(&peer.remote, Some(relation.shard.object), || {
                Request::Fetch {
                    object: relation.shard.object,
                }
            }) {
                Ok(Response::Bundle(bundle)) => bundle,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    return Err(error.into());
                }
                _ => continue,
            };
            if bundle.id() != relation.shard.object
                || bundle.data_head != relation.shard.data_head.encode()
                || bundle.index_head != relation.shard.index_head.encode()
            {
                continue;
            }
            if let (Ok(data), Ok(index)) = (
                EncryptedSnapshot::decode_for_head(
                    &bundle.data,
                    &relation.shard.data_head,
                    limits(),
                ),
                EncryptedSnapshot::decode_for_head(
                    &bundle.index,
                    &relation.shard.index_head,
                    limits(),
                ),
            ) {
                return Ok((data, index));
            }
        }
        Err(Error::UnavailableShard(relation.shard.id))
    }
    fn decrypt_image(&self, snapshot: &EncryptedSnapshot) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        for page in 0..snapshot
            .commitment()
            .layout()
            .page_count()
            .map_err(crypto)?
        {
            let response = snapshot.lookup(page as u64, limits()).map_err(crypto)?;
            let checked = response
                .verify(snapshot.commitment(), page as u64, limits())
                .map_err(crypto)?;
            bytes.extend_from_slice(self.owner.decrypt(&checked).map_err(crypto)?.as_bytes());
        }
        Ok(bytes)
    }
    fn decrypt_range(
        &self,
        data: &EncryptedSnapshot,
        range: std::ops::Range<usize>,
        cache: &mut BTreeMap<u64, compact_store::PlainPage>,
    ) -> Result<Vec<u8>> {
        if range.end > data.commitment().layout().row_count as usize || range.start > range.end {
            return Err(crypto("Invalid committed cell range"));
        }
        let mut bytes = Vec::with_capacity(range.len());
        let mut offset = range.start;
        while offset < range.end {
            let page = offset as u64 / u64::from(PAGE_BYTES);
            if let std::collections::btree_map::Entry::Vacant(entry) = cache.entry(page) {
                let response = data.lookup(page, limits()).map_err(crypto)?;
                let checked = response
                    .verify(data.commitment(), page, limits())
                    .map_err(crypto)?;
                entry.insert(self.owner.decrypt(&checked).map_err(crypto)?);
            }
            let local = offset % PAGE_BYTES as usize;
            let count = (range.end - offset).min(cache[&page].as_bytes().len() - local);
            bytes.extend_from_slice(&cache[&page].as_bytes()[local..local + count]);
            offset += count;
        }
        Ok(bytes)
    }
    /// Authenticates the complete private postings, prepares only the selected
    /// original cells and accepts each streamed BFV block only after STARK checks.
    pub fn select(&mut self, sql: &str) -> Result<Selected> {
        let started = Instant::now();
        let plan = relational_types::plan_select_schemas(&self.schemas(), sql).map_err(invalid)?;
        let requests = Requests::read_query();
        let version = self.synchronize(&requests)?;
        let relation = &self.relations[plan.table];
        let (data, encrypted_index) = self.fetch(relation, &requests)?;
        let index: PrivateIndex =
            serde_json::from_slice(&self.decrypt_image(&encrypted_index)?).map_err(crypto)?;
        index.validate(
            &relation.schema,
            data.commitment().layout().row_count as usize,
        )?;
        let ordinals = index.select(&plan)?;
        if ordinals
            .len()
            .checked_mul(plan.projection.len())
            .is_none_or(|n| n > 1_000_000)
        {
            return Err(invalid(
                "SELECT exceeds the one-million result-cell budget; use TOP/LIMIT or fewer columns",
            ));
        }
        let mut projected_bytes = 0usize;
        for ordinal in &ordinals {
            for column in &plan.projection {
                projected_bytes = projected_bytes
                    .checked_add(index.cells[*ordinal][*column].length)
                    .ok_or_else(|| invalid("Result byte budget overflow"))?;
                if projected_bytes > 32 * 1024 * 1024 {
                    return Err(invalid(
                        "SELECT exceeds the 32 MiB result budget; use TOP/LIMIT or fewer columns",
                    ));
                }
            }
        }
        let query = version_journal::hash(sql.as_bytes());
        let query_salt: Zeroizing<[u8; 32]> = Zeroizing::new(random()?);
        let mut cache = BTreeMap::new();
        let mut source = Zeroizing::new(Vec::new());
        let mut projection_mask = Vec::new();
        let mut output_cells = Vec::new();
        for ordinal in &ordinals {
            let mut original_cells = Vec::new();
            // Encrypt the ORIGINAL complete row before projection. The peer
            // homomorphically zeroes all unrequested cells; the owner must not
            // manufacture a projected plaintext answer before FHE evaluation.
            for (column, cell) in index.cells[*ordinal].iter().enumerate() {
                let start = source.len();
                source.extend_from_slice(&self.decrypt_range(
                    &data,
                    cell.offset..cell.offset + cell.length,
                    &mut cache,
                )?);
                projection_mask.extend(std::iter::repeat_n(
                    plan.projection.contains(&column),
                    cell.length,
                ));
                original_cells.push(start..source.len());
            }
            output_cells.push(
                plan.projection
                    .iter()
                    .map(|column| original_cells[*column].clone())
                    .collect::<Vec<_>>(),
            );
        }
        drop(cache);
        // An empty relation/result also receives genuine encrypted arithmetic
        // evidence bound to its complete authenticated empty selection.
        let meaningful = source.len();
        if source.is_empty() {
            source.push(0);
            projection_mask.push(false);
        }
        let count = source.len().div_ceil(bfv_query_core::BYTE_SELECT_CAPACITY);
        let nonce: [u8; 16] = random()?;
        let holders: Vec<_> = self
            .participants
            .iter()
            .filter(|peer| relation.shard.holders.contains(&peer.id))
            .cloned()
            .collect();
        if holders.is_empty() {
            return Err(Error::UnavailableShard(relation.shard.id));
        }
        let completed = crate::jobs::run(0..count, |block| {
            let start = block * bfv_query_core::BYTE_SELECT_CAPACITY;
            let end = (start + bfv_query_core::BYTE_SELECT_CAPACITY).min(source.len());
            let original = &source[start..end];
            let binding = version_journal::hash(&json(&(
                "typed-select-v1",
                &relation.schema,
                query,
                query_salt.as_ref(),
                version.block,
                version.state_root,
                relation.shard.id,
                &ordinals,
                &plan.projection,
                block,
                count,
                meaningful,
            ))?);
            let context = QueryContext::new(
                nonce,
                relation.shard.data_head.encode(),
                relation.shard.index_head.encode(),
            );
            let prepared = self
                .fhe
                .prepare_byte_select(
                    context,
                    binding,
                    original,
                    &projection_mask[start..start + original.len()],
                )
                .map_err(crypto)?;
            let (reply, checked) = requests.request(
                &holders[block % holders.len()].remote,
                &holders,
                ProofJob {
                    object: relation.shard.object,
                    setup: self.setup_id,
                    operation: Operation::ByteSelect,
                    ciphertext: &prepared.request,
                },
                |reply| {
                    compact_query::byte_select::check(
                        &self.evaluator,
                        &prepared,
                        &reply.output,
                        &reply.proof,
                    )
                    .map_err(crypto)
                },
            )?;
            Ok(Zeroizing::new(
                compact_query::byte_select::complete_checked(
                    &self.fhe,
                    &self.evaluator,
                    prepared,
                    &reply.output,
                    checked,
                )
                .map_err(crypto)?
                .into_bytes(),
            ))
        })?;
        let mut result = Zeroizing::new(Vec::with_capacity(source.len()));
        for bytes in completed {
            result.extend_from_slice(&bytes);
        }
        result.truncate(meaningful);
        let columns = plan
            .projection
            .iter()
            .map(|column| relation.schema.columns[*column].name.clone())
            .collect();
        let current = self.synchronize(&requests)?;
        self.journal
            .resolve(Freshness::Exact(version))
            .map_err(crypto)?;
        if current.state_root != version.state_root {
            return Err(crypto("Catalog changed during SELECT; result rejected"));
        }
        let rows = output_cells
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|range| relational_types::decode_value(&result[range]).map_err(crypto))
                    .collect::<Result<Row>>()
            })
            .collect::<Result<Vec<Row>>>()?;
        Ok(Selected {
            columns,
            rows,
            version,
            proof_blocks: count,
            elapsed: started.elapsed(),
        })
    }
}
