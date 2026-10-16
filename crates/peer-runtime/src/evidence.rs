//! Public validation of exact FHE jobs and owner-finalized root publication.
//! Private authenticated selection and AEAD writeback remain designated-client work.
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use bfv_query_core::{PublicUpdateEvaluator, PublicUpdateParameters};
use compact_store::Commitment;
use sha2::{Digest, Sha256};
use version_journal::{HeadPair, ShardState, TransitionStatement, TransitionVerifier};

use crate::{Operation, ProofReply, RemoteError};

pub const MAX_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_JOBS: usize = 32;
pub const MAX_JOB_BYTES: usize = 2 * 1024 * 1024;
const VERIFIED_PROOF_CACHE_ENTRIES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationJob {
    pub shard: u64,
    pub request: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct MutationManifest {
    /// Opaque application query identity, signed along with all exact job requests.
    pub query_binding: [u8; 32],
    pub operation: Operation,
    pub previous_shards: Vec<ShardState>,
    pub jobs: Vec<MutationJob>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationEvidence {
    /// Same canonical shard/job order as the exact signed manifest.
    pub jobs: Vec<ProofReply>,
}

fn invalid() -> RemoteError {
    RemoteError::InvalidRequest
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, RemoteError> {
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(RemoteError::ResourceLimit);
        }
        Ok(Self { bytes, offset: 0 })
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], RemoteError> {
        let end = self.offset.checked_add(count).ok_or_else(invalid)?;
        let slice = self.bytes.get(self.offset..end).ok_or_else(invalid)?;
        self.offset = end;
        Ok(slice)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RemoteError> {
        self.take(N)?.try_into().map_err(|_| invalid())
    }
    fn u32(&mut self) -> Result<u32, RemoteError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, RemoteError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self) -> Result<usize, RemoteError> {
        let count = self.u32()? as usize;
        if count == 0 || count > MAX_JOBS {
            return Err(RemoteError::ResourceLimit);
        }
        Ok(count)
    }
    fn blob(&mut self) -> Result<Vec<u8>, RemoteError> {
        let size = self.u32()? as usize;
        if size == 0 || size > MAX_JOB_BYTES {
            return Err(RemoteError::ResourceLimit);
        }
        Ok(self.take(size)?.to_vec())
    }
    fn finish(self) -> Result<(), RemoteError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
fn push_blob(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RemoteError> {
    if bytes.is_empty()
        || bytes.len() > MAX_JOB_BYTES
        || output
            .len()
            .checked_add(4 + bytes.len())
            .is_none_or(|n| n > MAX_EVIDENCE_BYTES)
    {
        return Err(RemoteError::ResourceLimit);
    }
    output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}
fn put_heads(bytes: &mut Vec<u8>, heads: HeadPair) {
    bytes.extend_from_slice(&heads.data);
    bytes.extend_from_slice(&heads.index);
}
fn read_heads(reader: &mut Reader<'_>) -> Result<HeadPair, RemoteError> {
    Ok(HeadPair {
        data: reader.array()?,
        index: reader.array()?,
    })
}
impl MutationManifest {
    pub fn encode(&self) -> Result<Vec<u8>, RemoteError> {
        self.check_shape()?;
        let mut bytes = b"DCSMUT01".to_vec();
        bytes.extend_from_slice(&self.query_binding);
        bytes.push(match self.operation {
            Operation::Insert => 1,
            Operation::Update => 2,
            _ => return Err(invalid()),
        });
        bytes.extend_from_slice(&(self.previous_shards.len() as u32).to_le_bytes());
        for shard in &self.previous_shards {
            bytes.extend_from_slice(&shard.id.to_le_bytes());
            put_heads(&mut bytes, shard.heads);
        }
        bytes.extend_from_slice(&(self.jobs.len() as u32).to_le_bytes());
        for job in &self.jobs {
            bytes.extend_from_slice(&job.shard.to_le_bytes());
            push_blob(&mut bytes, &job.request)?;
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RemoteError> {
        let mut reader = Reader::new(bytes)?;
        if reader.take(8)? != b"DCSMUT01" {
            return Err(invalid());
        }
        let query_binding = reader.array()?;
        let operation = match reader.array::<1>()?[0] {
            1 => Operation::Insert,
            2 => Operation::Update,
            _ => return Err(invalid()),
        };
        let count = reader.count()?;
        if reader.bytes.len().saturating_sub(reader.offset) < count * 232 {
            return Err(invalid());
        }
        let mut previous_shards = Vec::with_capacity(count);
        for _ in 0..count {
            previous_shards.push(ShardState {
                id: reader.u64()?,
                heads: read_heads(&mut reader)?,
            });
        }
        let count = reader.count()?;
        let mut jobs = Vec::with_capacity(count);
        for _ in 0..count {
            jobs.push(MutationJob {
                shard: reader.u64()?,
                request: reader.blob()?,
            });
        }
        reader.finish()?;
        let value = Self {
            query_binding,
            operation,
            previous_shards,
            jobs,
        };
        value.check_shape()?;
        Ok(value)
    }
    fn check_shape(&self) -> Result<(), RemoteError> {
        if self.previous_shards.is_empty()
            || self.previous_shards.len() > MAX_JOBS
            || self.jobs.is_empty()
            || self.jobs.len() > MAX_JOBS
            || self.previous_shards.windows(2).any(|w| w[0].id >= w[1].id)
            || self.jobs.windows(2).any(|w| w[0].shard >= w[1].shard)
        {
            return Err(invalid());
        }
        match self.operation {
            Operation::Update
                if self.jobs.len() != self.previous_shards.len()
                    || !self
                        .jobs
                        .iter()
                        .zip(&self.previous_shards)
                        .all(|(job, state)| job.shard == state.id) =>
            {
                Err(invalid())
            }
            Operation::Insert
                if self.jobs.len() != 1
                    || !self
                        .previous_shards
                        .iter()
                        .any(|s| s.id == self.jobs[0].shard) =>
            {
                Err(invalid())
            }
            Operation::Update | Operation::Insert => Ok(()),
            _ => Err(invalid()),
        }
    }
}
impl MutationEvidence {
    pub fn encode(&self) -> Result<Vec<u8>, RemoteError> {
        if self.jobs.is_empty() || self.jobs.len() > MAX_JOBS {
            return Err(RemoteError::ResourceLimit);
        }
        let mut bytes = b"DCSMUE01".to_vec();
        bytes.extend_from_slice(&(self.jobs.len() as u32).to_le_bytes());
        for job in &self.jobs {
            push_blob(&mut bytes, &job.output)?;
            push_blob(&mut bytes, &job.proof)?;
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RemoteError> {
        let mut reader = Reader::new(bytes)?;
        if reader.take(8)? != b"DCSMUE01" {
            return Err(invalid());
        }
        let count = reader.count()?;
        let mut jobs = Vec::with_capacity(count);
        for _ in 0..count {
            jobs.push(ProofReply {
                output: reader.blob()?,
                proof: reader.blob()?,
            });
        }
        reader.finish()?;
        Ok(Self { jobs })
    }
}

pub struct JobVerifier {
    evaluator: Arc<PublicUpdateEvaluator>,
    application_commitment: [u8; 32],
    verified: Mutex<VerifiedProofCache>,
}
#[derive(Default)]
struct VerifiedProofCache {
    entries: BTreeSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}
impl VerifiedProofCache {
    fn insert(&mut self, key: [u8; 32]) {
        if !self.entries.insert(key) {
            return;
        }
        self.order.push_back(key);
        if self.order.len() > VERIFIED_PROOF_CACHE_ENTRIES
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
    }
}
impl JobVerifier {
    pub fn new(parameters: PublicUpdateParameters) -> Result<Self, RemoteError> {
        let bytes = parameters.to_bytes().map_err(crypto)?;
        let evaluator =
            Arc::new(PublicUpdateEvaluator::from_parameters(&parameters).map_err(crypto)?);
        let mut application = Sha256::new();
        application.update(b"dcs/peer-runtime/proved-job-application/v1");
        application.update((bytes.len() as u64).to_le_bytes());
        application.update(&bytes);
        application.update(bfv_query_proof::PROOF_PROFILE_ID);
        Ok(Self {
            evaluator,
            application_commitment: application.finalize().into(),
            verified: Mutex::new(VerifiedProofCache::default()),
        })
    }
    pub fn application_commitment(&self) -> [u8; 32] {
        self.application_commitment
    }
    pub fn evaluator(&self) -> Arc<PublicUpdateEvaluator> {
        self.evaluator.clone()
    }
    pub fn circuit_request(
        &self,
        operation: Operation,
        request: &[u8],
    ) -> Result<Vec<u8>, RemoteError> {
        circuit_request(&self.evaluator, operation, request)
    }
    /// Derives the exact canonical input from the caller's trusted original job,
    /// verifies its serialized proof, and retains that successful verification for
    /// later journal validation. The returned arithmetic marker does not establish
    /// authenticated SQL selection, authorization, head agreement or freshness.
    pub fn check_job(
        &self,
        operation: Operation,
        trusted_request: &[u8],
        reply: &ProofReply,
    ) -> Result<bfv_query_proof::CheckedOperation, RemoteError> {
        let input = self.circuit_request(operation, trusted_request)?;
        let checked =
            bfv_query_proof::verify(&input, &reply.output, &reply.proof).map_err(crypto)?;
        self.remember_verified(self.arithmetic_key(&input, reply))
            .map_err(crypto)?;
        Ok(checked)
    }
    fn arithmetic_key(&self, input: &[u8], reply: &ProofReply) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"dcs/peer-runtime/verified-arithmetic/v1");
        digest.update(self.application_commitment);
        for part in [input, reply.output.as_slice(), reply.proof.as_slice()] {
            digest.update((part.len() as u64).to_le_bytes());
            digest.update(part);
        }
        digest.finalize().into()
    }
    fn remember_verified(&self, key: [u8; 32]) -> version_journal::Result<()> {
        self.verified
            .lock()
            .map_err(|_| version_journal::Error::RejectedComputationProof)?
            .insert(key);
        Ok(())
    }
    fn verify_arithmetic(&self, input: &[u8], reply: &ProofReply) -> version_journal::Result<()> {
        let key = self.arithmetic_key(input, reply);
        if self
            .verified
            .lock()
            .map_err(|_| version_journal::Error::RejectedComputationProof)?
            .entries
            .contains(&key)
        {
            return Ok(());
        }
        bfv_query_proof::verify(input, &reply.output, &reply.proof)
            .map_err(|_| version_journal::Error::RejectedComputationProof)?;
        // Only a successful genuine proof verification can create this entry.
        // Parent/header/context/freshness/manifest validation remains outside it.
        self.remember_verified(key)
    }
}
pub(crate) fn circuit_request(
    evaluator: &PublicUpdateEvaluator,
    operation: Operation,
    request: &[u8],
) -> Result<Vec<u8>, RemoteError> {
    if request.len() > MAX_JOB_BYTES {
        return Err(RemoteError::ResourceLimit);
    }
    match operation {
        Operation::Select => evaluator.select_circuit_request(request),
        Operation::Insert => evaluator.insert_circuit_request(request),
        Operation::Update => evaluator.circuit_request(request),
        Operation::ByteSelect => evaluator.byte_select_circuit_request(request),
        Operation::Aggregate => return Err(invalid()),
    }
    .map_err(crypto)
}
fn crypto(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Cryptography(error.to_string())
}
impl TransitionVerifier for JobVerifier {
    fn verify(&self, statement: TransitionStatement<'_>) -> version_journal::Result<()> {
        let bad = version_journal::Error::RejectedComputationProof;
        if statement.application_commitment != self.application_commitment {
            return Err(bad);
        }
        let manifest = MutationManifest::decode(statement.request).map_err(|_| bad.clone())?;
        let evidence = MutationEvidence::decode(statement.proof).map_err(|_| bad.clone())?;
        if manifest.previous_shards != statement.previous_shards
            || evidence.jobs.len() != manifest.jobs.len()
        {
            return Err(bad);
        }
        for update in statement.updates {
            if !manifest.jobs.iter().any(|job| job.shard == update.id) {
                return Err(bad);
            }
            check_head_change(
                update.old,
                update.new,
                manifest.operation,
                statement.database,
            )
            .map_err(|_| bad.clone())?;
        }
        if manifest.operation == Operation::Insert
            && (statement.updates.len() != 1 || statement.updates[0].id != manifest.jobs[0].shard)
        {
            return Err(bad);
        }
        for (job, proof) in manifest.jobs.iter().zip(&evidence.jobs) {
            let old = manifest
                .previous_shards
                .iter()
                .find(|s| s.id == job.shard)
                .ok_or_else(|| bad.clone())?;
            let context = self
                .evaluator
                .request_context(&job.request)
                .map_err(|_| bad.clone())?;
            if context.data_head() != old.heads.data || context.index_head() != old.heads.index {
                return Err(bad);
            }
            let input = self
                .circuit_request(manifest.operation, &job.request)
                .map_err(|_| bad.clone())?;
            self.verify_arithmetic(&input, proof)?;
        }
        Ok(())
    }
}

fn check_head_change(
    old: HeadPair,
    new: HeadPair,
    operation: Operation,
    database: [u8; 16],
) -> Result<(), RemoteError> {
    for (before, after, data) in [(old.data, new.data, true), (old.index, new.index, false)] {
        let old = Commitment::decode(&before, crate::store::custody_limits()).map_err(crypto)?;
        let new = Commitment::decode(&after, crate::store::custody_limits()).map_err(crypto)?;
        if old.database() != database
            || new.database() != database
            || old.key_domain() != new.key_domain()
            || old.layout().schema != new.layout().schema
            || old.layout().row_width != new.layout().row_width
            || old.layout().rows_per_page != new.layout().rows_per_page
            || old.revision().checked_add(1) != Some(new.revision())
        {
            return Err(RemoteError::Integrity);
        }
        if operation == Operation::Update && old.layout() != new.layout() {
            return Err(RemoteError::Integrity);
        }
        if operation == Operation::Insert
            && data
            && old.layout().row_count.checked_add(1) != Some(new.layout().row_count)
        {
            return Err(RemoteError::Integrity);
        }
        if operation == Operation::Insert
            && !data
            && new.layout().row_count < old.layout().row_count
        {
            return Err(RemoteError::Integrity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public codec fixtures are not valid FHE requests or proofs and are never
    // passed off as successful cryptographic verification.
    fn manifest() -> MutationManifest {
        MutationManifest {
            query_binding: [1; 32],
            operation: Operation::Update,
            previous_shards: vec![
                ShardState {
                    id: 7,
                    heads: HeadPair {
                        data: [2; 112],
                        index: [3; 112],
                    },
                },
                ShardState {
                    id: 9,
                    heads: HeadPair {
                        data: [4; 112],
                        index: [5; 112],
                    },
                },
            ],
            jobs: vec![
                MutationJob {
                    shard: 7,
                    request: vec![6],
                },
                MutationJob {
                    shard: 9,
                    request: vec![7],
                },
            ],
        }
    }
    #[test]
    fn canonical_manifest_preserves_every_original_job_and_rejects_omission() {
        let manifest = manifest();
        let bytes = manifest.encode().unwrap();
        let decoded = MutationManifest::decode(&bytes).unwrap();
        assert_eq!(decoded.previous_shards, manifest.previous_shards);
        assert_eq!(decoded.jobs, manifest.jobs);
        assert_eq!(decoded.query_binding, manifest.query_binding);
        let mut omitted = manifest;
        omitted.jobs.pop();
        assert!(omitted.encode().is_err());
    }
    #[test]
    fn insert_manifest_contains_exactly_one_existing_shard_job() {
        let mut manifest = manifest();
        manifest.operation = Operation::Insert;
        assert!(manifest.encode().is_err());
        manifest.jobs.pop();
        assert!(MutationManifest::decode(&manifest.encode().unwrap()).is_ok());
        manifest.jobs[0].shard = 99;
        assert!(manifest.encode().is_err());
    }
    #[test]
    fn a_proved_read_can_never_be_encoded_as_a_database_mutation() {
        let mut manifest = manifest();
        for operation in [
            Operation::Select,
            Operation::ByteSelect,
            Operation::Aggregate,
        ] {
            manifest.operation = operation;
            assert!(matches!(
                manifest.encode(),
                Err(RemoteError::InvalidRequest)
            ));
        }

        // These wire operation tags belong only to actual mutating circuits.
        // An invented read tag must also fail when bypassing the public encoder.
        let mut bytes = MutationManifest {
            operation: Operation::Update,
            ..manifest
        }
        .encode()
        .unwrap();
        for tag in [0, 3, 4, u8::MAX] {
            bytes[40] = tag;
            assert!(matches!(
                MutationManifest::decode(&bytes),
                Err(RemoteError::InvalidRequest)
            ));
        }
    }
    #[test]
    fn hostile_manifest_lengths_and_trailing_data_fail_before_allocation() {
        let bytes = manifest().encode().unwrap();
        for length in 0..bytes.len() {
            assert!(MutationManifest::decode(&bytes[..length]).is_err());
        }
        let mut hostile = bytes.clone();
        hostile[521..525].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            MutationManifest::decode(&hostile),
            Err(RemoteError::ResourceLimit)
        ));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(MutationManifest::decode(&trailing).is_err());
    }
    #[test]
    fn evidence_codec_bounds_each_job_and_does_not_ignore_trailing_bytes() {
        let evidence = MutationEvidence {
            jobs: vec![ProofReply {
                output: vec![1, 2],
                proof: vec![3, 4],
            }],
        };
        let bytes = evidence.encode().unwrap();
        assert_eq!(MutationEvidence::decode(&bytes).unwrap(), evidence);
        let mut hostile = bytes.clone();
        hostile[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            MutationEvidence::decode(&hostile),
            Err(RemoteError::ResourceLimit)
        ));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(MutationEvidence::decode(&trailing).is_err());
    }
    #[test]
    fn checking_an_original_job_caches_only_its_exact_verified_input_output_and_proof() {
        use bfv_query_core::{Geometry, Owner, QueryContext, SelectedField};
        // Fresh in-memory FHE keys and actual peer arithmetic. These literal
        // context fixtures test arithmetic caching only, not SQL/head acceptance.
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let verifier = JobVerifier::new(setup.update_parameters().unwrap()).unwrap();
        let prepared = owner
            .prepare_indexed_update_for_experiment(
                QueryContext::new([1; 16], [2; 112], [3; 112]),
                &[SelectedField {
                    age: 18,
                    amount: 20,
                    active: true,
                }],
                5,
            )
            .unwrap();
        let input = verifier
            .circuit_request(Operation::Update, &prepared.request)
            .unwrap();
        let genuine = bfv_query_proof::prove(&input).unwrap();
        let reply = ProofReply {
            output: genuine.output().to_vec(),
            proof: genuine.proof().to_vec(),
        };
        let checked = verifier
            .check_job(Operation::Update, &prepared.request, &reply)
            .unwrap();
        assert!(checked.matches_statement(&input, &reply.output));
        verifier.verify_arithmetic(&input, &reply).unwrap();
        assert_eq!(verifier.verified.lock().unwrap().entries.len(), 1);

        assert!(
            verifier
                .check_job(Operation::Insert, &prepared.request, &reply)
                .is_err()
        );
        let mut changed_request = prepared.request.clone();
        let last = changed_request.len() - 1;
        changed_request[last] ^= 1;
        assert!(
            verifier
                .check_job(Operation::Update, &changed_request, &reply)
                .is_err()
        );
        let mut rebound = input.clone();
        rebound[8] ^= 1;
        assert!(verifier.verify_arithmetic(&rebound, &reply).is_err());
        let mut wrong_output = reply.clone();
        wrong_output.output[40] ^= 1;
        assert!(
            verifier
                .check_job(Operation::Update, &prepared.request, &wrong_output)
                .is_err()
        );
        assert!(verifier.verify_arithmetic(&input, &wrong_output).is_err());
        let mut wrong_proof = reply;
        let end = wrong_proof.proof.len() - 1;
        wrong_proof.proof[end] ^= 1;
        assert!(
            verifier
                .check_job(Operation::Update, &prepared.request, &wrong_proof)
                .is_err()
        );
        assert!(verifier.verify_arithmetic(&input, &wrong_proof).is_err());
        assert_eq!(verifier.verified.lock().unwrap().entries.len(), 1);
    }
    #[test]
    fn cached_arithmetic_still_requires_original_heads_and_pinned_application_parameters() {
        use bfv_query_core::{Geometry, Owner, QueryContext, SelectedField};
        use version_journal::{HeadRef, ShardUpdate};

        // Public context fixtures exercise this application's proof boundary.
        // They are not accepted journal blocks, agreed heads or SQL results.
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let parameters = setup.update_parameters().unwrap();
        let legacy_application = version_journal::hash(&parameters.to_bytes().unwrap());
        let verifier = JobVerifier::new(parameters).unwrap();
        let prepared = owner
            .prepare_indexed_update_for_experiment(
                QueryContext::new([1; 16], [2; 112], [3; 112]),
                &[SelectedField {
                    age: 18,
                    amount: 20,
                    active: true,
                }],
                5,
            )
            .unwrap();
        let input = verifier
            .circuit_request(Operation::Update, &prepared.request)
            .unwrap();
        let genuine = bfv_query_proof::prove(&input).unwrap();
        let reply = ProofReply {
            output: genuine.output().to_vec(),
            proof: genuine.proof().to_vec(),
        };
        verifier
            .check_job(Operation::Update, &prepared.request, &reply)
            .unwrap();
        let manifest = MutationManifest {
            query_binding: [4; 32],
            operation: Operation::Update,
            previous_shards: vec![ShardState {
                id: 7,
                heads: HeadPair {
                    data: [2; 112],
                    index: [3; 112],
                },
            }],
            jobs: vec![MutationJob {
                shard: 7,
                request: prepared.request,
            }],
        };
        let request = manifest.encode().unwrap();
        let evidence = MutationEvidence { jobs: vec![reply] }.encode().unwrap();
        let statement = TransitionStatement {
            genesis: [5; 32],
            database: [6; 16],
            application_commitment: verifier.application_commitment(),
            parent: HeadRef {
                genesis: [5; 32],
                database: [6; 16],
                block: [7; 32],
                height: 1,
                state_root: [8; 32],
            },
            previous_shards: &manifest.previous_shards,
            next_shards: &manifest.previous_shards,
            request: &request,
            updates: &[],
            proof: &evidence,
            next_state_root: [9; 32],
        };

        // A genuine arithmetic cache hit still runs every surrounding rule.
        assert!(verifier.verify(TransitionStatement { ..statement }).is_ok());
        assert!(
            verifier
                .verify(TransitionStatement {
                    // The old setup-only anchor cannot advertise this new
                    // accepted arithmetic proof format, even on a cache hit.
                    application_commitment: legacy_application,
                    ..statement
                })
                .is_err()
        );
        let mut rebound = manifest.clone();
        rebound.previous_shards[0].heads.data[0] ^= 1;
        let rebound_request = rebound.encode().unwrap();
        assert!(
            verifier
                .verify(TransitionStatement {
                    previous_shards: &rebound.previous_shards,
                    request: &rebound_request,
                    ..statement
                })
                .is_err()
        );
        let invalid_head_change = [ShardUpdate {
            id: 7,
            old: manifest.previous_shards[0].heads,
            new: manifest.previous_shards[0].heads,
        }];
        assert!(
            verifier
                .verify(TransitionStatement {
                    updates: &invalid_head_change,
                    ..statement
                })
                .is_err()
        );
    }
    #[test]
    fn typed_byte_reads_require_their_exact_proved_operation_and_original_request() {
        use bfv_query_core::{Geometry, Owner, QueryContext};
        // Public fixture bytes stand in for an owner's authenticated page. This
        // boundary proves arithmetic; catalog completeness/freshness is checked
        // independently by the storage client before accepting a SQL result.
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let verifier = JobVerifier::new(setup.update_parameters().unwrap()).unwrap();
        let prepared = owner
            .prepare_byte_select(
                QueryContext::new([1; 16], [2; 112], [3; 112]),
                [4; 32],
                &[0, 127, 128, 255, b'A', b'B'],
                &[true, true, true, true, false, false],
            )
            .unwrap();

        let input = verifier
            .circuit_request(Operation::ByteSelect, &prepared.request)
            .unwrap();
        let genuine = bfv_query_proof::prove(&input).unwrap();
        let reply = ProofReply {
            output: genuine.output().to_vec(),
            proof: genuine.proof().to_vec(),
        };
        verifier.verify_arithmetic(&input, &reply).unwrap();

        for wrong in [
            Operation::Select,
            Operation::Insert,
            Operation::Update,
            Operation::Aggregate,
        ] {
            assert!(verifier.circuit_request(wrong, &prepared.request).is_err());
        }
        let other = owner
            .prepare_byte_select(
                QueryContext::new([1; 16], [2; 112], [3; 112]),
                [5; 32],
                &[0, 127, 128, 255, b'A', b'B'],
                &[true, true, true, true, false, false],
            )
            .unwrap();
        let rebound = verifier
            .circuit_request(Operation::ByteSelect, &other.request)
            .unwrap();
        assert!(verifier.verify_arithmetic(&rebound, &reply).is_err());
        let mut tampered = reply;
        tampered.output[40] ^= 1;
        assert!(verifier.verify_arithmetic(&input, &tampered).is_err());
        assert_eq!(verifier.verified.lock().unwrap().entries.len(), 1);
    }
    #[test]
    fn verified_proof_digest_cache_has_fixed_capacity_and_discards_oldest_entries() {
        let mut cache = VerifiedProofCache::default();
        for ordinal in 0..=VERIFIED_PROOF_CACHE_ENTRIES {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&(ordinal as u64).to_le_bytes());
            cache.insert(key);
        }
        assert_eq!(cache.entries.len(), VERIFIED_PROOF_CACHE_ENTRIES);
        assert_eq!(cache.order.len(), VERIFIED_PROOF_CACHE_ENTRIES);
        assert!(!cache.entries.contains(&[0; 32]));
    }
}
