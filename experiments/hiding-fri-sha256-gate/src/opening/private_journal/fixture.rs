//! Explicit PUBLIC NONSECRET owner/key/rows. Normal CLI, never a live owner API.
use super::{
    Application, Control, Error, Hash, PrivateVerifier, Result, bounded_body,
    request::{self, Operation, Request},
};
use crate::backend::{Error as BackendError, Val};
use crate::opening::{
    Relation, commitment, fixture as source_fixture, locking, registry_bootstrap,
    statement as source, trace as source_trace,
};
use ed25519_dalek::SigningKey;
use p3_field::PrimeCharacteristicRing;
use version_journal::{
    AuthorizedTransition, Body, Genesis, HeadPair, HeadRef, Header, Journal, ProtocolProfile,
    ShardUpdate, Target,
};

pub(super) const SOURCE_ID: u64 = 7;
pub(super) const CONTROL_ID: u64 = 8;
const OPEN_SALT: [Val; 4] = [Val::new(5); 4];
const REGISTRY_SALT: [Val; 4] = [Val::new(13); 4];
const CONTROLLERS: [[u8; 32]; 2] = [[0x41; 32], [0x42; 32]];
fn backend<T>(value: std::result::Result<T, BackendError>) -> Result<T> {
    value.map_err(|_| Error::RejectedComputationProof)
}

pub(super) struct Fixture {
    pub(super) application: Application,
    pub(super) genesis: Genesis,
    initial: source::Statement,
    source_witness: source_trace::Witness,
    plain: [u8; 2348],
}
pub(super) struct RegistryInput<'a> {
    pub(super) state: &'a locking::trace::Registry,
    pub(super) salt: [Val; 4],
}
pub(super) struct LockQuery<'a> {
    pub(super) actor: u8,
    pub(super) sql: &'a str,
    pub(super) nonce: Hash,
}
pub(super) struct Step {
    pub(super) body: Body,
    pub(super) next: locking::trace::Registry,
    pub(super) salt: [Val; 4],
    pub(super) outcome: u8,
    pub(super) returned: [bool; 4],
    pub(super) skipped: [bool; 4],
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let suffix = source_fixture::canonical_suffix();
        // Encrypt ONCE. Every command below changes only request/opening, never packets or heads.
        let (initial, source_witness) = backend(source_fixture::from_suffix(
            Relation::CanonicalIndex,
            [0x71; 32],
            ([Val::from_u8(3); 4], OPEN_SALT),
            [0x83; 32],
            data,
            &suffix,
        ))?;
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..124].copy_from_slice(&initial.heads[0]);
        plain[124..].copy_from_slice(&suffix);
        let application = Application::new([0xA9; 32], SOURCE_ID, CONTROL_ID, &initial)?;
        let genesis = Genesis {
            network_id: application.network,
            database: application.database,
            owner: Self::owner().verifying_key().to_bytes(),
            application_commitment: application.id(),
            timestamp: 1000,
            profile: ProtocolProfile {
                initial_target: Target([255; 32]),
                pow_limit: Target([255; 32]),
                block_spacing_secs: 10,
                retarget_interval: 100,
                max_future_secs: 60,
                confirmation_depth: 1,
                max_headers: 128,
                max_shards: 2,
                max_updates: 2,
                max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
                max_request_bytes: 4096,
                max_proof_bytes: crate::opening::proof_wire::MAX_BUNDLE_BYTES as u32,
                max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
            },
            initial_shards: application.initial_shards(),
        };
        application.require_genesis(&genesis)?;
        Ok(Self {
            application,
            genesis,
            initial,
            source_witness,
            plain,
        })
    }
    pub(super) fn owner() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }
    pub(super) fn verifier(&self) -> Result<PrivateVerifier> {
        PrivateVerifier::new(self.application.clone(), &self.genesis)
    }
    fn source(&self, query: Hash) -> source::Statement {
        let mut source = self.initial.clone();
        source.request = query;
        source.open_commitment =
            commitment::digest(&commitment::opening_fields(&source, OPEN_SALT, &self.plain));
        source
    }
    fn request(
        &self,
        operation: Operation,
        parent: HeadRef,
        nonce: Hash,
        enrollment: Hash,
        source: &source::Statement,
        plan: Hash,
    ) -> Request {
        Request {
            operation,
            genesis: parent.genesis,
            parent: parent.block,
            application: self.application.id(),
            nonce,
            query: source.request,
            enrollment,
            opening: locking::statement::encoded(source.open_commitment),
            plan,
            packets: source.packets.clone(),
        }
    }
    fn signed(
        &self,
        parent: HeadRef,
        request: Request,
        proof: Vec<u8>,
        old: HeadPair,
        new: HeadPair,
    ) -> Result<Body> {
        let mut transition = AuthorizedTransition {
            parent: parent.block,
            request: request.encode()?,
            updates: vec![ShardUpdate {
                id: CONTROL_ID,
                old,
                new,
            }],
            proof,
            owner_signature: [0; 64],
        };
        transition.sign(parent.genesis, &Self::owner());
        bounded_body(&self.genesis.profile, transition)
    }
    pub(super) fn bootstrap(&self, parent: HeadRef) -> Result<Step> {
        let witness = backend(registry_bootstrap::trace::Witness::new(
            self.plain,
            CONTROLLERS,
            [OPEN_SALT, [Val::from_u8(11); 4], REGISTRY_SALT],
        ))?;
        let enrollment = backend(witness.enrollment(&self.initial, parent.genesis))?;
        let nonce = [0xB1; 32];
        let query = request::bootstrap_query(
            &self.application,
            parent.genesis,
            parent.block,
            nonce,
            enrollment,
        );
        let source = self.source(query);
        let expected = backend(registry_bootstrap::statement::Expected::checked(
            &source,
            parent.genesis,
            parent.block,
            enrollment,
        ))?;
        let (statement, proof) = backend(registry_bootstrap::prove(
            &expected,
            &self.source_witness,
            &witness,
        ))?;
        let bytes = registry_bootstrap::wire::encode(&expected, &statement, &proof)
            .map_err(|_| Error::RejectedComputationProof)?;
        drop(proof);
        let new = Control::Active {
            enrollment,
            registry: statement.registry_root(),
        }
        .heads(&self.application);
        let body = self.signed(
            parent,
            self.request(
                Operation::Bootstrap,
                parent,
                nonce,
                enrollment,
                &source,
                [0; 32],
            ),
            bytes,
            Control::Pending.heads(&self.application),
            new,
        )?;
        let next = locking::trace::Registry {
            revision: 2,
            tx: core::array::from_fn(|t| locking::trace::Transaction {
                id: t as u32 + 1,
                controller: CONTROLLERS[t],
                sequence: 1,
                failed: false,
                held: [0; 4],
            }),
        };
        Ok(Step {
            body,
            next,
            salt: REGISTRY_SALT,
            outcome: 0,
            returned: [false; 4],
            skipped: [false; 4],
        })
    }
    /// Private preparation does not establish acceptance: Journal verifies both proofs anew.
    pub(super) fn acquire(
        &self,
        journal: &Journal,
        parent: HeadRef,
        input: RegistryInput<'_>,
        query: LockQuery<'_>,
    ) -> Result<Step> {
        let RegistryInput {
            state: old,
            salt: old_salt,
        } = input;
        let LockQuery { actor, sql, nonce } = query;
        let shards = journal.validated_shards(parent)?;
        let old_head = shards
            .iter()
            .find(|s| s.id == CONTROL_ID)
            .ok_or(Error::InvalidTransition)?
            .heads;
        let Control::Active {
            enrollment,
            registry,
        } = Control::decode(&self.application, old_head)?
        else {
            return Err(Error::InvalidTransition);
        };
        let compiled = backend(locking::sql::CompiledLockPlan::compile(sql, nonce))?;
        let source = self.source(compiled.request());
        let table = self.plain[124..156].try_into().unwrap();
        let plan = backend(compiled.plan(table, actor))?;
        let salts = [
            OPEN_SALT,
            old_salt,
            [Val::from_u8(17); 4],
            [Val::from_u8(19); 4],
            [Val::from_u8(23); 4],
            [Val::from_u8(29); 4],
        ];
        let witness = locking::trace::Witness {
            plain: self.plain,
            old: old.clone(),
            plan,
            salts,
        };
        let mut expected = backend(locking::statement::Expected::checked(
            &source,
            parent.genesis,
            parent.block,
            registry,
            [0; 32],
        ))?;
        // Match private input to the ACTUAL parent root; never nominate a replacement Cold.
        if locking::statement::encoded(commitment::digest(&locking::statement::registry_fields(
            &expected, &witness, old, old_salt,
        ))) != registry
        {
            return Err(Error::InvalidTransition);
        }
        let tx = old
            .tx
            .get(usize::from(actor))
            .ok_or(Error::InvalidTransition)?;
        let opening = locking::statement::PlanOpening {
            table,
            transaction: tx.id,
            controller: tx.controller,
            sequence: tx.sequence,
            revision: old.revision,
            salt: salts[2],
        };
        expected.plan = commitment::digest(&locking::statement::plan_fields_opening(
            &expected,
            &witness.plan,
            &opening,
        ));
        let result = backend(witness.walk())?;
        let (statement, proof) = backend(locking::prove_composite(
            &expected,
            &self.source_witness,
            &witness,
        ))?;
        let bytes = locking::wire::encode(&expected, &statement, &proof)
            .map_err(|_| Error::RejectedComputationProof)?;
        drop(proof);
        let next_root = locking::statement::encoded(statement.next);
        let body = self.signed(
            parent,
            self.request(
                Operation::Acquire,
                parent,
                nonce,
                enrollment,
                &source,
                locking::statement::encoded(expected.plan),
            ),
            bytes,
            old_head,
            Control::Active {
                enrollment,
                registry: next_root,
            }
            .heads(&self.application),
        )?;
        Ok(Step {
            body,
            next: result.next,
            salt: if result.outcome == 0 {
                salts[3]
            } else {
                old_salt
            },
            outcome: result.outcome,
            returned: result.returned,
            skipped: result.skip,
        })
    }
}
/// Easy public work only: this exercises actual Journal validation, not economic security.
pub(super) fn append(
    journal: &mut Journal,
    verifier: &PrivateVerifier,
    parent: Hash,
    body: &Body,
    timestamp: u64,
) -> Result<Header> {
    let mut header = journal.candidate(parent, body, timestamp)?;
    header.mine(1024)?;
    let bytes = body.encode(journal.profile())?;
    journal.import_block(header.clone(), &bytes, 10_000, verifier)?;
    Ok(header)
}

pub(super) fn gate(mode: &str) -> std::result::Result<(), BackendError> {
    if !matches!(mode, "security" | "prove") {
        return Err(BackendError::Shape);
    }
    let f = Fixture::new().map_err(|_| BackendError::Shape)?;
    if mode == "security" {
        // Report the unchanged child profiles; this adapter introduces no new AIR.
        let witness = registry_bootstrap::trace::Witness::new(
            f.plain,
            CONTROLLERS,
            [OPEN_SALT, [Val::from_u8(11); 4], REGISTRY_SALT],
        )?;
        let enrollment =
            witness.enrollment(&f.initial, f.genesis.id().map_err(|_| BackendError::Shape)?)?;
        let q = request::bootstrap_query(
            &f.application,
            f.genesis.id().map_err(|_| BackendError::Shape)?,
            f.genesis.id().map_err(|_| BackendError::Shape)?,
            [0xB1; 32],
            enrollment,
        );
        let source = f.source(q);
        let expected = registry_bootstrap::statement::Expected::checked(
            &source,
            f.genesis.id().map_err(|_| BackendError::Shape)?,
            f.genesis.id().map_err(|_| BackendError::Shape)?,
            enrollment,
        )?;
        crate::security(
            &witness.statement(&expected)?,
            "public-nonsecret-private-journal-bootstrap",
        )?;
        // The original Lock CLI's security path creates no trace or proof.
        return locking::gate("security");
    }
    let started = std::time::Instant::now();
    let result = (|| -> Result<_> {
        let verifier = f.verifier()?;
        let mut journal = Journal::new(f.genesis.clone())?;
        let initial = journal.genesis_head();
        let boot = f.bootstrap(initial)?;
        let bootstrap_bytes = boot.body.encode(journal.profile())?.len();
        let h1 = append(&mut journal, &verifier, initial.block, &boot.body, 1001)?;
        let parent = journal.best_validated();
        let first = f.acquire(
            &journal,
            parent,
            RegistryInput {
                state: &boot.next,
                salt: boot.salt
            },
            LockQuery {
                actor: 0,
                sql: "SELECT age, amount FROM records WHERE age >= 0 LIMIT 2 FOR UPDATE",
                nonce: [0xB2; 32]
            }
        )?;
        if first.outcome != 0 || first.returned != [true, true, false, false] {
            return Err(Error::InvalidTransition);
        }
        let acquire_bytes = first.body.encode(journal.profile())?.len();
        let h2 = append(&mut journal, &verifier, h1.id(), &first.body, 1002)?;
        let second = f.acquire(
            &journal,
            journal.best_validated(),
            RegistryInput {
                state: &first.next,
                salt: first.salt
            },
            LockQuery {
                actor: 1,
                sql: "SELECT age, amount FROM records WHERE age >= 0 LIMIT 2 FOR UPDATE SKIP LOCKED",
                nonce: [0xB3; 32]
            }
        )?;
        if second.outcome != 0
            || second.skipped != [true, true, false, false]
            || second.returned != [false, false, true, true]
        {
            return Err(Error::InvalidTransition);
        }
        let skip_bytes = second.body.encode(journal.profile())?.len();
        let h3 = append(&mut journal, &verifier, h2.id(), &second.body, 1003)?;
        append(&mut journal, &verifier, h3.id(), &Body::Empty, 1004)?;
        let confirmed = journal.resolve(version_journal::Freshness::LatestConfirmed)?;
        if confirmed.block != h3.id() {
            return Err(Error::StaleHead);
        }
        Ok((bootstrap_bytes, acquire_bytes, skip_bytes))
    })().map_err(|_| BackendError::Verification)?;
    println!(
        "{{\"stage\":\"verified_experimental_private_journal_lineage\",\"bootstrap_body_bytes\":{},\"acquire_body_bytes\":{},\"skip_body_bytes\":{},\"outer_lineage_ms\":{},\"owner_authorized\":true,\"live_sql_grant\":false,\"finality\":false}}",
        result.0,
        result.1,
        result.2,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
