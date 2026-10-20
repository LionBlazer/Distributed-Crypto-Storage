//! Actual owner custody, fresh Source/input16 and Control815/Predicate896.
//! Only preparation builds a private mathematical next bank. Completion opens
//! the captured result against the genuine QC-linked Step instead of rerunning it.
use super::*;
use super::{
    inventory::Inventory,
    state::{Bank, Kind, RawCall, STATEMENT_BYTES},
};
use crate::private_predicate::source::locking::CompiledLockingSelect;
use crate::private_predicate::{InputProofFrames, random_salt};
use bfv_ciphertext_formation::Expected as FormationExpected;
use bfv_mul_relin_proof::Provenance;
use bfv_query_core::{OperandInput, QueryContext};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_finality::progress::VerifiedParent;
use registry200_joint::progress::{Lane, Manifest, ProgressEvidenceIngress, Request};
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        self as encoding, circuit::Witness as EncodingWitness, statement::BfvBinding,
    },
    lifecycle::circuit::model::Command,
    registry_progress::{
        circuit::StatementOpening,
        transition::{self, Expected, Witness},
    },
    source::{self, statement as ss},
};
use zeroize::Zeroize;

pub(super) const ATTEMPT_CAP: usize = 8192;
const COMMAND_BYTES: usize = 88;
pub(super) struct Attempt {
    pub call: RawCall,
    pub custody: [u8; 32],
    pub before: [u8; 32],
    pub context_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub old_root: [u8; 32],
    pub source_salt: Zeroizing<[u64; 4]>,
    pub command_salt: Zeroizing<[u64; 4]>,
    pub command: Zeroizing<Command>,
    pub original: Option<Zeroizing<StatementOpening>>,
    pub next: Bank,
    pub result: Zeroizing<[u64; 160]>,
    pub next_root: [u8; 32],
    pub result_root: [u8; 32],
    pub inventory: Inventory,
    pub request: Request,
    pub catalog: Option<bfv_product_evidence::CatalogId>,
}
impl Attempt {
    pub fn lane(&self) -> Lane {
        if self.call.kind == Kind::Acquire {
            Lane::Predicate
        } else {
            Lane::Control
        }
    }
    pub fn manifest(&self) -> Result<Manifest> {
        match self.lane() {
            Lane::Predicate => Manifest::predicate(
                self.next_root,
                self.result_root,
                self.catalog.ok_or(Error::Phase)?,
                self.inventory.id(18)?,
            ),
            Lane::Control => Manifest::control(
                self.next_root,
                self.result_root,
                self.inventory.id(3)?,
                self.inventory.id(18)?,
            ),
            Lane::Bootstrap => return Err(Error::Phase),
        }
        .map_err(crypto)
    }
    pub fn expected(
        &self,
        pins: &Pins,
        old: &Bank,
        query: Option<&encoding::statement::Statement>,
    ) -> Result<Expected> {
        let a = app(&pins.binding)?;
        let source = self
            .request
            .inner()
            .source(a.source_spec())
            .map_err(crypto)?;
        let canonical = CanonicalSource::checked_claim(&source).map_err(crypto)?;
        // old root is pinned in the original private snapshot, not received from a peer.
        let old_root = self.old_root;
        let e = match query {
            Some(q) => Expected::predicate(
                q,
                a.genesis(),
                self.request.inner().parent,
                self.request.inner().enrollment,
                old_root,
                self.request.inner().command,
            ),
            None => Expected::control(
                &canonical,
                a.genesis(),
                self.request.inner().parent,
                self.request.inner().enrollment,
                old_root,
                self.request.inner().command,
            ),
        }
        .map_err(crypto)?;
        if transition::command_commitment(
            &e,
            &self.command,
            old.state.registry.revision,
            &old.controllers,
            *self.command_salt,
        )
        .map_err(crypto)?
            != self.request.inner().command
        {
            return Err(Error::Pins);
        }
        Ok(e)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut b = Zeroizing::new(Vec::with_capacity(ATTEMPT_CAP));
        b.extend_from_slice(b"POATT001");
        b.extend_from_slice(self.call.encode().as_ref());
        b.extend(self.custody);
        b.extend(self.before);
        b.extend(self.context_id);
        b.extend(self.request_digest);
        b.extend(self.old_root);
        for s in [&self.source_salt, &self.command_salt] {
            for v in s.iter() {
                b.extend(v.to_le_bytes());
            }
        }
        b.extend_from_slice(encode_command(&self.command)?.as_ref());
        if let Some(s) = &self.original {
            b.push(1);
            b.extend_from_slice(state::encode_statement(s)?.as_ref());
        } else {
            b.extend([0; 1 + STATEMENT_BYTES]);
        }
        b.extend_from_slice(self.next.encode()?.as_ref());
        for v in self.result.iter() {
            if *v >= Val::ORDER_U64 {
                return Err(Error::Encoding);
            }
            b.extend(v.to_le_bytes());
        }
        b.extend(self.next_root);
        b.extend(self.result_root);
        b.extend(self.inventory.encode());
        b.extend(self.request.encode().map_err(crypto)?);
        if let Some(c) = self.catalog {
            b.extend(c.blob_id().sha256());
            b.extend(c.blob_id().bytes().to_le_bytes());
        } else {
            b.extend([0; 40]);
        }
        if b.len() > ATTEMPT_CAP {
            return Err(Error::ResourceLimit);
        }
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = super::wal::Reader::new(bytes);
        if r.array::<8>()? != *b"POATT001" {
            return Err(Error::Encoding);
        }
        let call = RawCall::decode(r.take(state::CALL_BYTES)?)?.ok_or(Error::Encoding)?;
        let custody = r.array()?;
        let before = r.array()?;
        let context_id = r.array()?;
        let request_digest = r.array()?;
        let old_root = r.array()?;
        let _ = ss::decode_digest(old_root).map_err(crypto)?;
        let mut salts = Zeroizing::new([[0; 4]; 2]);
        for s in salts.iter_mut() {
            for v in s.iter_mut() {
                *v = r.u64()?;
                if *v >= Val::ORDER_U64 {
                    return Err(Error::Encoding);
                }
            }
        }
        let command = Zeroizing::new(decode_command(r.take(COMMAND_BYTES)?)?);
        let has = r.array::<1>()?[0];
        let sb = r.take(STATEMENT_BYTES)?;
        let original = match has {
            1 => Some(state::decode_statement(sb)?),
            0 if sb == [0; STATEMENT_BYTES] => None,
            _ => return Err(Error::Encoding),
        };
        let next = Bank::decode(r.take(state::BANK_BYTES)?)?;
        let mut result = Zeroizing::new([0; 160]);
        for v in result.iter_mut() {
            *v = r.u64()?;
            if *v >= Val::ORDER_U64 {
                return Err(Error::Encoding);
            }
        }
        let next_root = r.array()?;
        let result_root = r.array()?;
        let lane = if call.kind == Kind::Acquire {
            Lane::Predicate
        } else {
            Lane::Control
        };
        let inventory = Inventory::decode(r.take(inventory::INVENTORY_BYTES)?, lane)?;
        let request =
            Request::decode(r.take(registry200_joint::progress::REQUEST_BYTES)?).map_err(crypto)?;
        let cb = r.array::<40>()?;
        let catalog = if cb == [0; 40] {
            None
        } else {
            Some(
                bfv_product_evidence::CatalogId::from_blob(
                    protocol_storage::BlobId::new(
                        cb[..32].try_into().unwrap(),
                        u64::from_le_bytes(cb[32..].try_into().unwrap()),
                    )
                    .map_err(storage)?,
                )
                .map_err(crypto)?,
            )
        };
        r.end()?;
        if request.lane() != lane
            || (lane == Lane::Predicate) != original.is_some()
            || command.operation != call.kind.operation()
            || command.transaction != call.transaction
        {
            return Err(Error::Encoding);
        }
        let a = Self {
            call,
            custody,
            before,
            context_id,
            request_digest,
            old_root,
            source_salt: Zeroizing::new(salts[0]),
            command_salt: Zeroizing::new(salts[1]),
            command,
            original,
            next,
            result,
            next_root,
            result_root,
            inventory,
            request,
            catalog,
        };
        if a.encode()?.as_slice() != bytes {
            return Err(Error::Encoding);
        }
        Ok(a)
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.custody.zeroize();
        self.before.zeroize();
        self.context_id.zeroize();
        self.request_digest.zeroize();
    }
}
fn encode_command(c: &Command) -> Result<Zeroizing<[u8; COMMAND_BYTES]>> {
    c.require_shape().map_err(crypto)?;
    let mut b = Zeroizing::new([0; COMMAND_BYTES]);
    b[0] = c.operation as u8;
    b[1..9].copy_from_slice(&c.transaction.to_le_bytes());
    b[9] = c.principal;
    b[10..18].copy_from_slice(&c.sequence.to_le_bytes());
    b[18..50].copy_from_slice(&c.name);
    b[50..82].copy_from_slice(&c.mask);
    b[82..87].copy_from_slice(&[c.mode, c.wait, c.offset, c.limit, c.projection]);
    b[87] = u8::from(c.abort);
    Ok(b)
}
fn decode_command(b: &[u8]) -> Result<Command> {
    if b.len() != COMMAND_BYTES {
        return Err(Error::Encoding);
    }
    let operation = *registry200_proof::lifecycle::circuit::model::Operation::ALL
        .get(b[0] as usize)
        .ok_or(Error::Encoding)?;
    if b[87] > 1 {
        return Err(Error::Encoding);
    }
    let c = Command {
        operation,
        transaction: u64::from_le_bytes(b[1..9].try_into().unwrap()),
        principal: b[9],
        sequence: u64::from_le_bytes(b[10..18].try_into().unwrap()),
        name: b[18..50].try_into().unwrap(),
        mask: b[50..82].try_into().unwrap(),
        mode: b[82],
        wait: b[83],
        offset: b[84],
        limit: b[85],
        projection: b[86],
        abort: b[87] == 1,
    };
    c.require_shape().map_err(crypto)?;
    Ok(c)
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0; N];
    getrandom::getrandom(&mut b).map_err(crypto)?;
    Ok(b)
}

pub(super) struct Build<'a> {
    pub pins: &'a Pins,
    pub bank: &'a Bank,
    pub parent: &'a VerifiedParent,
    pub ingress: &'a ProgressEvidenceIngress,
    pub material: &'a Material<'a>,
    pub fetched: FetchedSource<'a>,
    pub call: RawCall,
    pub before: [u8; 32],
    pub sql: Option<&'a str>,
    pub resume: bool,
    pub name: [u8; 32],
}
impl Build<'_> {
    pub fn run(self) -> Result<Attempt> {
        let Self {
            pins,
            bank,
            parent,
            ingress,
            material,
            fetched,
            call,
            before,
            sql,
            resume,
            name,
        } = self;
        let a = app(&pins.binding)?;
        let source_owner = material.source(pins, again(&fetched))?;
        let mut loaded = source_owner.load(fetched).map_err(crypto)?;
        let plain = Zeroizing::new(
            loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Shape)?,
        );
        bank.require_parent(pins, parent, &loaded.draft, &plain)?;
        let (enrollment, registry) = bank.root(pins, parent.head().block, &loaded.draft, &plain)?;
        let nonce = random()?;
        let query = registry200_journal::intent_query(
            a.source_spec(),
            a.genesis(),
            parent.head().block,
            nonce,
            enrollment,
            registry200_journal::Operation::Transition,
        );
        let source_salt = Zeroizing::new(random_salt().map_err(crypto)?);
        loaded.draft.request = query;
        loaded.draft.open_commitment =
            source::commitment::digest(&source::commitment::opening_fields(
                &loaded.draft,
                source_salt.map(Val::from_u64),
                plain.as_ref(),
            ));
        let source = CanonicalSource::checked_claim(&loaded.draft).map_err(crypto)?;
        let command_salt = Zeroizing::new(random_salt().map_err(crypto)?);
        let next_salt = Zeroizing::new(random_salt().map_err(crypto)?);
        let result_salt = Zeroizing::new(random_salt().map_err(crypto)?);
        let source_proof = source::prove(
            &source,
            &source_owner.source_witness(source_salt.map(Val::from_u64), &loaded.originals),
        )
        .map_err(crypto)?;
        let mut command = Zeroizing::new(Command::control(
            call.kind.operation(),
            call.transaction,
            pins.clients[call.slot].principal,
            bank.state
                .registry
                .transactions
                .iter()
                .find(|t| t.id == call.transaction)
                .map_or(0, |t| t.sequence),
        ));
        command.name = name;
        command.abort = call.kind == Kind::EndAbort;
        let mut original = None;
        let mut context_id = [0; 16];
        let mut request_digest = [0; 32];
        let mut input = None;
        let mut all_salts = Zeroizing::new([[0; 4]; 8]);
        all_salts[0] = *source_salt;
        all_salts[1] = *bank.enroll_salt;
        all_salts[2] = *bank.registry_salt;
        all_salts[3] = *command_salt;
        all_salts[4] = *next_salt;
        all_salts[5] = *result_salt;
        all_salts[6] = random_salt().map_err(crypto)?;
        all_salts[7] = random_salt().map_err(crypto)?;
        if call.kind == Kind::Acquire {
            context_id = random()?;
            let blind = Zeroizing::new(random::<32>()?);
            let public_nonce = random()?;
            let mut hidden = if resume {
                let actor = bank
                    .state
                    .registry
                    .transactions
                    .iter()
                    .position(|t| t.id == call.transaction)
                    .ok_or(Error::Pins)?;
                Zeroizing::new(
                    bank.state.progress[actor]
                        .as_ref()
                        .ok_or(Error::Phase)?
                        .statement
                        .clone(),
                )
            } else {
                let compiled = CompiledLockingSelect::compile(
                    sql.ok_or(Error::Phase)?,
                    blind,
                    public_nonce,
                    context_id,
                )
                .map_err(crypto)?;
                let tx = bank
                    .state
                    .registry
                    .transactions
                    .iter()
                    .find(|t| t.id == call.transaction)
                    .ok_or(Error::Pins)?;
                Zeroizing::new(StatementOpening {
                    scope: [0; 64],
                    enrollment: ss::decode_digest(enrollment)
                        .map_err(crypto)?
                        .map(|v| v.as_canonical_u64()),
                    client: pins.clients[call.slot].id,
                    call: call.sequence,
                    transaction: call.transaction,
                    principal: command.principal,
                    controller: pins.controllers[usize::from(command.principal - 1)],
                    invocation: hash(&[
                        b"DCS/Progress-owner/call-invocation/v1",
                        &pins.id,
                        &call.encode()[..],
                        &random::<32>()?,
                    ]),
                    sql_identity: compiled.identity,
                    snapshot: tx.snapshot,
                    mask: *compiled.mask,
                    mode: compiled.mode,
                    wait: compiled.wait,
                    offset: compiled.offset,
                    limit: compiled.limit,
                    projection: compiled.projection,
                    salt: random_salt().map_err(crypto)?,
                })
            };
            command.mask = hidden.mask;
            command.mode = hidden.mode;
            command.wait = hidden.wait;
            command.offset = hidden.offset;
            command.limit = hidden.limit;
            command.projection = hidden.projection;
            let owner = material.owner(pins)?;
            let anchor = owner
                .restore_key_anchor(
                    material.setup,
                    material.anchor,
                    material.owner_identity,
                    material.owner_authority,
                    material.anchor_record,
                )
                .map_err(crypto)?;
            let mut epoch = anchor
                .restore_ready_epoch(
                    material.setup,
                    material.key,
                    material.owner_identity,
                    material.owner_authority,
                    material.ready_record,
                )
                .map_err(crypto)?;
            let key_bytes = epoch.key_evidence().map_err(crypto)?.as_bytes().to_vec();
            let binding = BfvBinding::new(material.anchor.full_setup_id(), material.key.clone());
            let source_expected =
                encoding::statement::Expected::source(&source, binding.clone()).map_err(crypto)?;
            let identity = if resume {
                hash(&[
                    b"DCS/Progress-owner/fresh-encoding-blind/v1",
                    &hidden.sql_identity,
                    &random::<32>()?,
                ])
            } else {
                hidden.sql_identity
            };
            let draft = encoding::statement::Expected::private_mask(
                &source,
                binding.clone(),
                identity,
                public_nonce,
                [0; 32],
            )
            .map_err(crypto)?;
            let mask_root =
                encoding::commitment::command_digest(&encoding::commitment::command_fields(
                    &draft,
                    hidden.mask,
                    all_salts[7].map(Val::from_u64),
                ));
            let mask_expected = encoding::statement::Expected::private_mask(
                &source,
                binding,
                identity,
                public_nonce,
                ss::encode_digest(mask_root),
            )
            .map_err(crypto)?;
            let source_witness = EncodingWitness::source(
                &source_expected,
                loaded.plain,
                *source_salt,
                random_salt().map_err(crypto)?,
            )
            .map_err(crypto)?;
            let mask_witness = EncodingWitness::private_mask(
                &mask_expected,
                Zeroizing::new(hidden.mask),
                all_salts[7],
                random_salt().map_err(crypto)?,
            )
            .map_err(crypto)?;
            let pairs = [
                encoding::prove(&source_expected, &source_witness, source_proof.as_bytes())
                    .map_err(crypto)?,
                encoding::prove(&mask_expected, &mask_witness, source_proof.as_bytes())
                    .map_err(crypto)?,
            ];
            let [(s0, p0), (s1, p1)] = pairs.map(|p| p.into_parts());
            let statements = [s0, s1];
            let originals = owner
                .encrypt_original_coefficient_rows_for_experiment(&loaded.originals)
                .map_err(crypto)?;
            let context =
                QueryContext::new(context_id, source.claim().heads[0], source.claim().heads[1]);
            let prepared = owner
                .prepare_private_coefficient_predicate_for_experiment(
                    context.clone(),
                    query,
                    &originals,
                    &hidden.mask,
                )
                .map_err(crypto)?;
            let parsed = material
                .setup
                .private_coefficient_request(&prepared.request)
                .map_err(crypto)?;
            if parsed.query() != query
                || parsed.context() != &context
                || parsed.ciphertexts() != prepared.operand_ciphertexts().map_err(crypto)?
            {
                return Err(Error::Pins);
            }
            request_digest = Sha256::digest(&prepared.request).into();
            let ciphertexts = prepared
                .operand_ciphertexts()
                .map_err(crypto)?
                .map(<[u8]>::to_vec);
            let provenance = Provenance::new(
                material.setup.clone(),
                material.anchor.clone(),
                statements.clone(),
                ciphertexts,
            )
            .map_err(crypto)?;
            let relin = material.setup.relinearization_material().map_err(crypto)?;
            let mut bases: [[Vec<u8>; 5]; 2] =
                core::array::from_fn(|_| core::array::from_fn(|_| Vec::new()));
            let mut formations: [Vec<u8>; 2] = core::array::from_fn(|_| Vec::new());
            for (operand, witness) in [source_witness, mask_witness].into_iter().enumerate() {
                let opening = witness
                    .formation_opening(&statements[operand])
                    .map_err(crypto)?;
                let mut job = epoch
                    .begin_operand(
                        query,
                        OperandInput {
                            ciphertext: &provenance.ciphertexts()[operand],
                            encoding: opening.commitment().clone(),
                        },
                    )
                    .map_err(crypto)?;
                let mut checked = Vec::with_capacity(5);
                for (basis, bytes) in bases[operand].iter_mut().enumerate() {
                    let evidence = job.prove_next_basis().map_err(crypto)?;
                    let e = bfv_basis_convolution::Expected::new(
                        material.key.clone(),
                        relin.parameters(),
                        &provenance.ciphertexts()[operand],
                        query,
                        basis,
                    )
                    .map_err(crypto)?;
                    let proof = bfv_basis_convolution::verify(
                        material.anchor.full_setup_id(),
                        &e,
                        &key_bytes,
                        evidence.as_bytes(),
                    )
                    .map_err(crypto)?;
                    proof.statement().require_expected(&e).map_err(crypto)?;
                    checked.push(proof.statement().clone());
                    *bytes = evidence.into_bytes();
                }
                let e = FormationExpected::new(
                    opening.commitment().clone(),
                    checked.try_into().map_err(|_| Error::Shape)?,
                )
                .map_err(crypto)?;
                job.begin_formation(opening).map_err(crypto)?;
                formations[operand] = job
                    .prove_formation(&e, bases[operand].each_ref().map(Vec::as_slice))
                    .map_err(crypto)?
                    .into_bytes();
            }
            let proofs = InputProofFrames {
                key: key_bytes,
                encodings: [p0, p1],
                bases,
                formations,
            };
            proofs.byte_len().map_err(crypto)?;
            let draft = Expected::predicate(
                &statements[1],
                a.genesis(),
                parent.head().block,
                enrollment,
                registry,
                [0; 32],
            )
            .map_err(crypto)?;
            if !resume {
                hidden.scope = draft.statement_scope();
            }
            original = Some(hidden);
            input = Some((provenance, prepared.request, proofs, statements[1].clone()));
        }
        let draft = match &input {
            Some((_, _, _, query)) => Expected::predicate(
                query,
                a.genesis(),
                parent.head().block,
                enrollment,
                registry,
                [0; 32],
            ),
            None => Expected::control(
                &source,
                a.genesis(),
                parent.head().block,
                enrollment,
                registry,
                [0; 32],
            ),
        }
        .map_err(crypto)?;
        let command_root = transition::command_commitment(
            &draft,
            &command,
            bank.state.registry.revision,
            &bank.controllers,
            *command_salt,
        )
        .map_err(crypto)?;
        let expected = match &input {
            Some((_, _, _, query)) => Expected::predicate(
                query,
                a.genesis(),
                parent.head().block,
                enrollment,
                registry,
                command_root,
            ),
            None => Expected::control(
                &source,
                a.genesis(),
                parent.head().block,
                enrollment,
                registry,
                command_root,
            ),
        }
        .map_err(crypto)?;
        let (next_state, witness) = if let Some(hidden) = &original {
            let mut step = Zeroizing::new(
                bank.state
                    .predicate(hidden, core::array::from_fn(|i| plain[3 * i]), all_salts[6])
                    .map_err(crypto)?,
            );
            let next = Zeroizing::new(core::mem::take(&mut step.next));
            let w = Witness::predicate(
                &expected,
                Zeroizing::new(*plain),
                bank.controllers.clone(),
                bank.state.clone(),
                Zeroizing::new((**hidden).clone()),
                all_salts,
            )
            .map_err(crypto)?;
            (next, w)
        } else {
            let next = Zeroizing::new(
                bank.state
                    .control(&command, parent.head().block)
                    .map_err(crypto)?,
            );
            let w = Witness::control(
                &expected,
                Zeroizing::new(*plain),
                bank.controllers.clone(),
                bank.state.clone(),
                command.clone(),
                Zeroizing::new(core::array::from_fn(|i| all_salts[i])),
            )
            .map_err(crypto)?;
            (next, w)
        };
        let next = Bank {
            state: next_state,
            controllers: bank.controllers.clone(),
            enroll_salt: bank.enroll_salt.clone(),
            registry_salt: next_salt,
        };
        if ss::encode_digest(
            next.state
                .root(
                    expected.registry_context(),
                    &plain,
                    &next.controllers,
                    *next.registry_salt,
                )
                .map_err(crypto)?,
        ) != witness.statement().next()
        {
            return Err(Error::Pins);
        }
        let result = witness.result_opening_fields().map_err(crypto)?;
        let proof = transition::prove(
            &expected,
            &witness,
            &transition::Prerequisites {
                source: source_proof.as_bytes(),
                query: input.as_ref().map(|v| v.2.encodings[1].as_slice()),
            },
        )
        .map_err(crypto)?;
        let next_root = proof.statement().next();
        let result_root = proof.statement().result();
        let inventory = if let Some((provenance, request, frames, _)) = &input {
            Inventory::predicate(
                ingress,
                provenance,
                request,
                frames,
                source_proof.as_bytes(),
                proof.as_bytes(),
            )?
        } else {
            Inventory::control(ingress, source_proof.as_bytes(), proof.as_bytes())?
        };
        let request = Request::new(
            &a,
            if input.is_some() {
                Lane::Predicate
            } else {
                Lane::Control
            },
            registry200_journal::Request {
                operation: registry200_journal::Operation::Transition,
                genesis: a.genesis(),
                parent: parent.head().block,
                application: a.source_spec().id(),
                nonce,
                query,
                enrollment,
                opening: ss::encode_digest(source.claim().open_commitment),
                command: command_root,
                packets: source.claim().packets.clone(),
            },
        )
        .map_err(crypto)?;
        Ok(Attempt {
            call,
            custody: material.fingerprint(pins)?,
            before,
            context_id,
            request_digest,
            old_root: registry,
            source_salt,
            command_salt,
            command,
            original,
            next,
            result,
            next_root,
            result_root,
            inventory,
            request,
            catalog: None,
        })
    }
}
