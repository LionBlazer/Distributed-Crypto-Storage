//! Actual Source/input16/Lifecycle/Link orchestration, with no admission path.
use super::{
    CompiledLockingSelect, LockingCompletion, LockingConflict, LockingControl, LockingParent,
    LockingPreparation, NextOwnerOpening, NonAdmittedLocking, PreparedLockingInputs,
    StagedLockingTransition,
};
use crate::private_predicate::{
    BfvContext, FetchedSource, InputProofFrames, ProducedInputs, SourceOwner, cryptography,
    invalid, random_salt,
};
use bfv_ciphertext_formation::Expected as FormationExpected;
use bfv_mul_relin_proof::Provenance;
use bfv_query_core::{OperandInput, OwnerProofEpoch, ProofEpochStage, QueryContext};
use p3_field::PrimeCharacteristicRing;
use registry200_journal::{Operation, Request};
use registry200_proof::{
    Val,
    admission::{CanonicalSource, Expected as LifeExpected},
    coefficient_encoding::{
        self as encoding, circuit::Witness as EncodingWitness, statement::BfvBinding,
    },
    lifecycle::{
        self,
        circuit::{self as life, commitment as life_commitment, model::Step},
    },
    predicate_acquire::{self as link, circuit::Opening as LinkOpening},
    source::{self, commitment, statement as source_statement},
};
use zeroize::{Zeroize, Zeroizing};

struct PrivateStep(Step);
impl Drop for PrivateStep {
    fn drop(&mut self) {
        let s = &mut self.0;
        s.next.zeroize();
        s.outcome.zeroize();
        s.search.zeroize();
        s.attempt.zeroize();
        s.conflict.zeroize();
        s.visit.zeroize();
        s.skipped.zeroize();
        s.returned.zeroize();
        s.block.zeroize();
    }
}

impl SourceOwner {
    /// Produces separate bounded mathematical proof frames for one historical
    /// validated parent. No owner Registry state, Journal, disk or SQL grant changes.
    /// All four originals are loaded once and encrypted; no selection/window is
    /// used to reduce the source ciphertext. Synchronous proving has no cancellation API.
    pub fn prepare_locking(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledLockingSelect,
        parent: &LockingParent,
        control: LockingControl,
    ) -> crate::Result<LockingPreparation> {
        let object = fetched.object;
        let mut loaded = self.load(fetched)?;
        parent
            .application
            .require_source(&loaded.draft)
            .map_err(cryptography)?;
        if epoch.stage() != ProofEpochStage::Ready {
            return Err(invalid("Owner proof epoch must already be Ready"));
        }
        if bfv.owner.geometry() != bfv.setup.geometry() {
            return Err(invalid("BFV owner and original setup geometry differ"));
        }
        let key_bytes = epoch
            .key_evidence()
            .map_err(cryptography)?
            .as_bytes()
            .to_vec();
        let key = bfv
            .setup
            .verify_key_transform(bfv.anchor, &key_bytes)
            .map_err(cryptography)?;
        let binding = BfvBinding::new(bfv.anchor.full_setup_id(), key.statement().clone());

        // Reconstruct the independently validated parent openings before any new
        // Source proof/trace. Stable enrollment/registry prefixes exclude q/Copen.
        let mut mathematical = life::Witness {
            plain: loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| invalid("Invalid complete Source opening"))?,
            controllers: *control.controllers,
            salts: [[Val::ZERO; 4]; 6],
            old: (*control.old).clone(),
            command: Some(compiled.command(&control)),
        };
        mathematical.salts[1] = control.salts[0].map(Val::from_u64);
        mathematical.salts[2] = control.salts[1].map(Val::from_u64);
        let draft = lifecycle::statement::Expected::transition(
            &loaded.draft,
            parent.head.genesis,
            parent.head.block,
            parent.enrollment,
            parent.registry,
            [0; 32],
        )
        .map_err(cryptography)?;
        if source_statement::encode_digest(commitment::digest(&life_commitment::enrollment_fields(
            &draft,
            &mathematical,
        ))) != parent.enrollment
            || source_statement::encode_digest(lifecycle::statement::digest(
                &life_commitment::registry_fields(
                    &draft,
                    &mathematical,
                    &mathematical.old,
                    mathematical.salts[2],
                ),
            )) != parent.registry
        {
            return Err(invalid(
                "Private control opening differs from the validated parent",
            ));
        }
        let mut step = PrivateStep(
            mathematical
                .old
                .step(
                    mathematical.command.as_ref().unwrap(),
                    parent.head.block,
                    mathematical.ages(),
                )
                .map_err(cryptography)?,
        );
        let (nonce, query) = compiled.intent(&loaded.draft, &binding, object, parent, &control);
        loaded.draft.request = query;
        let opening_salt = Zeroizing::new(random_salt()?);
        loaded.draft.open_commitment = commitment::digest(&commitment::opening_fields(
            &loaded.draft,
            (*opening_salt).map(Val::from_u64),
            &loaded.plain,
        ));
        let source = CanonicalSource::checked_claim(&loaded.draft).map_err(cryptography)?;
        mathematical.salts[0] = (*opening_salt).map(Val::from_u64);
        let command_salt = Zeroizing::new(random_salt()?);
        let result_salt = Zeroizing::new(random_salt()?);
        let next_salt = Zeroizing::new(random_salt()?);
        mathematical.salts[3] = (*command_salt).map(Val::from_u64);
        mathematical.salts[4] = (*next_salt).map(Val::from_u64);
        mathematical.salts[5] = (*result_salt).map(Val::from_u64);
        let draft = lifecycle::statement::Expected::transition(
            source.claim(),
            parent.head.genesis,
            parent.head.block,
            parent.enrollment,
            parent.registry,
            [0; 32],
        )
        .map_err(cryptography)?;
        let command = lifecycle::statement::digest(&life_commitment::command_fields(
            &draft,
            &mathematical,
            mathematical.command.as_ref().unwrap(),
        ));
        let expected = LifeExpected::transition(
            &source,
            parent.head.genesis,
            parent.head.block,
            parent.enrollment,
            parent.registry,
            source_statement::encode_digest(command),
        )
        .map_err(cryptography)?;
        let witness =
            lifecycle::PreparedWitness::new(&expected, mathematical).map_err(cryptography)?;
        let source_evidence = {
            let witness =
                self.source_witness((*opening_salt).map(Val::from_u64), &loaded.originals);
            source::prove(&source, &witness).map_err(cryptography)?
        };
        let lifecycle = lifecycle::prove(&expected, &witness, source_evidence.as_bytes())
            .map_err(cryptography)?;
        drop(witness);
        let request = Request {
            operation: Operation::Transition,
            genesis: parent.head.genesis,
            parent: parent.head.block,
            application: parent.application.id(),
            nonce,
            query,
            enrollment: parent.enrollment,
            opening: source_statement::encode_digest(source.claim().open_commitment),
            command: source_statement::encode_digest(command),
            packets: source.claim().packets.clone(),
        };
        // Strict original Request codec remains part of the output contract.
        request.encode().map_err(cryptography)?;
        if step.0.outcome != 0 {
            let outcome = match step.0.outcome {
                1 => LockingConflict::Wait,
                2 => LockingConflict::NoWait,
                _ => return Err(invalid("Unexpected non-Acquire lifecycle outcome")),
            };
            return Ok(LockingPreparation::NonAdmitted(Box::new(
                NonAdmittedLocking {
                    outcome,
                    request,
                    lifecycle,
                },
            )));
        }
        let completion = LockingCompletion {
            table: Zeroizing::new(loaded.plain[124..156].try_into().unwrap()),
            row_ids: Zeroizing::new(core::array::from_fn(|i| {
                loaded.plain[2220 + 32 * i..2252 + 32 * i]
                    .try_into()
                    .unwrap()
            })),
            ordinals: Zeroizing::new([0, 1, 2, 3]),
            flags: Zeroizing::new([step.0.returned, step.0.skipped, step.0.visit]),
            result_salt: Zeroizing::new(*result_salt),
            projection: Zeroizing::new(compiled.projection),
        };
        let mask_salt = Zeroizing::new(random_salt()?);
        let (source_expected, mask_expected) = compiled
            .bind(
                &source,
                binding,
                object,
                parent,
                &control,
                (*mask_salt).map(Val::from_u64),
            )
            .map_err(cryptography)?;
        let original = bfv
            .owner
            .encrypt_original_coefficient_rows_for_experiment(&loaded.originals)
            .map_err(cryptography)?;
        let context = QueryContext::new(
            compiled.query_id,
            loaded.draft.heads[0],
            loaded.draft.heads[1],
        );
        let prepared = bfv
            .owner
            .prepare_private_coefficient_predicate_for_experiment(
                context.clone(),
                query,
                &original,
                &compiled.mask,
            )
            .map_err(cryptography)?;
        let parsed = bfv
            .setup
            .private_coefficient_request(&prepared.request)
            .map_err(cryptography)?;
        if parsed.query() != query
            || parsed.context() != &context
            || parsed.ciphertexts() != prepared.operand_ciphertexts().map_err(cryptography)?
        {
            return Err(invalid(
                "Prepared locking BFV request changed its complete context",
            ));
        }
        let ciphertexts = prepared
            .operand_ciphertexts()
            .map_err(cryptography)?
            .map(<[u8]>::to_vec);
        let staging = NextOwnerOpening {
            plain: Zeroizing::new(
                loaded
                    .plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("Invalid staged complete Source opening"))?,
            ),
            next: Zeroizing::new(core::mem::take(&mut step.0.next)),
            control,
            source_salt: opening_salt,
            next_salt,
        };
        let source_witness = EncodingWitness::source(
            &source_expected,
            loaded.plain,
            *staging.source_salt,
            random_salt()?,
        )
        .map_err(cryptography)?;
        let mask_witness = EncodingWitness::private_mask(
            &mask_expected,
            Zeroizing::new(*compiled.mask),
            *mask_salt,
            random_salt()?,
        )
        .map_err(cryptography)?;
        let pairs = [
            encoding::prove(
                &source_expected,
                &source_witness,
                source_evidence.as_bytes(),
            )
            .map_err(cryptography)?,
            encoding::prove(&mask_expected, &mask_witness, source_evidence.as_bytes())
                .map_err(cryptography)?,
        ];
        drop(source_evidence);
        let [
            (original_statement, original_pair),
            (mask_statement, mask_pair),
        ] = pairs.map(|p| p.into_parts());
        let statements = [original_statement, mask_statement];
        let provenance = Provenance::new(
            bfv.setup.clone(),
            bfv.anchor.clone(),
            statements.clone(),
            ciphertexts,
        )
        .map_err(cryptography)?;
        let material = bfv.setup.relinearization_material().map_err(cryptography)?;
        let mut bases: [[Vec<u8>; 5]; 2] =
            core::array::from_fn(|_| core::array::from_fn(|_| Vec::new()));
        let mut formations: [Vec<u8>; 2] = core::array::from_fn(|_| Vec::new());
        for (operand, witness) in [source_witness, mask_witness].into_iter().enumerate() {
            let opening = witness
                .formation_opening(&statements[operand])
                .map_err(cryptography)?;
            let mut job = epoch
                .begin_operand(
                    query,
                    OperandInput {
                        ciphertext: &provenance.ciphertexts()[operand],
                        encoding: opening.commitment().clone(),
                    },
                )
                .map_err(cryptography)?;
            let mut basis_statements = Vec::with_capacity(5);
            for (basis, bytes) in bases[operand].iter_mut().enumerate() {
                let evidence = job.prove_next_basis().map_err(cryptography)?;
                let expected = bfv_basis_convolution::Expected::new(
                    key.statement().clone(),
                    material.parameters(),
                    &provenance.ciphertexts()[operand],
                    query,
                    basis,
                )
                .map_err(cryptography)?;
                let checked = bfv_basis_convolution::verify(
                    bfv.anchor.full_setup_id(),
                    &expected,
                    &key_bytes,
                    evidence.as_bytes(),
                )
                .map_err(cryptography)?;
                checked
                    .statement()
                    .require_expected(&expected)
                    .map_err(cryptography)?;
                basis_statements.push(checked.statement().clone());
                *bytes = evidence.into_bytes();
            }
            let basis_statements = basis_statements
                .try_into()
                .map_err(|_| invalid("Incomplete ordered locking Basis statements"))?;
            let expected = FormationExpected::new(opening.commitment().clone(), basis_statements)
                .map_err(cryptography)?;
            job.begin_formation(opening).map_err(cryptography)?;
            formations[operand] = job
                .prove_formation(&expected, bases[operand].each_ref().map(Vec::as_slice))
                .map_err(cryptography)?
                .into_bytes();
        }
        let proofs = InputProofFrames {
            key: key_bytes,
            encodings: [original_pair, mask_pair],
            bases,
            formations,
        };
        proofs.byte_len().map_err(cryptography)?;
        let link_expected =
            link::Expected::new(&statements[1], lifecycle.statement()).map_err(cryptography)?;
        let link_witness = link::circuit::Witness::new(
            &link_expected,
            LinkOpening {
                mask: *compiled.mask,
                transaction: staging.control.actor.transaction,
                principal: staging.control.actor.principal,
                controller: staging.control.controllers
                    [usize::from(staging.control.actor.principal - 1)],
                revision: staging.control.actor.revision,
                sequence: staging.control.actor.sequence,
                mode: compiled.mode,
                wait: compiled.wait,
                offset: compiled.offset,
                limit: compiled.limit,
                projection: compiled.projection,
                flags: *completion.flags,
                salts: [*mask_salt, *command_salt, *result_salt],
            },
        )
        .map_err(cryptography)?;
        let link = link::prove(
            &link_expected,
            &link_witness,
            &link::Prerequisites {
                query: &proofs.encodings[1],
                lifecycle: lifecycle.as_bytes(),
            },
        )
        .map_err(cryptography)?;
        let inputs = ProducedInputs {
            provenance,
            prepared,
            proofs,
        };
        let staged =
            StagedLockingTransition::new(parent, &request, &inputs, &lifecycle, &link, staging)?;
        Ok(LockingPreparation::Prepared(Box::new(
            PreparedLockingInputs {
                inputs,
                lifecycle,
                link,
                request,
                completion,
                staged,
            },
        )))
    }
}
