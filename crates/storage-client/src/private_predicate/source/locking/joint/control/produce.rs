//! Real Source loading and unchanged Source-first Core producers only.
use super::*;
use crate::private_predicate::random_salt;
use p3_field::PrimeCharacteristicRing;
use registry200_journal::{Operation as JournalOperation, Request as InnerRequest, intent_query};
use registry200_proof::{
    admission,
    lifecycle::{
        self,
        circuit::{self as life, commitment as fields},
    },
    source::{self, statement as ss},
};

struct PrivateStep(life::model::Step);
impl Drop for PrivateStep {
    fn drop(&mut self) {
        self.0.next.zeroize();
        self.0.search.zeroize();
        self.0.attempt.zeroize();
        self.0.conflict.zeroize();
        self.0.visit.zeroize();
        self.0.skipped.zeroize();
        self.0.returned.zeroize();
        self.0.block.zeroize();
        self.0.outcome.zeroize();
    }
}
fn life_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = lifecycle::statement::digest(&fields);
    fields.fill(Val::ZERO);
    root
}
fn source_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = source::commitment::digest(&fields);
    fields.fill(Val::ZERO);
    root
}
impl crate::private_predicate::SourceOwner {
    /// Consumes the historical private candidate, including on failure. No
    /// database mutation, filesystem, FHE, pending recovery or signing occurs.
    pub fn prepare_joint_control(
        &self,
        fetched: FetchedSource<'_>,
        parent: &JointControlParent,
        opening: JointRegistryOpening,
        intent: JointControlIntent,
    ) -> crate::Result<PreparedJointControl> {
        parent.require_stamp(&opening.binding, &opening.parent, opening.context)?;
        if fetched.object != parent.binding.application_descriptor().source_object() {
            return Err(invalid(
                "Control Source object differs from independent descriptor",
            ));
        }
        let loaded = self.load(fetched)?;
        let app = JointApplication::new(
            parent.binding.application_descriptor().clone(),
            parent.binding.journal_genesis(),
        )
        .map_err(cryptography)?;
        app.source_spec()
            .require_source(&loaded.draft)
            .map_err(cryptography)?;
        let Control::Active {
            enrollment,
            registry,
        } = parent.verified.control()
        else {
            return Err(invalid("Control requires Active Registry"));
        };
        let JointRegistryOpening {
            binding: _,
            parent: _,
            context: _,
            registry: old,
            controllers,
            salts,
        } = opening;
        old.require_canonical().map_err(cryptography)?;
        let table = Zeroizing::new(
            loaded.plain[124..156]
                .try_into()
                .map_err(|_| invalid("Invalid real Source TableId"))?,
        );
        let row_ids = Zeroizing::new(core::array::from_fn(|i| {
            loaded.plain[2220 + 32 * i..2252 + 32 * i]
                .try_into()
                .unwrap()
        }));
        let draft = lifecycle::statement::Expected::transition(
            &loaded.draft,
            app.genesis(),
            parent.head().block,
            enrollment,
            registry,
            [0; 32],
        )
        .map_err(cryptography)?;
        if ss::encode_digest(source_hash(fields::enrollment_fields_opening(
            &draft,
            &table,
            &controllers,
            salts[0].map(Val::from_u64),
        ))) != enrollment
            || ss::encode_digest(life_hash(fields::registry_fields_opening(
                &draft,
                &table,
                &row_ids,
                &controllers,
                &old,
                salts[1].map(Val::from_u64),
            ))) != registry
        {
            return Err(invalid(
                "Private control opening differs from actual Source/parent roots",
            ));
        }
        let command = Zeroizing::new(intent.command(&old)?);
        let mut step = PrivateStep(
            old.step(
                &command,
                parent.head().block,
                core::array::from_fn(|i| loaded.originals[i].age),
            )
            .map_err(cryptography)?,
        );
        if !matches!(step.0.outcome, 0 | 3) {
            return Err(invalid("Control intent has non-control outcome"));
        }
        let source_salt = Zeroizing::new(random_salt()?);
        let command_salt = Zeroizing::new(random_salt()?);
        let next_salt = Zeroizing::new(random_salt()?);
        let result_salt = Zeroizing::new(random_salt()?);
        let query = intent_query(
            app.source_spec(),
            app.genesis(),
            parent.head().block,
            intent.nonce,
            enrollment,
            JournalOperation::Transition,
        );
        let mut claim = loaded.draft.clone();
        claim.request = query;
        claim.open_commitment = source_hash(source::commitment::opening_fields(
            &claim,
            (*source_salt).map(Val::from_u64),
            loaded.plain.as_slice(),
        ));
        let provisional = lifecycle::statement::Expected::transition(
            &claim,
            app.genesis(),
            parent.head().block,
            enrollment,
            registry,
            [0; 32],
        )
        .map_err(cryptography)?;
        let mut command_fields = fields::command_fields_opening(
            &provisional,
            &command,
            &fields::CommandFieldsOpening {
                controller: controllers[usize::from(command.principal - 1)],
                revision: old.revision,
                salt: (*command_salt).map(Val::from_u64),
            },
        );
        let command_root = lifecycle::statement::digest(&command_fields);
        let command_words: Zeroizing<[u64; 160]> = Zeroizing::new(core::array::from_fn(|i| {
            command_fields[i].as_canonical_u64()
        }));
        command_fields.fill(Val::ZERO);
        let expected = lifecycle::statement::Expected::transition(
            &claim,
            app.genesis(),
            parent.head().block,
            enrollment,
            registry,
            ss::encode_digest(command_root),
        )
        .map_err(cryptography)?;
        let checked = admission::Expected::checked_claim(&expected).map_err(cryptography)?;
        let canonical = admission::CanonicalSource::checked_claim(&claim).map_err(cryptography)?;
        let revision = Zeroizing::new(old.revision);
        let mathematical = life::Witness {
            plain: loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| invalid("Invalid real N4 Source"))?,
            controllers: *controllers,
            old: (*old).clone(),
            command: Some((*command).clone()),
            salts: [
                *source_salt,
                salts[0],
                salts[1],
                *command_salt,
                *next_salt,
                *result_salt,
            ]
            .map(|s| s.map(Val::from_u64)),
        };
        let witness =
            lifecycle::PreparedWitness::new(&checked, mathematical).map_err(cryptography)?;
        let source = source::prove(
            &canonical,
            &self.source_witness((*source_salt).map(Val::from_u64), &loaded.originals),
        )
        .map_err(cryptography)?;
        drop(loaded);
        drop(old);
        let lifecycle =
            lifecycle::prove(&checked, &witness, source.as_bytes()).map_err(cryptography)?;
        drop(witness);
        drop(source);
        let kind_expected =
            control_kind::Expected::new(lifecycle.statement()).map_err(cryptography)?;
        let kind_opening = control_kind::circuit::Opening::new(*command_words);
        drop(command_words);
        let kind_opening = kind_opening.map_err(cryptography)?;
        let kind_witness = control_kind::circuit::Witness::new(&kind_expected, kind_opening)
            .map_err(cryptography)?;
        let kind = control_kind::prove(
            &kind_expected,
            &kind_witness,
            &control_kind::Prerequisites {
                lifecycle: lifecycle.as_bytes(),
            },
        )
        .map_err(cryptography)?;
        let request = JointRequest::new(
            &app,
            Lane::Control,
            InnerRequest {
                operation: JournalOperation::Transition,
                genesis: app.genesis(),
                parent: parent.head().block,
                application: app.source_spec().id(),
                nonce: intent.nonce,
                query,
                enrollment,
                opening: ss::encode_digest(claim.open_commitment),
                command: ss::encode_digest(command_root),
                packets: claim.packets,
            },
        )
        .map_err(cryptography)?;
        let candidate = JointControlCandidate {
            parent: JointControlParent {
                binding: parent.binding.clone(),
                verified: parent.verified.clone(),
                context: parent.context.clone(),
            },
            request: request.encode().map_err(cryptography)?,
            statement: lifecycle.statement().clone(),
            command,
            command_salt,
            result_salt,
            revision,
            table,
            row_ids,
            next: Zeroizing::new(core::mem::take(&mut step.0.next)),
            controllers,
            salts: Zeroizing::new([salts[0], *next_salt]),
            outcome: Zeroizing::new(step.0.outcome),
        };
        Ok(PreparedJointControl {
            request,
            lifecycle,
            kind,
            candidate,
        })
    }
}
