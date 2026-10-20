//! Restore private association only after actual complete prerequisite verification.
use super::*;
use p3_field::PrimeCharacteristicRing;
use registry200_journal::{Operation, intent_query};
use registry200_proof::{
    admission::CanonicalSource,
    lifecycle::{
        circuit::commitment,
        statement::{self as ls, Phase},
    },
    source::{self, statement as ss},
    wire,
};
use sha2::{Digest, Sha256};

impl EncryptedJointRecovery {
    /// Authenticate independently retained exact operation pins, reopen ALL
    /// private command/result/Registry commitments, and genuinely reverify every
    /// input16/Source/Lifecycle/Link premise before returning candidates. No FHE
    /// output, Journal decision, current lock, file or owner state is installed.
    /// Repeated recovery of the same authentic bytes is intentionally possible.
    pub fn restore_compute_prepared(
        &self,
        identity: &JointRecoveryIdentity,
        key: &JointRecoveryKey,
        bfv: BfvContext<'_>,
        epoch: &OwnerProofEpoch<'_>,
        parent: &JointLockingParent,
        public: JointRecoveryInputs<'_>,
    ) -> crate::Result<RecoveredJointComputePrepared> {
        // Bounds/AD authenticate the tiny private record before a verifier can
        // allocate any SDK proof/ciphertext object. Public buffers remain borrowed.
        codec::validate(self.as_bytes())?;
        let association = codec::association(parent, &public)?;
        let payload = codec::open(identity, key, association, self)?;
        let expected = expectations(parent, &bfv, &public)?;
        validate_openings(&expected, &payload, parent)?;
        // This actual constructor reopens Cmd48/Cmask, Cmd160/Ccmd AND Result144.
        // A valid AEAD tag is never a substitute for these commitment equations.
        let witness =
            predicate_acquire::circuit::Witness::new(&expected, codec::copy_opening(&payload.link))
                .map_err(cryptography)?;
        drop(witness);
        parent.require_ready(&bfv, epoch)?;
        public
            .provenance
            .verify_inputs(&public.proofs)
            .map_err(cryptography)?;
        predicate_acquire::verify(
            &expected,
            &predicate_acquire::Prerequisites {
                query: public.proofs.encodings[1],
                lifecycle: public.lifecycle,
            },
            public.link,
        )
        .map_err(cryptography)?;
        // Original full request bytes are reused, never encrypted or re-nonced.
        let parsed = bfv
            .setup
            .private_coefficient_request(public.encrypted_request)
            .map_err(cryptography)?;
        let pending = bfv
            .owner
            .restore_private_coefficient_predicate_for_experiment(
                public.encrypted_request.to_vec(),
                parsed.context().clone(),
                parsed.query(),
                Sha256::digest(public.encrypted_request).into(),
            )
            .map_err(cryptography)?;
        restored(parent, public, expected, payload, pending)
    }
}

fn expectations(
    parent: &JointLockingParent,
    bfv: &BfvContext<'_>,
    p: &JointRecoveryInputs<'_>,
) -> crate::Result<predicate_acquire::Expected> {
    let r = p.request.inner();
    let app = parent.application()?;
    let outer = JointRequest::new(&app, Lane::Acquire, r.clone()).map_err(cryptography)?;
    if p.request.lane() != Lane::Acquire
        || p.request.encode().map_err(cryptography)? != outer.encode().map_err(cryptography)?
        || r.operation != Operation::Transition
        || r.genesis != parent.head().genesis
        || r.parent != parent.head().block
        || r.application != parent.spec.id()
        || r.enrollment != parent.enrollment()
        || r.query
            != intent_query(
                &parent.spec,
                r.genesis,
                r.parent,
                r.nonce,
                r.enrollment,
                Operation::Transition,
            )
    {
        return Err(invalid("Joint recovery exact inner/outer intent differs"));
    }
    let descriptor = parent.binding.application_descriptor();
    let source =
        CanonicalSource::checked_claim(p.provenance.encodings()[0].expected.source_claim())
            .map_err(cryptography)?;
    let reconstructed = r.source(&parent.spec).map_err(cryptography)?;
    parent
        .spec
        .require_source(source.claim())
        .map_err(cryptography)?;
    if source.claim().values() != reconstructed.values()
        || source.claim().heads != reconstructed.heads
        || source.claim().packets != reconstructed.packets
        || p.provenance.query() != r.query
        || p.provenance.original_setup_digest() != descriptor.full_setup_digest()
        || p.provenance.anchor().encode_claim().map_err(cryptography)?
            != bfv.anchor.encode_claim().map_err(cryptography)?
    {
        return Err(invalid(
            "Joint recovery Source/setup/anchor association differs",
        ));
    }
    parent.require_key(bfv, p.provenance.encodings()[0].expected.bfv().key())?;
    parent.require_key(bfv, p.provenance.encodings()[1].expected.bfv().key())?;
    let parsed = bfv
        .setup
        .private_coefficient_request(p.encrypted_request)
        .map_err(cryptography)?;
    if parsed.query() != r.query
        || parsed.context().data_head() != source.claim().heads[0].as_slice()
        || parsed.context().index_head() != source.claim().heads[1].as_slice()
        || parsed.ciphertexts() != p.provenance.ciphertexts().each_ref().map(Vec::as_slice)
    {
        return Err(invalid(
            "Joint recovery encrypted pending/provenance differs",
        ));
    }
    let life = ls::Expected::transition(
        source.claim(),
        r.genesis,
        r.parent,
        r.enrollment,
        parent.registry(),
        r.command,
    )
    .map_err(cryptography)?;
    let frame = wire::frame::Frame::parse(wire::frame::Role::Transition, p.lifecycle)
        .map_err(cryptography)?;
    let statement = ls::Statement {
        expected: life,
        next: ss::decode_digest(frame.outputs[..32].try_into().unwrap()).map_err(cryptography)?,
        result: ss::decode_digest(frame.outputs[32..64].try_into().unwrap())
            .map_err(cryptography)?,
    };
    predicate_acquire::Expected::new(&p.provenance.encodings()[1], &statement).map_err(cryptography)
}
fn validate_openings(
    expected: &predicate_acquire::Expected,
    p: &codec::Payload,
    parent: &JointLockingParent,
) -> crate::Result<()> {
    let e = &expected.lifecycle().expected;
    let Phase::Transition { old, .. } = e.phase else {
        return Err(invalid("Joint recovery requires Acquire"));
    };
    let link = &p.link;
    // This constructor checks the actual old actor/principal/sequence/revision,
    // canonical Registry and all salts before any proof allocation.
    let control = LockingControl::new(
        (*p.old).clone(),
        *p.controllers,
        [p.salts[0], p.salts[1]],
        LockingActor::new(
            link.transaction,
            link.principal,
            link.revision,
            link.sequence,
        )?,
    )?;
    if control.controllers[usize::from(link.principal - 1)] != link.controller {
        return Err(invalid("Joint recovery controller differs from enrollment"));
    }
    let mut fields = commitment::enrollment_fields_opening(
        e,
        &p.table,
        &p.controllers,
        p.salts[0].map(Val::from_u64),
    );
    let enrollment = source::commitment::digest(&fields);
    fields.fill(Val::ZERO);
    let mut fields = commitment::registry_fields_opening(
        e,
        &p.table,
        &p.ids,
        &p.controllers,
        &p.old,
        p.salts[1].map(Val::from_u64),
    );
    let original = ls::digest(&fields);
    fields.fill(Val::ZERO);
    let mut fields = commitment::registry_fields_opening(
        e,
        &p.table,
        &p.ids,
        &p.controllers,
        &p.next,
        p.salts[2].map(Val::from_u64),
    );
    let next = ls::digest(&fields);
    fields.fill(Val::ZERO);
    if enrollment != e.enrollment
        || ss::encode_digest(enrollment) != parent.enrollment()
        || original != old
        || ss::encode_digest(original) != parent.registry()
        || next != expected.lifecycle().next
    {
        return Err(invalid(
            "Joint recovery original/enrollment/next opening differs",
        ));
    }
    let tx = p
        .next
        .transactions
        .iter()
        .find(|tx| tx.id == link.transaction)
        .ok_or_else(|| invalid("Joint recovery next actor is absent"))?;
    if p.next.revision
        != link
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("Joint recovery revision exhausted"))?
        || tx.sequence
            != link
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("Joint recovery sequence exhausted"))?
        || tx.principal != link.principal
        || tx.failed
    {
        return Err(invalid("Joint recovery next actor successor differs"));
    }
    Ok(())
}
fn restored(
    parent: &JointLockingParent,
    p: JointRecoveryInputs<'_>,
    expected: predicate_acquire::Expected,
    payload: codec::Payload,
    pending: PreparedPrivateCoefficientPredicate,
) -> crate::Result<RecoveredJointComputePrepared> {
    let codec::Payload {
        old,
        next,
        controllers,
        salts,
        table,
        ids,
        ordinals,
        link,
    } = payload;
    drop(old);
    let completion = LockingCompletion {
        table,
        row_ids: ids,
        ordinals,
        flags: Zeroizing::new(link.flags),
        result_salt: Zeroizing::new(link.salts[2]),
        projection: Zeroizing::new(link.projection),
    };
    let staged = StagedLockingTransition {
        next,
        controllers,
        salts: Zeroizing::new([salts[0], salts[2]]),
        actor: LockingActor::new(
            link.transaction,
            link.principal,
            link.revision,
            link.sequence,
        )?,
        parent: parent.head(),
        application: parent.spec.clone(),
        request: p.request.inner().encode().map_err(cryptography)?,
        provenance: p.provenance.encode_claim().map_err(cryptography)?,
        encrypted_request: p.encrypted_request.to_vec(),
        _association: expected,
    };
    Ok(RecoveredJointComputePrepared {
        pending,
        candidates: JointLockingCandidates {
            _completion: completion,
            _staged: staged,
            _binding: parent.binding.clone(),
            _parent: parent.verified.clone(),
            _outer_request: p.request.encode().map_err(cryptography)?,
        },
    })
}
