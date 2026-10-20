//! Actual fetched AEAD Source and unchanged Source-first Bootstrap producers.
use super::*;
use crate::private_predicate::random_salt;
use p3_field::PrimeCharacteristicRing;
use registry200_journal::{Operation, Request as InnerRequest, intent_query};
use registry200_proof::{
    admission,
    lifecycle::{
        self,
        circuit::{self as life, commitment as fields},
    },
    source::{self, statement as ss},
};
use sha2::{Digest, Sha256};

fn source_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = source::commitment::digest(&fields);
    fields.fill(Val::ZERO);
    root
}
impl crate::private_predicate::SourceOwner {
    /// Produce a Bootstrap for one sealed historical Pending parent. The supplied
    /// controllers are owner-private labels, not possession proofs. The caller
    /// chooses a fresh independent nonce. No signing, storage or state install occurs.
    pub fn prepare_joint_bootstrap(
        &self,
        fetched: FetchedSource<'_>,
        binding: &JointBinding,
        parent: &JointBootstrapParent,
        controllers: Zeroizing<[[u8; 32]; 2]>,
        nonce: [u8; 32],
    ) -> crate::Result<PreparedJointBootstrap> {
        let app = require_parent(binding, parent)?;
        if controllers.contains(&[0; 32]) {
            return Err(invalid("Bootstrap controllers must be nonzero"));
        }
        if fetched.object != binding.application_descriptor().source_object() {
            return Err(invalid(
                "Bootstrap Source object differs from independent descriptor",
            ));
        }
        let loaded = self.load(fetched)?;
        app.source_spec()
            .require_source(&loaded.draft)
            .map_err(cryptography)?;
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
        let source_salt = Zeroizing::new(random_salt()?);
        let enrollment_salt = Zeroizing::new(random_salt()?);
        let registry_salt = Zeroizing::new(random_salt()?);
        // Enrollment's stable prefix excludes q/Copen. No provisional query or
        // dummy plaintext witness is used to construct this pure commitment.
        let provisional = lifecycle::statement::Expected::bootstrap(
            &loaded.draft,
            app.genesis(),
            parent.head().block,
            [0; 32],
        )
        .map_err(cryptography)?;
        let enrollment = ss::encode_digest(source_hash(fields::enrollment_fields_opening(
            &provisional,
            &table,
            &controllers,
            (*enrollment_salt).map(Val::from_u64),
        )));
        let query = intent_query(
            app.source_spec(),
            app.genesis(),
            parent.head().block,
            nonce,
            enrollment,
            Operation::Bootstrap,
        );
        let mut claim = loaded.draft.clone();
        claim.request = query;
        claim.open_commitment = source_hash(source::commitment::opening_fields(
            &claim,
            (*source_salt).map(Val::from_u64),
            loaded.plain.as_slice(),
        ));
        let canonical = admission::CanonicalSource::checked_claim(&claim).map_err(cryptography)?;
        let expected = admission::Expected::bootstrap(
            &canonical,
            app.genesis(),
            parent.head().block,
            enrollment,
        )
        .map_err(cryptography)?;
        let mathematical = life::Witness {
            plain: loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| invalid("Invalid complete real Source"))?,
            controllers: *controllers,
            old: Registry::default(),
            command: None,
            salts: [
                *source_salt,
                *enrollment_salt,
                [0; 4],
                [0; 4],
                *registry_salt,
                [0; 4],
            ]
            .map(|salt| salt.map(Val::from_u64)),
        };
        let witness =
            lifecycle::PreparedWitness::new(&expected, mathematical).map_err(cryptography)?;
        let source = source::prove(
            &canonical,
            &self.source_witness((*source_salt).map(Val::from_u64), &loaded.originals),
        )
        .map_err(cryptography)?;
        drop(loaded);
        let lifecycle =
            lifecycle::prove(&expected, &witness, source.as_bytes()).map_err(cryptography)?;
        drop(witness);
        drop(source);
        let request = JointRequest::new(
            &app,
            Lane::Bootstrap,
            InnerRequest {
                operation: Operation::Bootstrap,
                genesis: app.genesis(),
                parent: parent.head().block,
                application: app.source_spec().id(),
                nonce,
                query,
                enrollment,
                opening: ss::encode_digest(claim.open_commitment),
                command: [0; 32],
                packets: claim.packets,
            },
        )
        .map_err(cryptography)?;
        let candidate = JointBootstrapCandidate {
            binding: binding.clone(),
            parent: parent.clone(),
            request: request.encode().map_err(cryptography)?,
            statement: lifecycle.statement().clone(),
            pair_hash: Sha256::digest(lifecycle.as_bytes()).into(),
            pair_bytes: lifecycle
                .as_bytes()
                .len()
                .try_into()
                .map_err(|_| invalid("Bootstrap pair length overflow"))?,
            table,
            row_ids,
            controllers,
            registry: Zeroizing::new(Registry::default()),
            salts: Zeroizing::new([*enrollment_salt, *registry_salt]),
        };
        Ok(PreparedJointBootstrap {
            request,
            lifecycle,
            candidate,
        })
    }
}
