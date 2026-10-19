use super::{
    BfvContext, CompiledPrivatePredicate, FetchedSource, InputProofFrames, ProducedInputs,
    SourceOwner, cryptography, invalid, random_salt,
};
use bfv_ciphertext_formation::Expected as FormationExpected;
use bfv_mul_relin_proof::Provenance;
use bfv_query_core::{OperandInput, OwnerProofEpoch, ProofEpochStage, QueryContext};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        self as encoding, circuit::Witness as EncodingWitness, statement::BfvBinding,
    },
    source::{self, commitment},
};

impl SourceOwner {
    /// Proves the old same-q input16 relation using real fetched original images.
    ///
    /// Every original row is encrypted before the private truth table is applied
    /// by a peer. The caller retains its BFV owner and live Ready epoch. Plaintext,
    /// private masks, Source/Encoding witnesses and current operand openings are
    /// dropped before public products return. No network SQL answer is accepted.
    pub fn produce(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledPrivatePredicate,
        query_id: [u8; 16],
    ) -> crate::Result<ProducedInputs> {
        // Real custody, owner and complete-image preflight precedes any proof work.
        let mut loaded = self.load(fetched)?;
        if epoch.stage() != ProofEpochStage::Ready {
            return Err(invalid("Owner proof epoch must already be Ready"));
        }
        if bfv.owner.geometry() != bfv.setup.geometry() {
            return Err(invalid("BFV owner and original setup geometry differ"));
        }
        // Own one bounded PUBLIC copy, so exclusive epoch jobs never overlap a
        // borrow of the epoch's retained Key frame. This becomes the output frame.
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
        let query = compiled.query(&loaded.draft, &binding);
        loaded.draft.request = query;
        let opening_salt = random_salt()?.map(Val::from_u64);
        loaded.draft.open_commitment = commitment::digest(&commitment::opening_fields(
            &loaded.draft,
            opening_salt,
            &loaded.plain,
        ));
        let source = CanonicalSource::checked_claim(&loaded.draft).map_err(cryptography)?;
        let command_salt = random_salt()?;
        let source_encoding_salt = random_salt()?;
        let mask_encoding_salt = random_salt()?;
        let (source_expected, mask_expected, mask) = compiled
            .bind(&source, binding, command_salt.map(Val::from_u64))
            .map_err(cryptography)?;

        let original = bfv
            .owner
            .encrypt_original_coefficient_rows_for_experiment(&loaded.originals)
            .map_err(cryptography)?;
        let context = QueryContext::new(query_id, loaded.draft.heads[0], loaded.draft.heads[1]);
        let prepared = bfv
            .owner
            .prepare_private_coefficient_predicate_for_experiment(
                context.clone(),
                query,
                &original,
                &mask,
            )
            .map_err(cryptography)?;
        // This public view binds the exact owner-produced request to the supplied
        // complete setup before private proof factories. It performs no FHE math.
        let parsed = bfv
            .setup
            .private_coefficient_request(&prepared.request)
            .map_err(cryptography)?;
        if parsed.query() != query || parsed.context() != &context {
            return Err(invalid(
                "Prepared private predicate request changed its context",
            ));
        }
        let ciphertexts = prepared
            .operand_ciphertexts()
            .map_err(cryptography)?
            .map(<[u8]>::to_vec);
        if parsed.ciphertexts() != prepared.operand_ciphertexts().map_err(cryptography)? {
            return Err(invalid(
                "Prepared ciphertext order differs from its pending binding",
            ));
        }
        let source_witness = EncodingWitness::source(
            &source_expected,
            loaded.plain,
            opening_salt.map(|v| v.as_canonical_u64()),
            source_encoding_salt,
        )
        .map_err(cryptography)?;
        let mask_witness =
            EncodingWitness::private_mask(&mask_expected, mask, command_salt, mask_encoding_salt)
                .map_err(cryptography)?;
        let pairs = {
            let evidence = {
                let witness = self.source_witness(opening_salt, &loaded.originals);
                source::prove(&source, &witness).map_err(cryptography)?
            };
            [
                encoding::prove(&source_expected, &source_witness, evidence.as_bytes())
                    .map_err(cryptography)?,
                encoding::prove(&mask_expected, &mask_witness, evidence.as_bytes())
                    .map_err(cryptography)?,
            ]
        };
        let [(source_statement, source_pair), (mask_statement, mask_pair)] =
            pairs.map(|pair| pair.into_parts());
        let statements = [source_statement, mask_statement];
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
                .map_err(|_| invalid("Incomplete ordered Basis statements"))?;
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
            encodings: [source_pair, mask_pair],
            bases,
            formations,
        };
        proofs.byte_len().map_err(cryptography)?;
        Ok(ProducedInputs {
            provenance,
            prepared,
            proofs,
        })
    }
}
