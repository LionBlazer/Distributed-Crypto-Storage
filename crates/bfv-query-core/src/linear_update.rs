//! Exact indexed addition needs the public parameters and domain binding, not rotation/relin keys.
use super::*;

/// Public-only operation descriptor. Its digest must come from the trusted caller's
/// full public setup; deserializing this descriptor does not authenticate its identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicUpdateParameters {
    version: u16,
    geometry: Geometry,
    parameters: Vec<u8>,
    keyset_id: [u8; 32],
}
impl PublicSetup {
    pub fn update_parameters(&self) -> Result<PublicUpdateParameters> {
        self.checked_parameters()?;
        Ok(PublicUpdateParameters {
            version: VERSION,
            geometry: self.geometry,
            parameters: self.parameters.clone(),
            keyset_id: keyset_id(self)?,
        })
    }
}
impl PublicUpdateParameters {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode(self)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let parameters: Self = decode(bytes)?;
        parameters.checked_parameters()?;
        Ok(parameters)
    }
    fn checked_parameters(&self) -> Result<Arc<BfvParameters>> {
        let expected = official_parameters()?;
        if self.version != VERSION || self.parameters != expected.to_bytes() {
            return Err(Error::ParameterProfile);
        }
        Ok(expected)
    }
}
/// Genuine public ciphertext addition, with no secret key, rotation key or clock.
/// The output remains unverified until an external computation proof is checked.
pub struct PublicUpdateEvaluator {
    parameters: Arc<BfvParameters>,
    geometry: Geometry,
    keyset_id: [u8; 32],
}
impl PublicUpdateEvaluator {
    pub fn from_parameters(setup: &PublicUpdateParameters) -> Result<Self> {
        Ok(Self {
            parameters: setup.checked_parameters()?,
            geometry: setup.geometry,
            keyset_id: setup.keyset_id,
        })
    }
    pub fn evaluate(&self, request: &[u8]) -> Result<Vec<u8>> {
        indexed_update::execute_addition(
            &self.parameters,
            self.geometry,
            self.keyset_id,
            request,
            || {},
        )
    }

    /// Converts the exact original ciphertext operands into the canonical public
    /// circuit input. Its digest must be retained by the trusted proof requester.
    pub fn circuit_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        indexed_update::circuit_request(&self.parameters, self.geometry, self.keyset_id, request)
    }

    /// Representation conversion only; this neither proves nor accepts an answer.
    /// A proof consumer must verify the exact circuit input/output digests before
    /// decrypting the returned ciphertext or authorizing any database write.
    pub fn restore_circuit_output(&self, request: &[u8], output: &[u8]) -> Result<Vec<u8>> {
        indexed_update::restore_circuit_output(
            &self.parameters,
            self.geometry,
            self.keyset_id,
            request,
            output,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Explicitly public fixtures; each test generates fresh keys in memory.

    fn fields() -> [SelectedField; 2] {
        [
            SelectedField {
                age: 18,
                amount: 20,
                active: true,
            },
            SelectedField {
                age: 42,
                amount: 30,
                active: true,
            },
        ]
    }
    fn context() -> QueryContext {
        QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES])
    }

    #[test]
    fn minimal_public_evaluator_performs_the_same_encrypted_update_without_rotation_keys() {
        let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let pending = owner
            .prepare_indexed_update_for_experiment(context(), &fields(), 5)
            .unwrap();
        let descriptor = setup.update_parameters().unwrap().to_bytes().unwrap();
        let evaluator = PublicUpdateEvaluator::from_parameters(
            &PublicUpdateParameters::from_bytes(&descriptor).unwrap(),
        )
        .unwrap();

        let actual = evaluator.evaluate(&pending.request).unwrap();

        let full = PeerEvaluator::from_public_setup(&setup)
            .unwrap()
            .evaluate_indexed_update(&pending.request)
            .unwrap();
        assert_eq!(actual, full.output);
        assert!(
            descriptor.len() < 1024,
            "Only the pinned parameters and domain are needed"
        );
        let UnverifiedUpdateOutcome::Values(values) = owner
            .decrypt_indexed_update_unverified_for_experiment(pending.pending, &actual)
            .unwrap()
        else {
            panic!("A bounded update must return its actual encrypted additions")
        };
        assert_eq!(
            values.rows.iter().map(|row| row.amount).collect::<Vec<_>>(),
            [25, 35]
        );
        assert_eq!(values.proof, ProofStatus::Unavailable);
    }

    #[test]
    fn public_update_evaluator_rejects_a_request_from_another_keyset() {
        let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
        let (_, other) = Owner::generate(Geometry::Rows256).unwrap();
        let pending = owner
            .prepare_indexed_update_for_experiment(context(), &fields(), 5)
            .unwrap();
        let evaluator =
            PublicUpdateEvaluator::from_parameters(&other.update_parameters().unwrap()).unwrap();
        assert!(matches!(
            evaluator.evaluate(&pending.request),
            Err(Error::BindingMismatch)
        ));
    }

    #[test]
    fn reduced_descriptor_never_allows_a_weaker_parameter_profile_or_a_truncated_wire() {
        let (_, setup) = Owner::generate(Geometry::Rows256).unwrap();
        let mut descriptor = setup.update_parameters().unwrap();
        descriptor.parameters[0] ^= 1;
        assert!(matches!(
            PublicUpdateEvaluator::from_parameters(&descriptor),
            Err(Error::ParameterProfile)
        ));
        let mut bytes = setup.update_parameters().unwrap().to_bytes().unwrap();
        bytes.pop();
        assert!(PublicUpdateParameters::from_bytes(&bytes).is_err());
    }

    #[test]
    fn canonical_ring_addition_matches_the_upstream_ciphertext_operator_for_both_geometries() {
        for geometry in [Geometry::Rows16, Geometry::Rows256] {
            let (owner, setup) = Owner::generate(geometry).unwrap();
            let evaluator =
                PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap())
                    .unwrap();
            let mut fields: Vec<_> = (0..geometry.slots())
                .map(|slot| SelectedField {
                    age: slot as u8,
                    amount: (slot * 251) as u16,
                    active: slot % 3 != 0,
                })
                .collect();
            fields[1].amount = u16::MAX;
            for delta in [0, 1, 256, u16::MAX] {
                let pending = owner
                    .prepare_indexed_update_for_experiment(context(), &fields, delta)
                    .unwrap();

                let input = evaluator.circuit_request(&pending.request).unwrap();
                let output = bfv_linear_circuit::evaluate(&input).unwrap();
                let actual = evaluator
                    .restore_circuit_output(&pending.request, &output)
                    .unwrap();

                let expected = evaluator.evaluate(&pending.request).unwrap();
                assert!(
                    actual == expected,
                    "Canonical and upstream ciphertext outputs differ"
                );
            }
        }
    }

    #[test]
    fn circuit_output_cannot_be_rebound_to_another_query_or_database_head() {
        let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
        let evaluator =
            PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
        let original = owner
            .prepare_indexed_update_for_experiment(context(), &fields(), 5)
            .unwrap();
        let output =
            bfv_linear_circuit::evaluate(&evaluator.circuit_request(&original.request).unwrap())
                .unwrap();
        for other_context in [
            QueryContext::new([8; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]),
            QueryContext::new([7; 16], [4; HEAD_BYTES], [3; HEAD_BYTES]),
            QueryContext::new([7; 16], [2; HEAD_BYTES], [5; HEAD_BYTES]),
        ] {
            let other = owner
                .prepare_indexed_update_for_experiment(other_context, &fields(), 5)
                .unwrap();

            let restored = evaluator.restore_circuit_output(&other.request, &output);

            assert!(matches!(restored, Err(Error::BindingMismatch)));
        }
    }

    #[test]
    fn ciphertexts_with_an_unexpected_representation_are_rejected_before_circuit_conversion() {
        use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
        let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
        let values = vec![0; DEGREE];
        let bytes = owner.encrypted(&values).unwrap();
        let fresh = fhe::bfv::Ciphertext::from_bytes(&bytes, &owner.parameters).unwrap();
        // Explicit components remove fresh-ciphertext seed compression, so the
        // modified second polynomial is actually present on the wire as well.
        let explicit = fhe::bfv::Ciphertext::new(fresh.to_vec(), &owner.parameters).unwrap();
        for position in [0, 1] {
            let mut ciphertext = explicit.clone();
            ciphertext[position].change_representation(fhe_math::rq::Representation::PowerBasis);

            let checked = checked_ciphertext(&ciphertext.to_bytes(), &owner.parameters);

            assert!(matches!(checked, Err(Error::InvalidShape)));
        }
    }
}
