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
}
