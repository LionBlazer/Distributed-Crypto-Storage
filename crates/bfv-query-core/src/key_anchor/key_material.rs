//! Query-independent private Key opening shared by the owning job constructors.
use super::*;
use p3_field::PrimeField64;
#[cfg(feature = "formation-proofs")]
use zeroize::Zeroize;

pub(super) fn check_original(anchor: &OwnerKeyAnchor<'_>, original: &PublicSetup) -> Result<()> {
    original.checked_parameters()?;
    if original.geometry != anchor.owner.geometry
        || keyset_id(original)? != anchor.owner.keyset_id
        || anchor.public.full_setup_id != anchor.owner.keyset_id
        || <[u8; 32]>::from(Sha256::digest(&original.parameters)) != anchor.public.parameter_digest
    {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}

pub(super) struct KeyMaterial {
    pub(super) shat: Zeroizing<Vec<u64>>,
    pub(super) output_salt: Zeroizing<[u64; 4]>,
    pub(super) witness: Option<ProverWitness>,
    pub(super) statement: bfv_key_transform::Statement,
}
impl KeyMaterial {
    #[cfg(feature = "formation-proofs")]
    pub(super) fn prove_key(
        &mut self,
        anchor: &OwnerKeyAnchor<'_>,
        missing_witness: Error,
    ) -> Result<bfv_key_transform::Evidence> {
        let evidence = bfv_key_transform::prove_statement(
            anchor.public.full_setup_id,
            &anchor.public.expected(),
            &self.statement,
            self.witness.as_ref().ok_or(missing_witness)?,
        )
        .map_err(backend)?;
        self.witness = None;
        Ok(evidence)
    }
    // The owning constructor checks the original setup before reaching this secret copy.
    pub(super) fn new(anchor: &OwnerKeyAnchor<'_>) -> Result<Self> {
        let coefficients = secret_coefficients(anchor.owner)?;
        let input = bfv_key_transform::input_commitment(
            &anchor.public.descriptor(),
            &coefficients,
            *anchor.input_salt,
        )
        .map_err(backend)?;
        if input != anchor.public.coefficients {
            return Err(Error::BindingMismatch);
        }
        let output_salt = Zeroizing::new(bfv_key_transform::random_salt().map_err(backend)?);
        let signed: Vec<_> = coefficients
            .iter()
            .copied()
            .map(bfv_key_transform::signed)
            .collect();
        let evaluations = bfv_key_transform::circuit::oracle(&signed);
        drop(signed);
        let shat = Zeroizing::new(evaluations.iter().map(|v| v.as_canonical_u64()).collect());
        let mut statement = bfv_key_transform::Statement {
            expected: anchor.public.expected(),
            transformed: [bfv_hiding_stark::Val::ZERO; 4],
        };
        statement.transformed = bfv_key_transform::circuit::digest(
            statement.contexts()[1],
            (*output_salt).map(bfv_hiding_stark::Val::from_u64),
            &evaluations,
        );
        drop(evaluations);
        let witness =
            ProverWitness::new(coefficients, *anchor.input_salt, *output_salt).map_err(backend)?;
        Ok(Self {
            shat,
            output_salt,
            witness: Some(witness),
            statement,
        })
    }
    #[cfg(feature = "formation-proofs")]
    pub(super) fn clear_private(&mut self) {
        self.witness = None;
        self.shat.zeroize();
        self.shat.clear();
        self.output_salt.zeroize();
    }
}
