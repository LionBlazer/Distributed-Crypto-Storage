//! Canonical public NTT representation only; arithmetic proof verification is external.
use super::*;
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};

pub(super) fn coefficients(ciphertext: &Ciphertext) -> Vec<u64> {
    ciphertext.iter().flat_map(Vec::<u64>::from).collect()
}

pub(super) fn ciphertext(
    parameters: &Arc<BfvParameters>,
    coefficients: &[u64],
) -> Result<Ciphertext> {
    if coefficients.len() != bfv_linear_circuit::COEFFICIENTS {
        return Err(Error::InvalidShape);
    }
    let context = parameters.context_at_level(0).map_err(backend)?;
    let polynomials = coefficients
        .as_chunks::<{ bfv_linear_circuit::COEFFICIENTS / 2 }>()
        .0
        .iter()
        // These are public ciphertext residues, matching fresh upstream ciphertext flags.
        // Upstream secret-key decryption separately disables variable-time computations.
        .map(|values| Poly::try_convert_from(values.to_vec(), context, true, Representation::Ntt))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(backend)?;
    Ciphertext::new(polynomials, parameters).map_err(backend)
}
