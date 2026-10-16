//! Canonical public NTT representation only; arithmetic proof verification is external.
use super::*;
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};

pub(super) fn coefficients(ciphertext: &Ciphertext) -> Vec<u64> {
    ciphertext.iter().flat_map(Vec::<u64>::from).collect()
}

/// Builds the exact level-zero ct-by-public-plaintext statement, never a proof.
/// Callers validate their request metadata and derive the public mask or kernel.
/// `public_plaintext` must contain only public values; its conversion is variable-time.
pub(super) fn public_product_request(
    parameters: &Arc<BfvParameters>,
    original_request: &[u8],
    ciphertext: &Ciphertext,
    public_plaintext: &Plaintext,
) -> Result<Vec<u8>> {
    if parameters.degree() != DEGREE
        || parameters.plaintext() != PLAINTEXT
        || parameters.moduli() != MODULI
    {
        return Err(Error::ParameterProfile);
    }
    let context = parameters.context_at_level(0).map_err(backend)?;
    if ciphertext.len() != 2
        || ciphertext.iter().any(|polynomial| {
            polynomial.representation() != &Representation::Ntt || polynomial.ctx() != context
        })
        || public_plaintext.level() != 0
    {
        return Err(Error::InvalidShape);
    }
    // This is the same public polynomial used by upstream Ciphertext * Plaintext.
    let mut polynomial =
        Poly::try_convert_from(public_plaintext, context, true, Representation::PowerBasis)
            .map_err(backend)?;
    polynomial.change_representation(Representation::Ntt);
    let values = Vec::<u64>::from(&polynomial);
    // Ciphertext component, then modulus, then coefficient. The codec validates
    // the complete fixed shape and canonical residues for both operands.
    let repeated: Vec<_> = values.iter().chain(&values).copied().collect();
    bfv_product_circuit::encode_request(
        Sha256::digest(original_request).into(),
        &coefficients(ciphertext),
        &repeated,
    )
    .map_err(backend)
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

#[cfg(test)]
mod tests;
