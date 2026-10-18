//! Canonical full PB/native endpoints. Public seed expansion is not a query NTT.
use crate::{DEGREE, Error, GraphClaims, Result};
use bfv_ciphertext_wire::{SecondComponent, StoredPowerBasis};
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::Serialize;
use std::sync::Arc;

fn parameters(bytes: &[u8]) -> Result<Arc<BfvParameters>> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_moduli(&bfv_fixed_geometry::MODULI)
        .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
        .set_variance(10)
        .build_arc()
        .map_err(|_| Error::Statement)?;
    if parameters.to_bytes() != bytes {
        return Err(Error::Statement);
    }
    Ok(parameters)
}
fn same_pb(poly: StoredPowerBasis<'_>, basis: usize, claimed: &[u64]) -> Result<()> {
    if poly
        .row(basis)
        .ok_or(Error::Statement)?
        .eq(claimed.iter().copied())
    {
        Ok(())
    } else {
        Err(Error::Statement)
    }
}
/// Associate all complete stored PB rows, original seeded c1 native rows, and
/// final PB output rows with a complete proposed graph. Parameters must be the
/// exact original fixed bytes. Source/Key/Formation proofs, full setup identity
/// and query/profile bindings remain the consumer's independent obligations.
pub fn check_ciphertext_bridges(
    parameter_bytes: &[u8],
    inputs: [&[u8]; 2],
    output: &[u8],
    c: &GraphClaims,
) -> Result<()> {
    // All envelopes and role flags are checked before fixed SDK construction or
    // public seed expansion. The borrowed views contain no native polynomial.
    let parsed = [
        bfv_ciphertext_wire::parse(inputs[0]).map_err(|_| Error::Statement)?,
        bfv_ciphertext_wire::parse(inputs[1]).map_err(|_| Error::Statement)?,
    ];
    let out = bfv_ciphertext_wire::parse(output).map_err(|_| Error::Statement)?;
    let SecondComponent::Stored(c1) = out.second() else {
        return Err(Error::Statement);
    };
    if !out.c0().allow_variable_time() || !c1.allow_variable_time() {
        return Err(Error::Statement);
    }
    let p = parameters(parameter_bytes)?;
    for (operand, parsed) in parsed.into_iter().enumerate() {
        for b in 0..5 {
            same_pb(parsed.c0(), b, values(c, operand * 10 + b)?)?;
        }
        match parsed.second() {
            SecondComponent::Stored(poly) => {
                for b in 0..5 {
                    same_pb(poly, b, values(c, operand * 10 + 5 + b)?)?;
                }
            }
            SecondComponent::Seed(seed) => {
                let expanded = Poly::random_from_seed(
                    p.context_at_level(0).map_err(|_| Error::Statement)?,
                    Representation::Ntt,
                    *seed,
                );
                if Vec::<u64>::from(&expanded).as_slice()
                    != c.native_component(2 * operand + 1)
                        .ok_or(Error::Statement)?
                {
                    return Err(Error::Statement);
                }
            }
        }
    }
    for (component, poly) in [out.c0(), c1].into_iter().enumerate() {
        for b in 0..5 {
            same_pb(poly, b, values(c, 124 + 5 * component + b)?)?;
        }
    }
    Ok(())
}
fn values(c: &GraphClaims, node: usize) -> Result<&[u64]> {
    Ok(c.node(node).ok_or(Error::Statement)?.coefficients())
}
