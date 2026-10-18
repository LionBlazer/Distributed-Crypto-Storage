//! PUBLIC NONSECRET actual Owner encrypted-product fixture and independent SDK oracle.
//! No fixture output enters a primitive proof or verifier request.
use crate::{COMPONENTS, DEGREE, Error, Input, MODULI, PreparedKey, Prover, Result, Verifier};
use bfv_query_core::{Geometry, Owner, PublicSetup, QueryContext, RowProjection, SelectedField};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, RelinearizationKey};
#[cfg(test)]
use fhe_math::rq::Poly;
use fhe_math::rq::Representation;
use fhe_traits::{DeserializeParametrized, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Instant};
mod security;

pub(crate) struct PublicFixture {
    pub setup: PublicSetup,
    pub keyset_id: [u8; 32],
    pub input: Input,
    pub oracle: [Vec<u64>; 2],
}
pub(crate) fn parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_moduli(&MODULI)
        .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
        .set_variance(10)
        .build_arc()
        .map_err(|_| Error::Oracle)
}
fn original_ciphertext(
    owner: &Owner,
    parameters: &Arc<BfvParameters>,
    tag: u8,
) -> Result<Ciphertext> {
    let fields = [
        SelectedField {
            age: tag,
            amount: 257 * u16::from(tag),
            active: true,
        },
        SelectedField {
            age: 255,
            amount: 65535,
            active: true,
        },
    ];
    let prepared = owner.prepare_exact_select_for_experiment(
        QueryContext::new([tag; 16], [3; 112], [4; 112]),
        &fields,
        RowProjection::AgeAmount,
    )?;
    // This is the documented PUBLIC ciphertext-only payload tuple, not a mirror
    // of Core's private Request or pending state. No secret or plaintext getter.
    let (rows, mask): (Vec<u8>, Vec<u8>) =
        bincode::deserialize(&prepared.ciphertext_payload_bytes()?).map_err(|_| Error::Oracle)?;
    if !mask.is_empty() {
        return Err(Error::Oracle);
    }
    Ciphertext::from_bytes(&rows, parameters).map_err(|_| Error::Oracle)
}
pub(crate) fn actual_owner_product() -> Result<PublicFixture> {
    let (owner, setup) = Owner::generate(Geometry::Rows16)?;
    let keyset_id = Sha256::digest(setup.to_bytes()?).into();
    let parameters = parameters()?;
    let material = setup.relinearization_material()?;
    if parameters.to_bytes() != material.parameters() {
        return Err(Error::Oracle);
    }
    let key = RelinearizationKey::from_bytes(material.relinearization_key(), &parameters)
        .map_err(|_| Error::Oracle)?;
    let left = original_ciphertext(&owner, &parameters, 17)?;
    let right = original_ciphertext(&owner, &parameters, 29)?;
    let mut product = &left * &right; // ACTUAL upstream full ciphertext multiplication.
    if product.len() != 3
        || product
            .iter()
            .any(|p| p.representation() != &Representation::Ntt)
    {
        return Err(Error::Oracle);
    }
    // Extract native NTT arrays. SDK to_bytes would contain PB, despite its NTT tag.
    let components: [Vec<u64>; 3] = core::array::from_fn(|i| Vec::<u64>::from(&product[i]));
    let input = Input::new([0x63; 32], components)?;
    key.relinearizes(&mut product).map_err(|_| Error::Oracle)?;
    let oracle = core::array::from_fn(|i| Vec::<u64>::from(&product[i]));
    drop(key);
    drop(owner); // Private Owner is gone BEFORE composition proof or verification.
    Ok(PublicFixture {
        setup,
        keyset_id,
        input,
        oracle,
    })
}
/// Actual analytical reports only: no Owner, key preprocessing, trace or proof generation.
pub fn security() -> Result<()> {
    for direction in [
        bfv_ntt_circuit::Direction::Inverse,
        bfv_ntt_circuit::Direction::Forward,
    ] {
        for basis in 0..5 {
            let (input, output) = security::ntt(direction, bfv_ntt_circuit::Basis::new(basis)?)?;
            let report = bfv_ntt_witness_proof::analyze(&input, &output)?;
            println!(
                "{}",
                serde_json::to_string(&report).map_err(|_| Error::Shape)?
            );
        }
    }
    for role in [
        bfv_relinearization_circuit::Role::Embed,
        bfv_relinearization_circuit::Role::AccumulateAndAdd,
    ] {
        let (input, output, aux) = security::relinearization(role)?;
        let report = bfv_relinearization_multilinear_proof::analyze(&input, &output, &aux)?;
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|_| Error::Shape)?
        );
    }
    Ok(())
}
pub fn prove_stream() -> Result<()> {
    let total = Instant::now();
    let fixture = actual_owner_product()?;
    let setup_bytes = fixture.setup.to_bytes()?;
    let owner_and_oracle_ms = total.elapsed().as_secs_f64() * 1000.0;
    let timer = Instant::now();
    let key = PreparedKey::from_original(&fixture.setup, fixture.keyset_id)?;
    let setup_ms = timer.elapsed().as_secs_f64() * 1000.0;
    let mut spool = crate::spool::PublicSpool::new()?;
    let mut sizes = Vec::with_capacity(COMPONENTS);
    let timer = Instant::now();
    let mut prover = Prover::new(&key, &fixture.input);
    while let Some(component) = prover.prove_next()? {
        sizes.push(component.as_bytes().len());
        spool.write_next(component.as_bytes())?;
    }
    if prover.progress() != COMPONENTS || spool.count() != COMPONENTS {
        return Err(Error::Incomplete);
    }
    drop(prover);
    drop(key);
    let generation_ms = timer.elapsed().as_secs_f64() * 1000.0;
    let timer = Instant::now();
    let fresh_setup = PublicSetup::from_bytes(&setup_bytes)?;
    let fresh_key = PreparedKey::from_original(&fresh_setup, fixture.keyset_id)?;
    let mut verifier = Verifier::new(&fresh_key, &fixture.input);
    for ordinal in 0..COMPONENTS {
        verifier.accept(&spool.read(ordinal)?)?;
    }
    let checked = verifier.finish()?;
    if !checked.matches(&fresh_key, &fixture.input) || checked.output() != &fixture.oracle {
        return Err(Error::Oracle);
    }
    let verification_ms = timer.elapsed().as_secs_f64() * 1000.0;
    spool.finish()?; // Include CHECKED public-file cleanup in complete elapsed.
    println!(
        "{}",
        serde_json::json!({
            "stage":"verified_complete_relinearization_stream", "components":COMPONENTS,
            "input_representation":"native_ntt3_q5", "output_representation":"native_ntt2_q5",
            "coefficients_per_row":DEGREE,"output_rows":10,"all8192_sdk_oracle":true,
            "component_bytes":sizes,"setup_bytes":setup_bytes.len(),
            "owner_input_and_sdk_oracle_ms":owner_and_oracle_ms,"public_key_preprocessing_ms":setup_ms,
            "proving_and_spool_write_ms":generation_ms,
            "fresh_key_setup_spool_read_and_verification_ms":verification_ms,
            "total_ms":total.elapsed().as_secs_f64()*1000.0,"spool_cleanup":true,
            "live_sql_grant":false,"same_secret_evaluation_key_proven":false,
            "whole_mul_relin":false,"agreed_finality":false,"writer_fence":false,
            "composed_128_claim":false
        })
    );
    Ok(())
}
/// Independent actual SDK key oracle used only by owning tests.
#[cfg(test)]
pub(crate) fn sdk_key_rows(setup: &PublicSetup) -> Result<[[Vec<u64>; 2]; 5]> {
    use fhe_math::rq::traits::TryConvertFrom;
    let params = parameters()?;
    let key = RelinearizationKey::from_bytes(
        setup.relinearization_material()?.relinearization_key(),
        &params,
    )
    .map_err(|_| Error::Oracle)?;
    let context = params.context_at_level(0).map_err(|_| Error::Oracle)?;
    let mut result: [[Vec<u64>; 2]; 5] =
        core::array::from_fn(|_| core::array::from_fn(|_| Vec::new()));
    for (source, rows) in result.iter_mut().enumerate() {
        let mut spike = vec![0; 5 * DEGREE];
        spike[source * DEGREE] = 1;
        let mut c2 = Poly::try_convert_from(spike, context, true, Representation::PowerBasis)
            .map_err(|_| Error::Oracle)?;
        c2.change_representation(Representation::Ntt);
        let zero = Poly::zero(context, Representation::Ntt);
        let mut probe =
            Ciphertext::new(vec![zero.clone(), zero, c2], &params).map_err(|_| Error::Oracle)?;
        key.relinearizes(&mut probe).map_err(|_| Error::Oracle)?;
        *rows = [Vec::<u64>::from(&probe[0]), Vec::<u64>::from(&probe[1])];
    }
    Ok(result)
}
