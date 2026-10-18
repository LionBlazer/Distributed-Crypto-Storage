//! Actual upstream public polynomial and scaler oracles, not duplicate host formulas.
use super::*;
#[test]
fn all8192_outputs_of_all_seventeen_roles_match_actual_upstream_sdk_operations() {
    use fhe_math::{
        rns::{RnsContext, RnsScaler, ScalingFactor},
        rq::{Context as PolyContext, Poly, Representation, traits::TryConvertFrom},
    };
    use num_bigint::BigUint;
    use std::sync::Arc;
    let context = fixture::context();
    let requests = fixture::requests(context).unwrap();
    let (outputs, aux) = proof::evaluate(&requests).unwrap();
    drop(aux);
    for (index, (request, output)) in requests.iter().zip(&outputs).enumerate() {
        match (request, output) {
            (RelationRequest::Scale(r), RelationOutput::Scale(o)) => {
                let from = Arc::new(RnsContext::new(r.role().input_moduli()).unwrap());
                let to = Arc::new(RnsContext::new(r.role().output_moduli()).unwrap());
                let factor = if r.role() == scale::Role::Extend5To10 {
                    ScalingFactor::one()
                } else {
                    let denominator = scale::MODULI.iter().fold(BigUint::from(1u8), |x, &p| x * p);
                    ScalingFactor::new(&BigUint::from(scale::PLAINTEXT), &denominator)
                };
                let scaler = RnsScaler::new(&from, &to, factor);
                for coefficient in 0..8192 {
                    let residues = (0..r.role().input_moduli().len())
                        .map(|i| r.input()[i * 8192 + coefficient])
                        .collect::<Vec<_>>();
                    let wanted = scaler.scale_new(
                        ndarray::ArrayView1::from(residues.as_slice()),
                        r.role().output_moduli().len(),
                    );
                    for (lane, &v) in wanted.iter().enumerate() {
                        assert_eq!(
                            o.coefficients()[lane * 8192 + coefficient],
                            v,
                            "relation{index} lane{lane} coefficient{coefficient}"
                        );
                    }
                }
            }
            (RelationRequest::Tensor(r), RelationOutput::Tensor(o)) => {
                let context = Arc::new(PolyContext::new(&[r.basis().modulus()], 8192).unwrap());
                let polys = r
                    .input()
                    .as_chunks::<8192>()
                    .0
                    .iter()
                    .map(|row| {
                        Poly::try_convert_from(row.to_vec(), &context, false, Representation::Ntt)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                let d0 = &polys[0] * &polys[2];
                let mut d1 = &polys[0] * &polys[3];
                d1 += &(&polys[1] * &polys[2]);
                let d2 = &polys[1] * &polys[3];
                let wanted = [d0, d1, d2]
                    .iter()
                    .flat_map(Vec::<u64>::from)
                    .collect::<Vec<_>>();
                assert_eq!(o.coefficients(), wanted, "relation{index}");
            }
            _ => panic!("sealed role mismatch"),
        }
    }
}
#[test]
fn actual_sdk_prime_generator_selects_the_same_complete_qp_basis() {
    let mut primes = Vec::new();
    let mut upper = 1u64 << 62;
    while primes.len() < 6 {
        upper = fhe_math::zq::primes::generate_prime(62, 16384, upper).unwrap();
        if !primes.contains(&upper) && !scale::MODULI.contains(&upper) {
            primes.push(upper);
        }
    }
    let bits = scale::MODULI
        .iter()
        .map(|q| (64 - q.leading_zeros()) as usize)
        .sum::<usize>();
    let used = (bits + 60).div_ceil(62);
    assert_eq!(used, 5);
    assert_eq!(&primes[..used], scale::AUXILIARY_MODULI.as_slice());
    assert_eq!(scale::EXTENDED_MODULI, tensor::EXTENDED_MODULI);
}
