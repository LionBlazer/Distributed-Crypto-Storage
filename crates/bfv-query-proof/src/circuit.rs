use crate::{Error, Operation};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{AirLayout, OpeningShape, ProvenSecurity, StarkConfig, StarkSecurityParams};
use sha2::{Digest, Sha256};

type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<12>;
type Hash = PaddingFreeSponge<Perm, 12, 8, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 12>;
type Mmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 4>;
type Challenge = BinomialExtensionField<Val, 5>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
type Pcs = TwoAdicFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ChallengeMmcs>;
pub(super) type Config = StarkConfig<Pcs, Challenge, Challenger>;
const LIMB_BITS: usize = 22;
const BASE: u64 = 1 << LIMB_BITS;
const MASK: u64 = BASE - 1;
const QUOTIENT_BITS: usize = 44;
const FIRST_CARRY_BITS: usize = 23;
const SECOND_CARRY_BITS: usize = 24;

pub(super) struct ArithmeticAir {
    operation: Operation,
    public: RowMajorMatrix<Val>,
}
impl BaseAir<Val> for ArithmeticAir {
    fn width(&self) -> usize {
        self.operation.witness_columns()
    }
    fn preprocessed_width(&self) -> usize {
        self.operation.public_columns()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.public.clone())
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        self.operation.public_values()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for ArithmeticAir {
    fn eval(&self, builder: &mut AB) {
        match self.operation {
            Operation::Addition => {
                for lane in 0..self.operation.lanes() {
                    let (k, a, b, c, q) = {
                        let main = builder.main();
                        let prep = builder.preprocessed();
                        (
                            main.current(lane).unwrap(),
                            prep.current(4 * lane).unwrap(),
                            prep.current(4 * lane + 1).unwrap(),
                            prep.current(4 * lane + 2).unwrap(),
                            prep.current(4 * lane + 3).unwrap(),
                        )
                    };
                    builder.assert_bool(k);
                    builder.assert_zero(a + b - c - q * k);
                }
            }
            Operation::PublicPolynomialProduct => {
                for lane in 0..self.operation.lanes() {
                    let main = builder.main();
                    let prep = builder.preprocessed();
                    let zero = main.current(lane).unwrap();
                    let public: [_; 12] =
                        core::array::from_fn(|col| prep.current(lane * 12 + col).unwrap());
                    let [a0, a1, b0, b1, c0, c1, q0, q1, k0, k1, r1, r2] = public;
                    builder.assert_zero(zero);
                    builder.assert_zero(a0 * b0 - c0 - q0 * k0 - r1 * Val::from_u64(BASE));
                    builder.assert_zero(
                        a0 * b1 + a1 * b0 - c1 - q0 * k1 - q1 * k0 + r1 - r2 * Val::from_u64(BASE),
                    );
                    builder.assert_zero(a1 * b1 - q1 * k1 + r2);
                }
            }
        }
    }
}

pub(super) fn config(air: &ArithmeticAir) -> Result<Config, Error> {
    let perm = default_goldilocks_poseidon2_12();
    let mmcs = Mmcs::new(Hash::new(perm.clone()), Compress::new(perm.clone()), 0);
    let fri = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 192,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs.clone()),
    };
    let height = air.operation.height();
    let params = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<Val>(air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, air.operation.log_height()).unwrap(),
        319,
        128,
        1,
        OpeningShape::new(),
        fri.grinding_sites(),
    );
    let bound = ProvenSecurity::compute(&params, height);
    if bound.unique_decoding_bits < 128 || bound.list_decoding_bits < 128 {
        return Err(Error::SecurityProfile);
    }
    Ok(Config::new(
        Pcs::new(Radix2DitParallel::default(), mmcs, fri),
        Challenger::new(perm),
    ))
}

pub(super) fn statement(
    operation: Operation,
    input: &[u8],
    output: &[u8],
    certificate: &[u8],
) -> Result<(ArithmeticAir, Vec<Val>), Error> {
    if input.len() != bfv_linear_circuit::REQUEST_BYTES
        || certificate.len() != operation.certificate_bytes()
    {
        return Err(Error::StatementShape);
    }
    let (binding, results) = match operation {
        Operation::Addition => {
            bfv_linear_circuit::decode_output(output).map_err(|err| match err {
                bfv_linear_circuit::Error::Shape => Error::StatementShape,
                bfv_linear_circuit::Error::NonCanonicalResidue => Error::NonCanonicalResidue,
            })?
        }
        Operation::PublicPolynomialProduct => {
            bfv_product_circuit::decode_output(output).map_err(|err| match err {
                bfv_product_circuit::Error::Shape => Error::StatementShape,
                bfv_product_circuit::Error::NonCanonicalResidue => Error::NonCanonicalResidue,
            })?
        }
    };
    if input[8..40] != binding {
        return Err(Error::RequestBinding);
    }
    let mut data = vec![Val::ZERO; operation.height() * operation.public_columns()];
    for (i, c) in results.into_iter().enumerate() {
        let (a, b, q) = operands(input, i);
        if a >= q || b >= q {
            return Err(Error::NonCanonicalResidue);
        }
        match operation {
            Operation::Addition => data[i * 4..i * 4 + 4].copy_from_slice(&[
                Val::from_u64(a),
                Val::from_u64(b),
                Val::from_u64(c),
                Val::from_u64(q),
            ]),
            Operation::PublicPolynomialProduct => {
                let (k, s1, s2) = decode_certificate(&certificate[i * 12..(i + 1) * 12])?;
                let limbs = [
                    a & MASK,
                    a >> LIMB_BITS,
                    b & MASK,
                    b >> LIMB_BITS,
                    c & MASK,
                    c >> LIMB_BITS,
                    q & MASK,
                    q >> LIMB_BITS,
                    k & MASK,
                    k >> LIMB_BITS,
                ];
                let row = &mut data[i * 12..i * 12 + 12];
                for (target, value) in row.iter_mut().zip(limbs) {
                    *target = Val::from_u64(value);
                }
                row[10] = Val::from_u64(s1) - Val::from_u64(BASE);
                row[11] = Val::from_u64(s2) - Val::from_u64(2 * BASE);
            }
        }
    }
    // The verifier performs range checks and commitments only, never either
    // arithmetic relation. The digests bind the entire opaque original request.
    let mut hashes = vec![Sha256::digest(input), Sha256::digest(output)];
    if operation == Operation::PublicPolynomialProduct {
        hashes.push(Sha256::digest(certificate));
    }
    let values = hashes
        .iter()
        .flat_map(|hash| {
            hash.as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| Val::from_u32(u32::from_le_bytes(*bytes)))
        })
        .collect();
    Ok((
        ArithmeticAir {
            operation,
            public: RowMajorMatrix::new(data, operation.public_columns()),
        },
        values,
    ))
}

fn operands(input: &[u8], index: usize) -> (u64, u64, u64) {
    let read = |i| u64::from_le_bytes(input[40 + i * 8..48 + i * 8].try_into().unwrap());
    let q = bfv_linear_circuit::MODULI[(index / bfv_linear_circuit::DEGREE) % 5];
    (
        read(index),
        read(index + bfv_linear_circuit::COEFFICIENTS),
        q,
    )
}

/// Public auxiliary values are derived only from public ciphertext operands.
/// The verifier parses their ranges, commits them independently, and still requires
/// the STARK of the exact integer-safe limb relation; it never recomputes them.
pub(super) fn certificate(operation: Operation, input: &[u8]) -> Result<Vec<u8>, Error> {
    if operation == Operation::Addition {
        return Ok(vec![]);
    }
    let mut certificate = Vec::with_capacity(operation.certificate_bytes());
    for i in 0..bfv_linear_circuit::COEFFICIENTS {
        let (a, b, q) = operands(input, i);
        let (k, s1, s2) = product_carries(a, b, q)?;
        certificate.extend_from_slice(&k.to_le_bytes()[..6]);
        certificate.extend_from_slice(&s1.to_le_bytes()[..3]);
        certificate.extend_from_slice(&s2.to_le_bytes()[..3]);
    }
    Ok(certificate)
}

fn decode_certificate(certificate: &[u8]) -> Result<(u64, u64, u64), Error> {
    let read = |bytes: &[u8]| {
        let mut padded = [0; 8];
        padded[..bytes.len()].copy_from_slice(bytes);
        u64::from_le_bytes(padded)
    };
    let k = read(&certificate[..6]);
    let s1 = read(&certificate[6..9]);
    let s2 = read(&certificate[9..12]);
    if k >= 1 << QUOTIENT_BITS || s1 >= 1 << FIRST_CARRY_BITS || s2 >= 1 << SECOND_CARRY_BITS {
        return Err(Error::NonCanonicalResidue);
    }
    Ok((k, s1, s2))
}

pub(super) fn witness(operation: Operation, input: &[u8]) -> Result<RowMajorMatrix<Val>, Error> {
    let mut values = vec![Val::ZERO; operation.height() * operation.witness_columns()];
    if operation == Operation::Addition {
        for (i, value) in values
            .iter_mut()
            .enumerate()
            .take(bfv_linear_circuit::COEFFICIENTS)
        {
            let (a, b, q) = operands(input, i);
            *value = Val::from_bool(a + b >= q);
        }
    }
    Ok(RowMajorMatrix::new(values, operation.witness_columns()))
}

fn product_carries(a: u64, b: u64, q: u64) -> Result<(u64, u64, u64), Error> {
    let product = u128::from(a) * u128::from(b);
    let k = (product / u128::from(q)) as u64;
    let c = (product % u128::from(q)) as u64;
    let limb = |v: u64| (i128::from(v & MASK), i128::from(v >> LIMB_BITS));
    let ((a0, a1), (b0, b1), (c0, c1), (q0, q1), (k0, k1)) =
        (limb(a), limb(b), limb(c), limb(q), limb(k));
    let base = i128::from(BASE);
    let first_numerator = a0 * b0 - c0 - q0 * k0;
    if first_numerator % base != 0 {
        return Err(Error::Proving);
    }
    let r1 = first_numerator / base;
    let second_numerator = a0 * b1 + a1 * b0 - c1 - q0 * k1 - q1 * k0 + r1;
    if second_numerator % base != 0 {
        return Err(Error::Proving);
    }
    let r2 = second_numerator / base;
    if a1 * b1 - q1 * k1 + r2 != 0
        || !(0..1u64 << QUOTIENT_BITS).contains(&k)
        || !(-base..base).contains(&r1)
        || !(-2 * base..2 * base).contains(&r2)
    {
        return Err(Error::Proving);
    }
    Ok((k, (r1 + base) as u64, (r2 + 2 * base) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotient_and_shifted_carry_ranges_cover_every_fixed_modulus_boundary() {
        for q in bfv_linear_circuit::MODULI {
            for a in [0, 1, BASE - 1, BASE, BASE + 1, q / 2, q - 2, q - 1] {
                for b in [0, 1, BASE - 1, BASE, BASE + 1, q / 2, q - 2, q - 1] {
                    let (k, s1, s2) = product_carries(a, b, q).unwrap();
                    assert!(k < q);
                    assert!(s1 < 2 * BASE);
                    assert!(s2 < 4 * BASE);
                }
            }
        }
    }

    #[test]
    fn limb_air_rejects_a_canonical_modular_product_that_only_matches_by_goldilocks_wrap() {
        // Construct the concrete attack against the tempting single-field equation:
        // ab - forged_c - q*forged_k = -p, rather than zero over integers.
        let q = bfv_linear_circuit::MODULI[4];
        let p = 18_446_744_069_414_584_321_u128;
        let delta = p.div_ceil(u128::from(q)) as u64;
        let gap = u128::from(q) * u128::from(delta) - p;
        let b = q * 618 / 1000;
        let a = (0..1024)
            .map(|n| q / 2 + n)
            .find(|a| u128::from(*a) * u128::from(b) % u128::from(q) >= gap)
            .unwrap();
        let (k, s1, s2) = product_carries(a, b, q).unwrap();
        let c = (u128::from(a) * u128::from(b) % u128::from(q)) as u64;
        let forged_c = (u128::from(c) - gap) as u64;
        let forged_k = k + delta;
        assert!(forged_c < q && forged_k < q);
        let naive = Val::from_u64(a) * Val::from_u64(b)
            - Val::from_u64(forged_c)
            - Val::from_u64(q) * Val::from_u64(forged_k);
        assert_eq!(
            naive,
            Val::ZERO,
            "the naive 64-bit-field relation accepts this forgery"
        );

        let limbs = [
            a & MASK,
            a >> LIMB_BITS,
            b & MASK,
            b >> LIMB_BITS,
            forged_c & MASK,
            forged_c >> LIMB_BITS,
            q & MASK,
            q >> LIMB_BITS,
            forged_k & MASK,
            forged_k >> LIMB_BITS,
        ];
        let operation = Operation::PublicPolynomialProduct;
        let mut public = vec![Val::ZERO; operation.public_columns()];
        for (target, value) in public.iter_mut().zip(limbs) {
            *target = Val::from_u64(value);
        }
        public[10] = Val::from_u64(s1) - Val::from_u64(BASE);
        public[11] = Val::from_u64(s2) - Val::from_u64(2 * BASE);
        let air = ArithmeticAir {
            operation,
            public: RowMajorMatrix::new(public, operation.public_columns()),
        };
        let trace = RowMajorMatrix::new(
            vec![Val::ZERO; operation.witness_columns()],
            operation.witness_columns(),
        );

        let report = p3_air::check_all_constraints(&air, &trace, &[Val::ZERO; 24], Some(4));

        assert!(
            !report.is_ok(),
            "integer limb constraints must reject the field-wrap forgery"
        );
    }
}
