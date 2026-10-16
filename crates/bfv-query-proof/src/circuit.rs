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
                    let (k, a, b, c) = {
                        let main = builder.main();
                        let prep = builder.preprocessed();
                        (
                            main.current(lane).unwrap(),
                            prep.current(3 * lane).unwrap(),
                            prep.current(3 * lane + 1).unwrap(),
                            prep.current(3 * lane + 2).unwrap(),
                        )
                    };
                    builder.assert_bool(k);
                    builder.assert_zero(a + b - c - k * Val::from_u64(modulus(lane)));
                }
            }
            Operation::PublicPolynomialProduct => {
                for lane in 0..self.operation.lanes() {
                    let main = builder.main();
                    let prep = builder.preprocessed();
                    let zero = main.current(lane).unwrap();
                    let public: [_; 10] =
                        core::array::from_fn(|col| prep.current(lane * 10 + col).unwrap());
                    let [a0, a1, b0, b1, c0, c1, k0, k1, r1, r2] = public;
                    let q0 = Val::from_u64(modulus(lane) & MASK);
                    let q1 = Val::from_u64(modulus(lane) >> LIMB_BITS);
                    builder.assert_zero(zero);
                    builder.assert_zero(a0 * b0 - c0 - k0 * q0 - r1 * Val::from_u64(BASE));
                    builder.assert_zero(
                        a0 * b1 + a1 * b0 - c1 - k1 * q0 - k0 * q1 + r1 - r2 * Val::from_u64(BASE),
                    );
                    builder.assert_zero(a1 * b1 - k1 * q1 + r2);
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

pub(super) struct Statement {
    pub air: ArithmeticAir,
    pub values: Vec<Val>,
    /// Exact input/output/certificate hashes; the addition certificate is empty.
    pub hashes: [[u8; 32]; 3],
}

pub(super) fn statement(
    operation: Operation,
    input: &[u8],
    output: &[u8],
    certificate: &[u8],
) -> Result<Statement, Error> {
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
    let columns = operation.public_columns() / operation.lanes();
    for (row, public) in data
        .chunks_exact_mut(operation.public_columns())
        .enumerate()
    {
        for (lane, target) in public.chunks_exact_mut(columns).enumerate() {
            let i = lane * bfv_linear_circuit::DEGREE + row;
            let c = results[i];
            let (a, b, q) = operands(input, i);
            if a >= q || b >= q {
                return Err(Error::NonCanonicalResidue);
            }
            match operation {
                Operation::Addition => {
                    target.copy_from_slice(&[Val::from_u64(a), Val::from_u64(b), Val::from_u64(c)])
                }
                Operation::PublicPolynomialProduct => {
                    let (k, s1, s2) = decode_certificate(&certificate[i * 12..(i + 1) * 12])?;
                    let limbs = [
                        a & MASK,
                        a >> LIMB_BITS,
                        b & MASK,
                        b >> LIMB_BITS,
                        c & MASK,
                        c >> LIMB_BITS,
                        k & MASK,
                        k >> LIMB_BITS,
                    ];
                    for (target, value) in target.iter_mut().zip(limbs) {
                        *target = Val::from_u64(value);
                    }
                    target[8] = Val::from_u64(s1) - Val::from_u64(BASE);
                    target[9] = Val::from_u64(s2) - Val::from_u64(2 * BASE);
                }
            }
        }
    }
    // The verifier performs range checks and commitments only, never either
    // arithmetic relation. The digests bind the entire opaque original request.
    let hashes: [[u8; 32]; 3] = [
        Sha256::digest(input).into(),
        Sha256::digest(output).into(),
        Sha256::digest(certificate).into(),
    ];
    let transcript_hashes = if operation == Operation::Addition {
        2
    } else {
        3
    };
    let values = hashes
        .iter()
        .take(transcript_hashes)
        .flat_map(|hash| {
            hash.as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| Val::from_u32(u32::from_le_bytes(*bytes)))
        })
        .collect();
    Ok(Statement {
        air: ArithmeticAir {
            operation,
            public: RowMajorMatrix::new(data, operation.public_columns()),
        },
        values,
        hashes,
    })
}

fn modulus(lane: usize) -> u64 {
    bfv_linear_circuit::MODULI[lane % bfv_linear_circuit::MODULI.len()]
}

fn operands(input: &[u8], index: usize) -> (u64, u64, u64) {
    let read = |i| u64::from_le_bytes(input[40 + i * 8..48 + i * 8].try_into().unwrap());
    let q = modulus(index / bfv_linear_circuit::DEGREE);
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
        for i in 0..bfv_linear_circuit::COEFFICIENTS {
            let (a, b, q) = operands(input, i);
            let lane = i / bfv_linear_circuit::DEGREE;
            let row = i % bfv_linear_circuit::DEGREE;
            values[row * operation.lanes() + lane] = Val::from_bool(a + b >= q);
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
    fn arithmetic_constraints_cover_both_ends_of_every_polynomial_lane() {
        let left: Vec<_> = (0..bfv_linear_circuit::COEFFICIENTS)
            .map(|index| index as u64 * 17 + 3)
            .collect();
        let right: Vec<_> = (0..bfv_linear_circuit::COEFFICIENTS)
            .map(|index| modulus(index / bfv_linear_circuit::DEGREE) - 1)
            .collect();
        for operation in [Operation::Addition, Operation::PublicPolynomialProduct] {
            let input = match operation {
                Operation::Addition => {
                    bfv_linear_circuit::encode_request([7; 32], &left, &right).unwrap()
                }
                Operation::PublicPolynomialProduct => {
                    bfv_product_circuit::encode_request([7; 32], &left, &right).unwrap()
                }
            };
            let output = operation.evaluate(&input).unwrap();
            let auxiliary = certificate(operation, &input).unwrap();
            let trace = witness(operation, &input).unwrap();
            let Statement { air, values, .. } =
                statement(operation, &input, &output, &auxiliary).unwrap();
            assert!(p3_air::check_all_constraints(&air, &trace, &values, Some(1)).is_ok());
            for lane in 0..operation.lanes() {
                for coefficient in [0, bfv_linear_circuit::DEGREE - 1] {
                    let index = lane * bfv_linear_circuit::DEGREE + coefficient;
                    let offset = 40 + index * 8;
                    let mut changed = output.clone();
                    let value = u64::from_le_bytes(changed[offset..offset + 8].try_into().unwrap());
                    changed[offset..offset + 8]
                        .copy_from_slice(&((value + 1) % modulus(lane)).to_le_bytes());
                    // Rebuild public preprocessing and hashes around the forged
                    // result: rejection must come from arithmetic, not reuse of
                    // a proof with a different SHA-256 transcript.
                    let Statement {
                        air: forged,
                        values: hashes,
                        ..
                    } = statement(operation, &input, &changed, &auxiliary).unwrap();
                    assert!(
                        !p3_air::check_all_constraints(&forged, &trace, &hashes, Some(1)).is_ok(),
                        "{operation:?}, polynomial {lane}, coefficient {coefficient}"
                    );
                }
            }
        }
    }

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
            forged_k & MASK,
            forged_k >> LIMB_BITS,
        ];
        let operation = Operation::PublicPolynomialProduct;
        let mut public = vec![Val::ZERO; operation.public_columns()];
        // This attack uses MODULI[4], hence lane four. Using lane zero with
        // another constant modulus would reject for the wrong reason.
        let attack = &mut public[4 * 10..5 * 10];
        for (target, value) in attack.iter_mut().zip(limbs) {
            *target = Val::from_u64(value);
        }
        attack[8] = Val::from_u64(s1) - Val::from_u64(BASE);
        attack[9] = Val::from_u64(s2) - Val::from_u64(2 * BASE);
        let mut correct = public.clone();
        correct[4 * 10 + 4] = Val::from_u64(c & MASK);
        correct[4 * 10 + 5] = Val::from_u64(c >> LIMB_BITS);
        correct[4 * 10 + 6] = Val::from_u64(k & MASK);
        correct[4 * 10 + 7] = Val::from_u64(k >> LIMB_BITS);
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
        let correct_air = ArithmeticAir {
            operation,
            public: RowMajorMatrix::new(correct, operation.public_columns()),
        };
        assert!(
            p3_air::check_all_constraints(&correct_air, &trace, &[Val::ZERO; 24], Some(4)).is_ok(),
            "the same lane and carries must accept the genuine integer product"
        );
    }
}
