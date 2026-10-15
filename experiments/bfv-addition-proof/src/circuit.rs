use crate::Error;
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

pub(super) struct AddAir {
    public: RowMajorMatrix<Val>,
}
impl BaseAir<Val> for AddAir {
    fn width(&self) -> usize {
        super::LANES
    }
    fn preprocessed_width(&self) -> usize {
        4 * super::LANES
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
        16
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for AddAir {
    fn eval(&self, builder: &mut AB) {
        for lane in 0..super::LANES {
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
}

pub(super) fn config(air: &AddAir) -> Result<Config, Error> {
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
    let params = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<Val>(air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, super::LOG_HEIGHT).unwrap(),
        319,
        128,
        1,
        OpeningShape::new(),
        fri.grinding_sites(),
    );
    let bound = ProvenSecurity::compute(&params, 1 << super::LOG_HEIGHT);
    if bound.unique_decoding_bits < 128 || bound.list_decoding_bits < 128 {
        return Err(Error::SecurityProfile);
    }
    Ok(Config::new(
        Pcs::new(Radix2DitParallel::default(), mmcs, fri),
        Challenger::new(perm),
    ))
}

pub(super) fn statement(input: &[u8], output: &[u8]) -> Result<(AddAir, Vec<Val>), Error> {
    if input.len() != bfv_linear_circuit::REQUEST_BYTES || &input[..8] != b"BFVLADQ1" {
        return Err(Error::StatementShape);
    }
    let (binding, values) = bfv_linear_circuit::decode_output(output).map_err(|err| match err {
        bfv_linear_circuit::Error::Shape => Error::StatementShape,
        bfv_linear_circuit::Error::NonCanonicalResidue => Error::NonCanonicalResidue,
    })?;
    if input[8..40] != binding {
        return Err(Error::RequestBinding);
    }
    let read = |offset| u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
    let n = bfv_linear_circuit::COEFFICIENTS;
    let mut data = vec![Val::ZERO; super::TRACE_HEIGHT * super::LANES * 4];
    for (i, c) in values.into_iter().enumerate() {
        let a = read(40 + i * 8);
        let b = read(40 + (n + i) * 8);
        let q = bfv_linear_circuit::MODULI[(i / bfv_linear_circuit::DEGREE) % 5];
        if a >= q || b >= q {
            return Err(Error::NonCanonicalResidue);
        }
        data[i * 4..i * 4 + 4].copy_from_slice(&[
            Val::from_u64(a),
            Val::from_u64(b),
            Val::from_u64(c),
            Val::from_u64(q),
        ]);
    }
    // No addition is performed here: these are the verifier's own fixed public
    // operands/claimed answer. Every real row is committed; remaining rows are zero.
    let values = [Sha256::digest(input), Sha256::digest(output)]
        .iter()
        .flat_map(|hash| {
            hash.as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| Val::from_u32(u32::from_le_bytes(*bytes)))
        })
        .collect();
    Ok((
        AddAir {
            public: RowMajorMatrix::new(data, 4 * super::LANES),
        },
        values,
    ))
}
