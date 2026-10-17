//! Caller-owned mathematical inputs; one in-place field vector and one row-major trace.
//! Native field/FFT/row buffers are not securely erased by this low-level kernel.
use crate::{
    BLOCKS, FIELDS, FIRST_STAGE, GADGETS, N, OUTPUT_ROW, TWIST_ROW, circuit::*, hash_phase, psi,
    reverse, signed,
};
use crate::{Expected, SetupDescriptor, Statement};
use bfv_hiding_stark::poseidon;
use bfv_hiding_stark::{Error, TRACE_HEIGHT, Val};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

pub fn digest(context: [Val; 8], salt: [Val; 4], vector: &[Val]) -> [Val; 4] {
    assert_eq!(vector.len(), N);
    let prefix: Vec<_> = context
        .into_iter()
        .chain(salt)
        .chain([Val::ZERO; 4])
        .collect();
    let permutation = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    for block in prefix
        .as_chunks::<8>()
        .0
        .iter()
        .chain(vector.as_chunks::<8>().0.iter())
    {
        state[..8].copy_from_slice(block);
        permutation.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
pub fn oracle(coefficients: &[Val]) -> Vec<Val> {
    // SDK default explicitly materializes its BitReversedMatrixView into natural order.
    Radix2DitParallel::<Val>::default().coset_dft(coefficients.to_vec(), psi())
}
pub fn advance(vector: &mut [Val], physical: usize) {
    if physical == TWIST_ROW {
        // Twist in natural order, then bit-reverse in-place: no second vector bank.
        let mut power = Val::ONE;
        for value in vector.iter_mut() {
            *value *= power;
            power *= psi();
        }
        for i in 0..N {
            let r = reverse(i);
            if i < r {
                vector.swap(i, r);
            }
        }
    } else if (FIRST_STAGE..OUTPUT_ROW).contains(&physical) {
        let half = 1 << (physical - FIRST_STAGE);
        let phi = psi() * psi();
        let step = phi.exp_u64((N / (2 * half)) as u64);
        for block in vector.chunks_exact_mut(2 * half) {
            let (left, right) = block.split_at_mut(half);
            let mut power = Val::ONE;
            for (a, b) in left.iter_mut().zip(right) {
                let old = *a;
                let value = *b * power;
                *a = old + value;
                *b = old - value;
                power *= step;
            }
        }
    }
}
pub fn statement(
    coefficients: &[i8],
    salts: [[Val; 4]; 2],
    descriptor: SetupDescriptor,
) -> Statement {
    assert_eq!(coefficients.len(), N);
    let vector: Vec<_> = coefficients.iter().copied().map(signed).collect();
    let mut statement = Statement {
        expected: Expected {
            descriptor,
            coefficients: [Val::ZERO; 4],
        },
        transformed: [Val::ZERO; 4],
    };
    let shifted: Vec<_> = vector.iter().map(|s| *s + Val::from_u8(20)).collect();
    statement.expected.coefficients = digest(statement.contexts()[0], salts[0], &shifted);
    statement.transformed = digest(statement.contexts()[1], salts[1], &oracle(&vector));
    statement
}
pub fn trace(
    coefficients: &[i8],
    salts: [[Val; 4]; 2],
    statement: &Statement,
) -> Result<RowMajorMatrix<Val>, Error> {
    if coefficients.len() != N {
        return Err(Error::Shape);
    }
    let mut vector: Vec<_> = coefficients.iter().copied().map(signed).collect();
    let mut checkpoint = [Val::ZERO; 12];
    let mut values = Vec::with_capacity(TRACE_HEIGHT * WIDTH);
    let contexts = statement.contexts();
    for physical in 0..TRACE_HEIGHT {
        values.extend(write_row(
            &vector,
            &mut checkpoint,
            salts,
            contexts,
            physical,
        ));
        advance(&mut vector, physical);
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}
/// Same native row writer is used by the real witness and coherent rebuilt tests.
pub fn write_row(
    vector: &[Val],
    checkpoint: &mut [Val; 12],
    salts: [[Val; 4]; 2],
    contexts: [[Val; 8]; 2],
    physical: usize,
) -> Vec<Val> {
    let mut row = vec![Val::ZERO; WIDTH];
    row[VECTOR..VECTOR + N].copy_from_slice(vector);
    row[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(checkpoint);
    for (role, salt) in salts.iter().enumerate() {
        row[SALTS + role * 4..SALTS + (role + 1) * 4].copy_from_slice(salt);
    }
    for g in 0..GADGETS {
        let mut input = [Val::ZERO; 12];
        if let Some((role, local)) = hash_phase(physical) {
            let block = local * GADGETS + g;
            if block < BLOCKS {
                for (slot, value) in input[..8].iter_mut().enumerate() {
                    let field = block * 8 + slot;
                    *value = match field {
                        0..=7 => contexts[role][field],
                        8..=11 => salts[role][field - 8],
                        12..=15 => Val::ZERO,
                        _ => vector[field - 16] + Val::from_u8(if role == 0 { 20 } else { 0 }),
                    };
                    if role == 0 && (16..FIELDS).contains(&field) {
                        let z = (vector[field - 16] + Val::from_u8(20)).as_canonical_u64();
                        let slack = 40u64.saturating_sub(z);
                        let at = RANGE + (g * 8 + slot) * 12;
                        for bit in 0..6 {
                            row[at + bit] = Val::from_u64((z >> bit) & 1);
                            row[at + 6 + bit] = Val::from_u64((slack >> bit) & 1);
                        }
                    }
                }
                if block != 0 {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
        }
        let out = poseidon::write(
            &mut row[P2 + g * poseidon::WIDTH..P2 + (g + 1) * poseidon::WIDTH],
            input,
        );
        if hash_phase(physical).is_some_and(|(_, local)| local * GADGETS + g < BLOCKS) {
            *checkpoint = out;
        }
    }
    row
}
