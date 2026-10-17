//! Pure exact relation writer for caller-owned inputs; native field buffers are not securely erased.
use super::air::*;
use crate::{
    BLOCKS, Expected, FIRST_STAGE, GADGETS, MULTIPLY_ROW, N, SCALE_ROW, Statement, hash_phase, psi,
    reverse,
};
use bfv_hiding_stark::{Error, TRACE_HEIGHT, Val, poseidon};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
pub fn oracle(evaluations: &[Val], a_hat: &[Val]) -> Vec<Val> {
    assert_eq!(evaluations.len(), N);
    assert_eq!(a_hat.len(), N);
    let product = evaluations
        .iter()
        .zip(a_hat)
        .map(|(a, b)| *a * *b)
        .collect();
    let mut output = Radix2DitParallel::<Val>::default().idft(product);
    let mut power = Val::ONE;
    let step = psi().inverse();
    for v in &mut output {
        *v *= power;
        power *= step;
    }
    output
}
pub fn statement(evaluations: &[Val], salts: [[Val; 4]; 2], expected: Expected) -> Statement {
    let mut s = Statement {
        expected,
        result: [Val::ZERO; 4],
    };
    s.result = bfv_key_transform::circuit::digest(
        s.contexts()[1],
        salts[1],
        &oracle(evaluations, s.expected.ciphertext().evaluations()),
    );
    s
}
pub fn trace(
    evaluations: &[Val],
    salts: [[Val; 4]; 2],
    s: &Statement,
) -> Result<RowMajorMatrix<Val>, Error> {
    if evaluations.len() != N {
        return Err(Error::Shape);
    }
    let mut vector = evaluations.to_vec();
    let mut cp = [Val::ZERO; 12];
    let mut values = Vec::with_capacity(TRACE_HEIGHT * WIDTH);
    let contexts = s.contexts();
    for physical in 0..TRACE_HEIGHT {
        values.extend(write_row(&vector, &mut cp, salts, contexts, physical));
        advance(&mut vector, physical, s.expected.ciphertext().evaluations());
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}
pub fn advance(vector: &mut [Val], physical: usize, a_hat: &[Val]) {
    if physical == MULTIPLY_ROW {
        for (x, a) in vector.iter_mut().zip(a_hat) {
            *x *= *a;
        }
        for i in 0..N {
            let r = reverse(i);
            if i < r {
                vector.swap(i, r);
            }
        }
    } else if (FIRST_STAGE..SCALE_ROW).contains(&physical) {
        let half = 1 << (physical - FIRST_STAGE);
        let phi_inverse = (psi() * psi()).inverse();
        let step = phi_inverse.exp_u64((N / (2 * half)) as u64);
        for block in vector.chunks_exact_mut(2 * half) {
            let (left, right) = block.split_at_mut(half);
            let mut power = Val::ONE;
            for (a, b) in left.iter_mut().zip(right) {
                let old = *a;
                let v = *b * power;
                *a = old + v;
                *b = old - v;
                power *= step;
            }
        }
    } else if physical == SCALE_ROW {
        let mut power = Val::from_usize(N).inverse();
        let step = psi().inverse();
        for v in vector {
            *v *= power;
            power *= step;
        }
    }
}
pub fn write_row(
    vector: &[Val],
    cp: &mut [Val; 12],
    salts: [[Val; 4]; 2],
    contexts: [[Val; 8]; 2],
    physical: usize,
) -> Vec<Val> {
    let mut row = vec![Val::ZERO; WIDTH];
    row[..N].copy_from_slice(vector);
    row[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(cp);
    for (role, salt) in salts.iter().enumerate() {
        row[SALTS + role * 4..SALTS + (role + 1) * 4].copy_from_slice(salt);
    }
    for g in 0..GADGETS {
        let mut input = [Val::ZERO; 12];
        if let Some((role, local)) = hash_phase(physical) {
            let block = local * GADGETS + g;
            if block < BLOCKS {
                for (slot, v) in input[..8].iter_mut().enumerate() {
                    let f = block * 8 + slot;
                    *v = match f {
                        0..=7 => contexts[role][f],
                        8..=11 => salts[role][f - 8],
                        12..=15 => Val::ZERO,
                        _ => vector[f - 16],
                    };
                }
                if block != 0 {
                    input[8..].copy_from_slice(&cp[8..]);
                }
            }
        }
        let out = poseidon::write(
            &mut row[P2 + g * poseidon::WIDTH..P2 + (g + 1) * poseidon::WIDTH],
            input,
        );
        if hash_phase(physical).is_some_and(|(_, local)| local * GADGETS + g < BLOCKS) {
            *cp = out;
        }
    }
    row
}
