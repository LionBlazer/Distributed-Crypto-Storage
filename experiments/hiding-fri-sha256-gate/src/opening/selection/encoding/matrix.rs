//! Public inverse-SIMD map only. No source value enters matrix generation.
use std::sync::OnceLock;

pub(super) const N: usize = 8192;
pub(super) const T: u64 = 114689;
pub(super) const Q_MOD_T: u64 = 78307;
pub(super) const SLOTS: [usize; 12] = [0, 1, 2, 3, 4096, 4097, 4098, 4099, 512, 513, 514, 515];
// fhe-math0.1.1 native::primitive_root(N,T), seed_from_u64(0), first
// public candidate81323^7. This is a PUBLIC parameter, not encryption randomness.
// Whole-matrix upstream tests bind this convention to the pinned encoder.
const ROOT: u64 = 64917;

fn mul(a: u64, b: u64) -> u64 {
    a * b % T
}
fn pow(mut a: u64, mut n: u64) -> u64 {
    let mut out = 1;
    while n != 0 {
        if n & 1 != 0 {
            out = mul(out, a);
        }
        a = mul(a, a);
        n >>= 1;
    }
    out
}
pub(super) fn inverse(values: &mut [u64]) {
    assert_eq!(values.len(), N);
    let inverse_root = pow(ROOT, T - 2);
    let mut powers = vec![inverse_root; N];
    for i in 1..N {
        powers[i] = mul(powers[i - 1], inverse_root);
    }
    let inverse: Vec<_> = (0..N)
        .map(|i| powers[i.reverse_bits() >> (usize::BITS - 13)])
        .collect();
    let mut length = 1;
    let mut at = 0;
    while length < N {
        for chunk in values.chunks_exact_mut(2 * length) {
            let omega = inverse[at];
            at += 1;
            let (left, right) = chunk.split_at_mut(length);
            for (x, y) in left.iter_mut().zip(right) {
                let old = *x;
                *x = (old + *y) % T;
                *y = mul(old + T - *y, omega);
            }
        }
        length *= 2;
    }
    let n_inverse = pow(N as u64, T - 2);
    for x in values {
        *x = mul(*x, n_inverse);
    }
}
pub(super) fn mapped_slot(slot: usize) -> usize {
    let mut position = 1;
    for _ in 0..slot % (N / 2) {
        position = (position * 3) & (2 * N - 1);
    }
    let index = if slot < N / 2 {
        (position - 1) / 2
    } else {
        (2 * N - position - 1) / 2
    };
    index.reverse_bits() >> (usize::BITS - 13)
}
pub(super) fn coefficients() -> &'static [[u32; 12]] {
    static MATRIX: OnceLock<Vec<[u32; 12]>> = OnceLock::new();
    MATRIX.get_or_init(|| {
        assert_eq!(pow(ROOT, N as u64), T - 1);
        let mut out = vec![[0; 12]; N];
        for (column, slot) in SLOTS.into_iter().enumerate() {
            let mut basis = vec![0; N];
            basis[mapped_slot(slot)] = 1;
            inverse(&mut basis);
            for (row, value) in out.iter_mut().zip(basis) {
                row[column] = value as u32;
            }
        }
        out
    })
}
pub(super) fn digest() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"DCS/public-N4-SIMD-matrix/v1");
    for row in coefficients() {
        for value in row {
            h.update(value.to_le_bytes());
        }
    }
    h.finalize().into()
}
