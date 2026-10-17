//! Exact public root/table/routing convention of pinned fhe-math0.1.1 native.rs.
use crate::{Basis, DEGREE, Direction};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
pub struct Parameters {
    root: u64,
    inverse_size: u64,
    forward: Vec<u64>,
    inverse: Vec<u64>,
}
impl Parameters {
    pub fn primitive_root(&self) -> u64 {
        self.root
    }
    pub fn inverse_size(&self) -> u64 {
        self.inverse_size
    }
    pub fn forward_twiddles(&self) -> &[u64] {
        &self.forward
    }
    pub fn inverse_twiddles(&self) -> &[u64] {
        &self.inverse
    }
}
pub(crate) fn mul(x: u64, y: u64, p: u64) -> u64 {
    ((x as u128 * y as u128) % p as u128) as u64
}
pub(crate) fn pow(mut x: u64, mut n: u64, p: u64) -> u64 {
    let mut out = 1;
    while n != 0 {
        if n & 1 != 0 {
            out = mul(out, x, p);
        }
        x = mul(x, x, p);
        n >>= 1;
    }
    out
}
fn build(basis: Basis) -> Parameters {
    let p = basis.modulus();
    let lambda = (p - 1) / (2 * DEGREE as u64);
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let root = (0..100)
        .find_map(|_| {
            let root = pow(rng.random_range(0..p), lambda, p);
            (pow(root, (2 * DEGREE) as u64, p) == 1 && pow(root, DEGREE as u64, p) != 1)
                .then_some(root)
        })
        .expect("fixed pinned primes support exact native SDK root search");
    let root_inv = pow(root, p - 2, p);
    let mut powers = vec![1; DEGREE];
    let mut inverses = vec![root_inv; DEGREE];
    for i in 1..DEGREE {
        powers[i] = mul(powers[i - 1], root, p);
        inverses[i] = mul(inverses[i - 1], root_inv, p);
    }
    let reverse = |i: usize| i.reverse_bits() >> (usize::BITS - 13);
    Parameters {
        root,
        inverse_size: pow(DEGREE as u64, p - 2, p),
        forward: (0..DEGREE).map(|i| powers[reverse(i)]).collect(),
        inverse: (0..DEGREE).map(|i| inverses[reverse(i)]).collect(),
    }
}
pub fn parameters(basis: Basis) -> &'static Parameters {
    static VALUES: OnceLock<[Parameters; 10]> = OnceLock::new();
    &VALUES.get_or_init(|| core::array::from_fn(|i| build(Basis::new(i as u8).unwrap())))
        [basis.index() as usize]
}
pub(crate) struct Lane {
    pub x: usize,
    pub y: usize,
    pub a: u64,
    pub b: u64,
}
/// Exact SDK gathers with fixed positive modular weights. No coefficient arithmetic.
pub(crate) fn lane(direction: Direction, basis: Basis, stage: usize, index: usize) -> Lane {
    let params = parameters(basis);
    if direction == Direction::Inverse && stage == 13 {
        return Lane {
            x: index,
            y: index,
            a: params.inverse_size,
            b: 0,
        };
    }
    let l = match direction {
        Direction::Forward => DEGREE >> (stage + 1),
        Direction::Inverse => 1 << stage,
    };
    let chunk = index / (2 * l);
    let position = index % (2 * l);
    let x = chunk * (2 * l) + position % l;
    let right = position >= l;
    let p = basis.modulus();
    let (a, b) = match direction {
        Direction::Forward => {
            let w = params.forward[(1 << stage) + chunk];
            (1, if right { p - w } else { w })
        }
        Direction::Inverse => {
            let w = params.inverse[DEGREE - (DEGREE >> stage) + chunk];
            if right { (w, p - w) } else { (1, 1) }
        }
    };
    Lane { x, y: x + l, a, b }
}
pub fn profile_digest(direction: Direction, basis: Basis) -> [u8; 32] {
    // Fixed public tables are cached; this performs no caller-coefficient NTT.
    let params = parameters(basis);
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-NTT-CIRCUIT/v1/fhe-math0.1.1/native-ChaCha8-seed0/full8192");
    h.update([direction as u8, basis.index()]);
    h.update((DEGREE as u64).to_le_bytes());
    h.update(basis.modulus().to_le_bytes());
    h.update(params.root.to_le_bytes());
    h.update(params.inverse_size.to_le_bytes());
    for table in [&params.forward, &params.inverse] {
        for &w in table {
            h.update(w.to_le_bytes());
        }
    }
    h.update(b"forward-DIF-l=N/2..1-k=2^s+chunk;inverse-DIT-l=1..N/2-k=N-(N>>s)+chunk;inverse-extra-Ninv;canonical-stage-output;positive-weights-FL1w-FR1(p-w)-IL11-IRw(p-w)-NormNinv0;u66+2^64;d25+2^24;base16;8digits/endcarry0;stage-major45B/8192;headers80/112/144;repPower1/Native2/Aux3;PP32/stage;all-fixed-gathers;zero-main");
    h.finalize().into()
}
