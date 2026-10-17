//! Immutable constants from the pinned fhe-math0.1.1 RnsScaler constructor.
use crate::{DEGREE, MODULI, PLAINTEXT, Role};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedMagnitude {
    pub negative: bool,
    pub magnitude: u128,
}
pub struct CoefficientConstants {
    pub(crate) shift: usize,
    pub(crate) t: Vec<u128>,
    pub(crate) theta: Vec<SignedMagnitude>,
    pub(crate) gamma: [u64; 5],
    pub(crate) omega: [[u64; 10]; 5],
}
impl CoefficientConstants {
    pub fn garner_shift(&self) -> usize {
        self.shift
    }
    pub fn garner_weights(&self) -> &[u128] {
        &self.t
    }
    pub fn theta(&self) -> &[SignedMagnitude] {
        &self.theta
    }
    pub fn gamma(&self) -> &[u64; 5] {
        &self.gamma
    }
    pub fn omega(&self) -> &[[u64; 10]; 5] {
        &self.omega
    }
}
fn pow_mod(mut x: u64, mut n: u64, p: u64) -> u64 {
    let mut out = 1;
    while n != 0 {
        if n & 1 != 0 {
            out = ((out as u128 * x as u128) % p as u128) as u64;
        }
        x = ((x as u128 * x as u128) % p as u128) as u64;
        n >>= 1;
    }
    out
}
fn projection(
    input: &BigUint,
    a: &BigUint,
    b: &BigUint,
    to: &[u64; 5],
    round_up: bool,
) -> ([u64; 5], SignedMagnitude) {
    let product = input * a;
    let gamma = (&product + (b >> 1usize)) / b;
    let projected = core::array::from_fn(|i| (&gamma % to[i]).to_u64().unwrap());
    let mut remainder = &product % b;
    let half = b >> 1usize;
    let negative = if b > &BigUint::one() {
        if b & BigUint::one() == BigUint::one() {
            remainder > half
        } else {
            remainder >= half
        }
    } else {
        false
    };
    if negative {
        remainder = b - remainder;
    }
    let scaled = remainder << 127usize;
    // Exact constructor-directed rounding: ceil for Omega positive/Gamma negative.
    let ceil = round_up != negative;
    let theta = if ceil {
        (scaled + b - BigUint::one()) / b
    } else {
        scaled / b
    };
    (
        projected,
        SignedMagnitude {
            negative,
            magnitude: theta.to_u128().unwrap(),
        },
    )
}
fn build(role: Role) -> CoefficientConstants {
    let from = role.input_moduli();
    let to = role.computed_moduli();
    let m: BigUint = from.iter().map(|&q| BigUint::from(q)).product();
    let q: BigUint = MODULI.iter().map(|&q| BigUint::from(q)).product();
    let (a, b) = match role {
        Role::Extend5To10 => (BigUint::one(), BigUint::one()),
        Role::Scale10To5 => (BigUint::from(PLAINTEXT), q),
    };
    let garner: Vec<_> = from
        .iter()
        .map(|&p| {
            let star = &m / p;
            let residue = (&star % p).to_u64().unwrap();
            star * pow_mod(residue, p - 2, p)
        })
        .collect();
    let shift = from
        .iter()
        .map(|&q| {
            let x = q as u128 * from.len() as u128;
            191 - ((x - 1).ilog2() + 1) as usize
        })
        .min()
        .unwrap()
        .min(127);
    let t = garner
        .iter()
        .map(|g| ((g << shift) + (&m >> 1usize)) / &m)
        .map(|x| x.to_u128().unwrap())
        .collect();
    let (gamma, tg) = projection(&m, &a, &b, to, false);
    assert_eq!(tg.magnitude, 0, "fixed roles have exact integer Gamma");
    let mut omega = [[0; 10]; 5];
    let mut theta = Vec::with_capacity(from.len());
    for (i, g) in garner.iter().enumerate() {
        let (values, ti) = projection(g, &a, &b, to, true);
        for j in 0..5 {
            omega[j][i] = values[j];
        }
        theta.push(ti);
    }
    CoefficientConstants {
        shift,
        t,
        theta,
        gamma,
        omega,
    }
}
pub fn constants(role: Role) -> &'static CoefficientConstants {
    static EXT: OnceLock<CoefficientConstants> = OnceLock::new();
    static DOWN: OnceLock<CoefficientConstants> = OnceLock::new();
    match role {
        Role::Extend5To10 => EXT.get_or_init(|| build(role)),
        Role::Scale10To5 => DOWN.get_or_init(|| build(role)),
    }
}
/// Entire fixed algorithm, ordered bases, exact constants and all codec/range conventions.
pub fn profile_digest(role: Role) -> [u8; 32] {
    let c = constants(role);
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-RNS-SCALE-CIRCUIT/v1/fhe-math0.1.1/PowerBasis-natural-single-poly");
    h.update([role as u8]);
    h.update((DEGREE as u64).to_le_bytes());
    h.update(PLAINTEXT.to_le_bytes());
    for &p in role.input_moduli().iter().chain(role.output_moduli()) {
        h.update(p.to_le_bytes());
    }
    h.update((c.shift as u64).to_le_bytes());
    for &t in &c.t {
        h.update(t.to_le_bytes());
    }
    for theta in &c.theta {
        h.update([u8::from(theta.negative)]);
        h.update(theta.magnitude.to_le_bytes());
    }
    for &g in &c.gamma {
        h.update(g.to_le_bytes());
    }
    for row in &c.omega {
        for &v in row {
            h.update(v.to_le_bytes());
        }
    }
    h.update(b"nearest-v/T;ceil-OmegaTheta;floor-GammaTheta0;W=floor((E+2^126)/2^127);base16;rv-h;re127;Wb46+2^45;U66+2^64;d25+2^24;12/11/8;56carry;zero-boundaries;315B/8192;headers80/112/144;full-extend-copy5");
    h.finalize().into()
}
