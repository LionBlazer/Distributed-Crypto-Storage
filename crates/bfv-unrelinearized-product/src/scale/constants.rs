//! Immutable constants from the pinned fhe-math0.1.1 RnsScaler constructor.
use super::{CERTIFICATE_BYTES, HEADER_BYTES, K_OFFSET, ROW_BYTES, Role, W_OFFSET};
use crate::geometry::{N, Q, T};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SignedMagnitude {
    pub negative: bool,
    pub magnitude: u128,
}
pub(super) struct CoefficientConstants {
    pub(super) shift: usize,
    pub(super) t: Vec<u128>,
    pub(super) theta: Vec<SignedMagnitude>,
    pub(super) gamma: [u64; 2],
    pub(super) omega: [[u64; 4]; 2],
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
    to: &[u64; 2],
    round_up: bool,
) -> ([u64; 2], SignedMagnitude) {
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
    let q: BigUint = Q.iter().map(|&q| BigUint::from(q)).product();
    let (a, b) = match role {
        Role::Extend2To4 => (BigUint::one(), BigUint::one()),
        Role::Scale4To2 => (BigUint::from(T), q),
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
    let mut omega = [[0; 4]; 2];
    let mut theta = Vec::with_capacity(from.len());
    for (i, g) in garner.iter().enumerate() {
        let (values, ti) = projection(g, &a, &b, to, true);
        for j in 0..2 {
            omega[j][i] = values[j];
        }
        theta.push(ti);
    }
    assert_eq!(
        shift, 127,
        "closed profiles use the complete127-bit Garner interval"
    );
    if role == Role::Extend2To4 {
        assert!(theta.iter().all(|x| x.magnitude == 0));
    } else {
        assert!(
            theta[2..].iter().all(|x| x.magnitude == 0),
            "P Garner terms are exact multiples ofQ"
        );
    }
    CoefficientConstants {
        shift,
        t,
        theta,
        gamma,
        omega,
    }
}
pub(super) fn constants(role: Role) -> &'static CoefficientConstants {
    static EXT: OnceLock<CoefficientConstants> = OnceLock::new();
    static DOWN: OnceLock<CoefficientConstants> = OnceLock::new();
    match role {
        Role::Extend2To4 => EXT.get_or_init(|| build(role)),
        Role::Scale4To2 => DOWN.get_or_init(|| build(role)),
    }
}
/// Entire fixed algorithm, ordered bases, exact constants and all codec/range conventions.
pub(super) fn profile_digest(role: Role) -> [u8; 32] {
    let c = constants(role);
    let mut h = Sha256::new();
    h.update(b"DCS/EXPERIMENT/UNREL-SCALER-CERTIFICATE/v1/fhe-math0.1.1/N4096-Q2-P2/PB-natural");
    h.update([role as u8]);
    h.update((N as u64).to_le_bytes());
    for bytes in [HEADER_BYTES, ROW_BYTES, CERTIFICATE_BYTES] {
        h.update((bytes as u64).to_le_bytes());
    }
    h.update(W_OFFSET.to_le_bytes());
    h.update(K_OFFSET.to_le_bytes());
    h.update([64, 46, 66, 127]);
    h.update(T.to_le_bytes());
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
    h.update(b"v-round-half-up-shift127;W-floor(E+2^126)/2^127;GammaTheta0;full-canonical4096;extend-copyQ2;integer-not-field;v64;Wbias2^45-range46;kBias2^64-range66;row32-LE-v8-W6-k9-k9;reserved0;exact-EOF;no-carries-or-remainders-on-wire");
    h.finalize().into()
}
