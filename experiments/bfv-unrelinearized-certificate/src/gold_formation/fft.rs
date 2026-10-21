//! Fixed4096 Goldilocks negacyclic FFT. Owner-private scratch is always guarded.
use crate::{Error, Result, geometry::N};
use zeroize::Zeroizing;

pub(super) const GOLD: u64 = 0xffff_ffff_0000_0001;
// Pinned Goldilocks primitive8192-th root; new() checks its exact order.
const PSI: u64 = 0x1544_ef23_35d1_7997;
fn add(a: u64, b: u64) -> u64 {
    ((u128::from(a) + u128::from(b)) % u128::from(GOLD)) as u64
}
fn sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { GOLD - (b - a) }
}
pub(super) fn mul(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(GOLD)) as u64
}
fn pow(mut value: u64, mut exponent: u64) -> u64 {
    let mut out = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            out = mul(out, value);
        }
        value = mul(value, value);
        exponent >>= 1;
    }
    out
}
pub(super) struct Plan {
    twist: Vec<u64>,
    untwist: Vec<u64>,
    root: u64,
    inverse_root: u64,
    inverse_n: u64,
}
impl Plan {
    pub(super) fn new() -> Result<Self> {
        if N != 4096 || pow(PSI, N as u64) != GOLD - 1 || pow(PSI, (2 * N) as u64) != 1 {
            return Err(Error::Arithmetic);
        }
        let inverse_psi = pow(PSI, GOLD - 2);
        let root = mul(PSI, PSI);
        let mut twist = vec![1; N];
        let mut untwist = vec![1; N];
        for at in 1..N {
            twist[at] = mul(twist[at - 1], PSI);
            untwist[at] = mul(untwist[at - 1], inverse_psi);
        }
        Ok(Self {
            twist,
            untwist,
            root,
            inverse_root: pow(root, GOLD - 2),
            inverse_n: pow(N as u64, GOLD - 2),
        })
    }
    fn cyclic(&self, values: &mut [u64], inverse: bool) {
        let mut j = 0;
        for i in 1..N {
            let mut bit = N >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if i < j {
                values.swap(i, j);
            }
        }
        for log in 1..=12 {
            let width = 1 << log;
            let stride = pow(
                if inverse {
                    self.inverse_root
                } else {
                    self.root
                },
                (N / width) as u64,
            );
            for start in (0..N).step_by(width) {
                let mut power = 1;
                for offset in 0..width / 2 {
                    let x = values[start + offset];
                    let y = mul(values[start + offset + width / 2], power);
                    values[start + offset] = add(x, y);
                    values[start + offset + width / 2] = sub(x, y);
                    power = mul(power, stride);
                }
            }
        }
        if inverse {
            for value in values {
                *value = mul(*value, self.inverse_n);
            }
        }
    }
    fn transform(&self, values: &mut [u64], inverse: bool) -> Result<()> {
        if values.len() != N {
            return Err(Error::Shape);
        }
        if values.iter().any(|&v| v >= GOLD) {
            return Err(Error::Arithmetic);
        }
        if !inverse {
            for (v, &twist) in values.iter_mut().zip(&self.twist) {
                *v = mul(*v, twist);
            }
        }
        self.cyclic(values, inverse);
        if inverse {
            for (v, &untwist) in values.iter_mut().zip(&self.untwist) {
                *v = mul(*v, untwist);
            }
        }
        Ok(())
    }
    pub(super) fn secret_frequency(&self, secret: &[i64]) -> Result<Zeroizing<Vec<u64>>> {
        if secret.len() != N || secret.iter().any(|v| !(-20..=20).contains(v)) {
            return Err(Error::Arithmetic);
        }
        let mut out = Zeroizing::new(
            secret
                .iter()
                .map(|&v| {
                    if v < 0 {
                        GOLD - v.unsigned_abs()
                    } else {
                        v as u64
                    }
                })
                .collect::<Vec<_>>(),
        );
        self.transform(&mut out, false)?;
        Ok(out)
    }
    pub(super) fn product(
        &self,
        public: &[u64],
        secret_frequency: &[u64],
        q: u64,
    ) -> Result<Zeroizing<Vec<i64>>> {
        if public.len() != N || secret_frequency.len() != N {
            return Err(Error::Shape);
        }
        if public.iter().any(|&v| v >= q) || secret_frequency.iter().any(|&v| v >= GOLD) {
            return Err(Error::Arithmetic);
        }
        if !crate::geometry::Q.contains(&q) {
            return Err(Error::Shape);
        }
        let mut work = Zeroizing::new(public.to_vec());
        self.transform(&mut work, false)?;
        for (value, &secret) in work.iter_mut().zip(secret_frequency) {
            *value = mul(*value, secret);
        }
        self.transform(&mut work, true)?;
        let maximum = 20_i128 * N as i128 * i128::from(q - 1);
        let mut out = Zeroizing::new(Vec::with_capacity(N));
        for &value in work.iter() {
            let signed = if value <= GOLD / 2 {
                i128::from(value)
            } else {
                -i128::from(GOLD - value)
            };
            if signed.abs() > maximum {
                return Err(Error::Arithmetic);
            }
            out.push(signed as i64);
        }
        Ok(out)
    }
}
