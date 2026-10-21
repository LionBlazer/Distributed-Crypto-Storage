//! Complete actual row/port/constant inventory. Never supplied by a prover.
use super::super::geometry::N;
use super::*;
use bfv_hiding_stark::Val;
use p3_field::PrimeCharacteristicRing;
pub(super) const COEFFICIENTS: usize = 128;
pub(super) const FLAGS: usize = 256;
pub(super) const ARITH: usize = 0;
pub(super) const RANGE: usize = 1;
pub(super) const HASH: usize = 2;
pub(super) const FIRST: usize = 3;
pub(super) const LAST: usize = 4;
pub(super) const CONTEXT: usize = 5;
pub(super) const SALT: usize = 6;
pub(super) const PAYLOAD: usize = 7;
pub(super) const SOURCE: usize = 8;
pub(super) const MASK: usize = 9;
pub(super) const CS: usize = 10;
pub(super) const FANOUT: usize = 11;
pub(super) const POINTWISE: usize = 12;
pub(super) const EMIT: usize = 13;
pub(super) const RESET: usize = 14;
pub(super) const PADDING: usize = 15;

pub(super) fn node(tag: usize, index: usize) -> Result<u64> {
    if tag >= 68 || index >= N || (tag == 67 && index >= 512) {
        return Err(Error::Shape);
    }
    Ok(1 + tag as u64 * 65536 + index as u64)
}
pub(super) fn row(d: &Descriptor, index: usize) -> Result<[Val; PP_WIDTH]> {
    if index >= HEIGHT {
        return Err(Error::Shape);
    }
    let mut out = [Val::ZERO; PP_WIDTH];
    if index < RANGE_FIRST {
        out[FLAGS + ARITH] = Val::ONE;
        let gates = d.graph.row(index)?.gates;
        let point = (768..1280).contains(&index);
        out[FLAGS + POINTWISE] = Val::from_bool(point);
        out[FLAGS + FANOUT] = Val::from_bool((704..768).contains(&index));
        for (slot, gate) in gates.iter().enumerate() {
            for (p, n) in gate.inputs.iter().chain(&gate.outputs).enumerate() {
                if let Some(n) = n {
                    out[slot * 4 + p] = Val::from_u64(n.id())
                }
            }
            for (at, value) in gate.linear.iter().flatten().enumerate() {
                out[COEFFICIENTS + slot * 4 + at] = Val::from_u64(*value)
            }
            let expected = if (704..768).contains(&index) {
                [4, 4]
            } else if point {
                [1, 0]
            } else {
                [1, 1]
            };
            if gate.output_uses != expected {
                return Err(Error::Shape);
            }
        }
    } else if index < SOURCE_FIRST {
        let r = index - RANGE_FIRST;
        out[FLAGS + RANGE] = Val::ONE;
        out[FLAGS + RESET] = Val::from_bool(r.is_multiple_of(4));
        out[FLAGS + EMIT] = Val::from_bool(r % 4 == 3);
        out[COEFFICIENTS + 8] = Val::from_u64(1u64 << (12 * (r % 4)));
        for c in 0..2 {
            let at = 2 * r + c;
            let base = 17 * c;
            out[base] = Val::from_u64(node(0, at)?);
            out[base + 7] = Val::from_u64(node(65, at)?);
            out[base + 8] = Val::from_u64(node(66, at)?);
            for job in 0..4 {
                out[base + 9 + job] = Val::from_u64(node(28 + 12 * job, at)?);
                out[COEFFICIENTS + 4 * c + job] = Val::from_u64(d.c0[job][at]);
            }
        }
        if r % 4 == 3 {
            out[34] = Val::from_u64(node(67, r / 4)?)
        }
    } else if index < PADDING_FIRST {
        let (role, start, length, tag, flag) = if index < MASK_FIRST {
            (0, SOURCE_FIRST, 514, 65, SOURCE)
        } else if index < CS_FIRST {
            (1, MASK_FIRST, 514, 66, MASK)
        } else {
            (2, CS_FIRST, 66, 67, CS)
        };
        let r = index - start;
        for f in [HASH, flag] {
            out[FLAGS + f] = Val::ONE
        }
        out[FLAGS + FIRST] = Val::from_bool(r == 0);
        out[FLAGS + LAST] = Val::from_bool(r + 1 == length);
        out[FLAGS + CONTEXT] = Val::from_bool(r == 0);
        out[FLAGS + SALT] = Val::from_bool(r == 1);
        out[FLAGS + PAYLOAD] = Val::from_bool(r >= 2);
        out[COEFFICIENTS..COEFFICIENTS + 8].copy_from_slice(&d.contexts[role]);
        out[COEFFICIENTS + 8..COEFFICIENTS + 12].copy_from_slice(&d.roots[role]);
        if r >= 2 {
            for (i, value) in out.iter_mut().take(8).enumerate() {
                *value = Val::from_u64(node(tag, 8 * (r - 2) + i)?);
            }
        }
    } else {
        out[FLAGS + PADDING] = Val::ONE
    }
    Ok(out)
}

/// Signed exact port multiplicity, shared by descriptor inventory and AIR expression.
pub(super) fn count(p: usize, f: &[i32; 16]) -> i32 {
    let mut n = 0;
    if f[ARITH] != 0 {
        n = match p % 4 {
            0 => -1,
            1 => -1 + f[POINTWISE],
            2 => 1 + 3 * f[FANOUT],
            3 => 1 - f[POINTWISE] + 3 * f[FANOUT],
            _ => 0,
        };
    }
    if f[RANGE] != 0 {
        if p < 34 {
            n += match p % 17 {
                0 | 7 | 8 => 1,
                9..=12 => -1,
                _ => 0,
            };
        }
        if p == 34 {
            n += f[EMIT];
        }
    }
    if p < 8 {
        n -= f[PAYLOAD];
    }
    n
}

pub(super) fn inventory(d: &Descriptor) -> Result<()> {
    use p3_field::PrimeField64;
    let mut balance = vec![0i32; 68 * N];
    let mut producers = vec![0u8; 68 * N];
    for r in 0..HEIGHT {
        let row = row(d, r)?;
        let flags = core::array::from_fn(|i| row[FLAGS + i].as_canonical_u64() as i32);
        for (p, value) in row.iter().take(PORTS).enumerate() {
            let n = count(p, &flags);
            if n.abs() > 4 {
                return Err(Error::Shape);
            }
            if n == 0 {
                continue;
            }
            let id = value.as_canonical_u64();
            if id == 0 {
                return Err(Error::Shape);
            }
            let tag = ((id - 1) / 65536) as usize;
            let at = ((id - 1) % 65536) as usize;
            if node(tag, at)? != id {
                return Err(Error::Shape);
            }
            let cell = tag * N + at;
            balance[cell] = balance[cell].checked_add(n).ok_or(Error::Resource)?;
            if n > 0 {
                producers[cell] = producers[cell].checked_add(1).ok_or(Error::Shape)?;
            }
        }
    }
    if balance.iter().any(|&n| n != 0) {
        return Err(Error::Shape);
    }
    for tag in 0..68 {
        for at in 0..N {
            let want = u8::from(tag < 67 || at < 512);
            if producers[tag * N + at] != want {
                return Err(Error::Shape);
            }
        }
    }
    Ok(())
}
