//! Consumed owner-private mathematical inputs. No key/Source/SQL grant or secret getter.
use super::program::{ACCUMULATOR, BITS, CHECKPOINT, HEIGHT, WIDTH};
use super::{
    Error, Expected, Result, Val,
    geometry::{DELTA, N, Q, T},
    graph,
    relation::{CapturedExpected, ExpectedRef},
};
use bfv_hiding_stark::poseidon;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::Zeroizing;
const SMALL: i64 = 20;
const MAX_K: i128 = 524287;

/// A private opening of one complete already-scaled W4096 commitment. No raw getters.
pub struct ScaledOpening {
    context: [Val; 8],
    root: [Val; 4],
    words: Zeroizing<Vec<u64>>,
    salt: Zeroizing<[u64; 4]>,
}
impl ScaledOpening {
    pub fn checked(
        context: [Val; 8],
        root: [Val; 4],
        words: Zeroizing<Vec<u64>>,
        salt: Zeroizing<[u64; 4]>,
    ) -> Result<Self> {
        if words.len() != N || words.iter().any(|&v| v >= T) {
            return Err(Error::Shape);
        }
        if hash_fields(context, &salt, &words)? != root {
            return Err(Error::Binding);
        }
        Ok(Self {
            context,
            root,
            words,
            salt,
        })
    }
}
/// ONE same bounded secret and its exact Cs528 salt; the serialized SDK key is consumed.
pub struct SecretOpening {
    context: [Val; 8],
    root: [Val; 4],
    secret: Zeroizing<Vec<i64>>,
    salt: Zeroizing<[u64; 4]>,
}
impl SecretOpening {
    pub fn checked(
        context: [Val; 8],
        root: [Val; 4],
        sdk_key: Zeroizing<Vec<u8>>,
        salt: Zeroizing<[u64; 4]>,
    ) -> Result<Self> {
        let secret = decode_sdk_secret(sdk_key)?;
        let words = pack_secret(&secret)?;
        if hash_fields(context, &salt, &words)? != root {
            return Err(Error::Binding);
        }
        Ok(Self {
            context,
            root,
            secret,
            salt,
        })
    }
}
fn decode_sdk_secret(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<i64>>> {
    if bytes.len() != N + 3 || bytes[..3] != [0x0a, 0x80, 0x20] {
        return Err(Error::Shape);
    }
    let mut s = Zeroizing::new(Vec::with_capacity(N));
    for &b in &bytes[3..] {
        if b > 40 {
            return Err(Error::Arithmetic);
        }
        let v = i64::from(b >> 1) ^ -i64::from(b & 1);
        if !(-SMALL..=SMALL).contains(&v) {
            return Err(Error::Arithmetic);
        }
        s.push(v);
    }
    Ok(s)
}
pub(super) fn pack_secret(s: &[i64]) -> Result<Zeroizing<Vec<u64>>> {
    if s.len() != N || s.iter().any(|v| !(-SMALL..=SMALL).contains(v)) {
        return Err(Error::Arithmetic);
    }
    Ok(Zeroizing::new(
        s.as_chunks::<8>()
            .0
            .iter()
            .map(|row| {
                row.iter()
                    .enumerate()
                    .fold(0u64, |word, (i, &v)| word | (((v + 20) as u64) << (6 * i)))
            })
            .collect(),
    ))
}
struct PrivateFields<const L: usize>([Val; L]);
impl<const L: usize> Drop for PrivateFields<L> {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO);
    }
}
/// Same overwrite-rate8/capacity4 sponge used by the full AIR. Input vectors stay guarded.
pub(super) fn hash_fields(context: [Val; 8], salt: &[u64; 4], words: &[u64]) -> Result<[Val; 4]> {
    if !matches!(words.len(), N | 512)
        || salt.iter().any(|&v| v >= Val::ORDER_U64)
        || words.iter().any(|&v| v >= Val::ORDER_U64)
    {
        return Err(Error::Shape);
    }
    let mut state = PrivateFields([Val::ZERO; 12]);
    let mut scratch = PrivateFields([Val::ZERO; poseidon::WIDTH]);
    for row in 0..2 + words.len() / 8 {
        let mut input = PrivateFields([Val::ZERO; 12]);
        input.0[8..].copy_from_slice(&state.0[8..]);
        if row == 0 {
            input.0[..8].copy_from_slice(&context)
        } else if row == 1 {
            for (slot, &value) in input.0[..4].iter_mut().zip(salt) {
                *slot = Val::from_u64(value);
            }
        } else {
            for i in 0..8 {
                input.0[i] = Val::from_u64(words[8 * (row - 2) + i]);
            }
        }
        state.0 = poseidon::write(&mut scratch.0, input.0);
    }
    state.0[..4].try_into().map_err(|_| Error::Shape)
}

/// Opaque consumed witness for the original Pair relation; public API unchanged.
pub struct Prepared {
    pub(super) inner: Preparation,
}
impl Prepared {
    pub fn new(
        expected: &Expected,
        openings: [ScaledOpening; 2],
        key: SecretOpening,
    ) -> Result<Self> {
        Ok(Self {
            inner: Preparation::new(ExpectedRef::Pair(expected), Vec::from(openings), key)?,
        })
    }
    #[cfg(test)]
    pub(super) fn require_expected(&self, expected: &Expected) -> Result<()> {
        self.inner.require_expected(ExpectedRef::Pair(expected))
    }
    #[cfg(test)]
    pub(super) fn trace(self, expected: &Expected) -> Result<PrivateTrace> {
        self.inner.trace(ExpectedRef::Pair(expected))
    }
}
pub(super) struct Preparation {
    expected: CapturedExpected,
    openings: Vec<ScaledOpening>,
    key: SecretOpening,
}
impl Preparation {
    pub(super) fn new(
        expected: ExpectedRef<'_>,
        openings: Vec<ScaledOpening>,
        key: SecretOpening,
    ) -> Result<Self> {
        let kind = expected.kind();
        if openings.len() != kind.operands() {
            return Err(Error::Shape);
        }
        for (i, o) in openings.iter().enumerate() {
            if o.context != expected.context(i) || o.root != expected.root(i) {
                return Err(Error::Binding);
            }
        }
        if key.context != expected.context(kind.operands())
            || key.root != expected.root(kind.operands())
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            expected: expected.captured(),
            openings,
            key,
        })
    }
    pub(super) fn require_expected(&self, expected: ExpectedRef<'_>) -> Result<()> {
        self.expected.require_same(expected)
    }
    /// Called only by the closed backend AFTER actual assessment/resource gates.
    /// All auxiliary secret graph/product banks drop before native MAIN commitment.
    pub(super) fn trace(self, expected: ExpectedRef<'_>) -> Result<PrivateTrace> {
        self.require_expected(expected)?;
        let kind = expected.kind();
        let layout = kind.range();
        let plan = graph::Plan::new(expected.inputs()?)?;
        let graph = plan.build(&self.key.secret)?;
        let products: Vec<Zeroizing<Vec<i64>>> = (0..kind.products())
            .map(|j| plan.product(&graph, j / 2, j % 2))
            .collect::<Result<Vec<_>>>()?;
        let mut errors: Vec<Zeroizing<Vec<i64>>> = (0..kind.operands())
            .map(|_| Zeroizing::new(vec![0; N]))
            .collect();
        let mut quotients: Vec<Zeroizing<Vec<i64>>> = (0..kind.products())
            .map(|_| Zeroizing::new(vec![0; N]))
            .collect();
        for j in 0..kind.products() {
            let operand = j / 2;
            let b = j % 2;
            let ct = expected.input(2 * operand);
            for at in 0..N {
                let phase = i128::from(ct[b][at]) + i128::from(products[j][at])
                    - i128::from(DELTA[b]) * i128::from(self.openings[operand].words[at]);
                let residue = phase.rem_euclid(i128::from(Q[b]));
                let error = if residue > i128::from(Q[b] / 2) {
                    residue - i128::from(Q[b])
                } else {
                    residue
                };
                if !(-20..=20).contains(&error) {
                    return Err(Error::Arithmetic);
                }
                if b == 0 {
                    errors[operand][at] = error as i64;
                } else if errors[operand][at] != error as i64 {
                    return Err(Error::Arithmetic);
                }
                let exact = phase - error;
                if exact % i128::from(Q[b]) != 0 {
                    return Err(Error::Arithmetic);
                }
                let k = exact / i128::from(Q[b]);
                if !(-MAX_K..=MAX_K).contains(&k) {
                    return Err(Error::Arithmetic);
                }
                quotients[j][at] = k as i64;
            }
        }
        let mut main = PrivateTrace(RowMajorMatrix::new(Val::zero_vec(HEIGHT * WIDTH), WIDTH));
        for r in 0..kind.graph_rows() {
            let row = &mut main.0.values[r * WIDTH..(r + 1) * WIDTH];
            for (slot, values) in graph.values[32 * r..32 * r + 32].iter().enumerate() {
                for (i, &v) in values.iter().enumerate() {
                    row[4 * slot + i] = Val::from_u64(v);
                }
            }
        }
        drop(graph);
        drop(plan);
        let mut cs_words = Zeroizing::new(Vec::with_capacity(512));
        let mut accumulator = 0u64;
        for r in 0..2048 {
            let row = &mut main.0.values
                [(kind.range_first() + r) * WIDTH..(kind.range_first() + r + 1) * WIDTH];
            row[ACCUMULATOR] = Val::from_u64(accumulator);
            for k in 0..2 {
                let at = 2 * r + k;
                let base = layout.stride * k;
                let mut bit = BITS + layout.bits * k;
                for bank in 0..1 + kind.operands() {
                    let value = if bank == 0 {
                        self.key.secret[at]
                    } else {
                        errors[bank - 1][at]
                    };
                    row[base + bank] = signed(value);
                    let biased = (value + 20) as u64;
                    write_bits(&mut row[bit..bit + 6], biased);
                    write_bits(&mut row[bit + 6..bit + 12], 40 - biased);
                    bit += 12;
                }
                for j in 0..kind.products() {
                    let value = quotients[j][at];
                    row[base + layout.k + j] = signed(value);
                    let biased = (value + 524288) as u64;
                    write_bits(&mut row[bit..bit + 20], biased);
                    bit += 20;
                    row[base + layout.inverse + j] = Val::from_u64(biased)
                        .try_inverse()
                        .ok_or(Error::Arithmetic)?;
                }
                for operand in 0..kind.operands() {
                    let w = self.openings[operand].words[at];
                    row[base + layout.w + operand] = Val::from_u64(w);
                    write_bits(&mut row[bit..bit + 17], w);
                    write_bits(&mut row[bit + 17..bit + 34], T - 1 - w);
                    bit += 34;
                }
                for j in 0..kind.products() {
                    row[base + layout.product + j] = signed(products[j][at]);
                }
                if bit != BITS + layout.bits * (k + 1) {
                    return Err(Error::Shape);
                }
            }
            let pair = (self.key.secret[2 * r] + 20) as u64
                + 64 * ((self.key.secret[2 * r + 1] + 20) as u64);
            let word = accumulator + (pair << (12 * (r % 4)));
            if r % 4 == 3 {
                row[2 * layout.stride] = Val::from_u64(word);
                cs_words.push(word);
                accumulator = 0;
            } else {
                accumulator = word;
            }
        }
        drop(products);
        drop(errors);
        drop(quotients);
        for role in 0..=kind.operands() {
            let (start, context, root, salt, words) = if role < kind.operands() {
                let opening = &self.openings[role];
                (
                    kind.cw_first(role),
                    opening.context,
                    opening.root,
                    &*opening.salt,
                    opening.words.as_slice(),
                )
            } else {
                (
                    kind.cs_first(),
                    self.key.context,
                    self.key.root,
                    &*self.key.salt,
                    cs_words.as_slice(),
                )
            };
            write_hash(&mut main.0, start, context, salt, words, root)?;
        }
        // All relation-specific padding rows and inactive columns stay zero.
        Ok(main)
    }
}
fn write_bits(out: &mut [Val], value: u64) {
    for (i, v) in out.iter_mut().enumerate() {
        *v = Val::from_u64((value >> i) & 1);
    }
}
fn signed(v: i64) -> Val {
    if v < 0 {
        -Val::from_u64(v.unsigned_abs())
    } else {
        Val::from_u64(v as u64)
    }
}
fn write_hash(
    main: &mut RowMajorMatrix<Val>,
    start: usize,
    context: [Val; 8],
    salt: &[u64; 4],
    words: &[u64],
    root: [Val; 4],
) -> Result<()> {
    let mut checkpoint = PrivateFields([Val::ZERO; 12]);
    for r in 0..2 + words.len() / 8 {
        let row = &mut main.values[(start + r) * WIDTH..(start + r + 1) * WIDTH];
        row[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(&checkpoint.0);
        let mut input = PrivateFields([Val::ZERO; 12]);
        input.0[8..].copy_from_slice(&checkpoint.0[8..]);
        if r == 0 {
            input.0[..8].copy_from_slice(&context)
        } else if r == 1 {
            for i in 0..4 {
                row[i] = Val::from_u64(salt[i]);
                input.0[i] = row[i];
            }
        } else {
            for i in 0..8 {
                row[i] = Val::from_u64(words[8 * (r - 2) + i]);
                input.0[i] = row[i];
            }
        }
        checkpoint.0 = poseidon::write(&mut row[BITS..BITS + poseidon::WIDTH], input.0);
    }
    if checkpoint.0[..4] != root {
        return Err(Error::Binding);
    }
    Ok(())
}
pub(super) struct PrivateTrace(pub(super) RowMajorMatrix<Val>);
impl Drop for PrivateTrace {
    fn drop(&mut self) {
        self.0.values.fill(Val::ZERO);
    }
}
