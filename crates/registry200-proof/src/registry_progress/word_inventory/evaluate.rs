//! Closed, memoized owner-witness evaluation. No proof or acceptance result.
use super::{
    expr::{Node, Op, Pool},
    owner::PrimaryInputs,
    recipes::{Origins, Recipe},
};
use crate::Val;
use bfv_hiding_stark::poseidon;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Shape,
    Origin,
    Cycle,
    Resource,
    Arithmetic,
    Binding,
    Base,
    Lookup,
}
pub(super) type Result<T> = core::result::Result<T, Error>;
pub(super) const MAX_NODES: usize = 10_000;
pub(super) const MAX_HASHES: usize = 209;
/// Private SSA and permutation scratch are best-effort filled on drop.
/// This does not guarantee erasure of compiler, stack or allocator copies.
pub(super) struct Values {
    pub values: Vec<Val>,
    pub hashes: Vec<[Val; 248]>,
}
impl Drop for Values {
    fn drop(&mut self) {
        self.values.fill(Val::ZERO);
        self.hashes.iter_mut().for_each(|v| v.fill(Val::ZERO));
    }
}
pub(super) struct Evaluator<'a> {
    pool: &'a Pool,
    origins: &'a Origins,
    input: &'a PrimaryInputs,
    out: Values,
    state: Vec<u8>,
    recipe_state: Vec<u8>,
    hash_state: Vec<u8>,
    depth: usize,
}
impl<'a> Evaluator<'a> {
    pub fn new(pool: &'a Pool, origins: &'a Origins, input: &'a PrimaryInputs) -> Result<Self> {
        origins.require_complete(pool).map_err(|_| Error::Origin)?;
        if pool.nodes.len() > MAX_NODES
            || pool.hashes.len() != MAX_HASHES
            || origins.recipes.len() > MAX_NODES
        {
            return Err(Error::Resource);
        }
        Ok(Self {
            pool,
            origins,
            input,
            out: Values {
                values: vec![Val::ZERO; pool.nodes.len()],
                hashes: vec![[Val::ZERO; 248]; pool.hashes.len()],
            },
            state: vec![0; pool.nodes.len()],
            recipe_state: vec![0; origins.recipes.len()],
            hash_state: vec![0; pool.hashes.len()],
            depth: 0,
        })
    }
    pub fn finish(mut self) -> Result<Values> {
        for id in 0..self.pool.nodes.len() {
            let _ = self.value(id)?;
        }
        for (&id, &bits) in &self.pool.ranges {
            if self.out.values[id].as_canonical_u64() >= (1u64 << bits) {
                return Err(Error::Arithmetic);
            }
        }
        if self
            .pool
            .assertions
            .iter()
            .any(|&id| self.out.values[id] != Val::ZERO)
        {
            return Err(Error::Binding);
        }
        Ok(self.out)
    }
    fn value(&mut self, id: usize) -> Result<Val> {
        let state = *self.state.get(id).ok_or(Error::Shape)?;
        if state == 2 {
            return Ok(self.out.values[id]);
        }
        if state == 1 {
            return Err(Error::Cycle);
        }
        // A closed bound on stack depth, in addition to the full node/shape bound.
        if self.depth >= 1024 {
            return Err(Error::Resource);
        }
        self.depth += 1;
        self.state[id] = 1;
        let result = self.evaluate(id);
        self.depth -= 1;
        if let Ok(v) = result {
            self.out.values[id] = v;
            self.state[id] = 2;
        }
        result
    }
    fn evaluate(&mut self, id: usize) -> Result<Val> {
        Ok(match self.pool.nodes[id].clone() {
            Node::Constant(v) => v,
            Node::Input(..) => {
                if let Some(p) = self.origins.primary.get(&id) {
                    self.input.value(*p)?
                } else {
                    let r = *self.origins.targets.get(&id).ok_or(Error::Origin)?;
                    self.recipe(r)?;
                    self.out.values[id]
                }
            }
            Node::Arith(op, a, b) => {
                let x = self.value(a)?;
                let y = self.value(b)?;
                match op {
                    Op::Add => x + y,
                    Op::Sub => x - y,
                    Op::Mul => x * y,
                    Op::Neg => -x,
                }
            }
            Node::Hash(h, w) => {
                self.hash(h)?;
                self.out.values[self.pool.hashes[h].output[w]]
            }
            Node::Policy(q, w) => {
                let p = self.pool.policies[q].clone();
                let a = self.small(p.a, 4)?;
                let b = self.small(p.b, 4)?;
                Val::from_u64(match w {
                    0 => a.max(b),
                    1 => u64::from(a <= b),
                    2 => u64::from(crate::lifecycle::conflicts(a as u8, b as u8)),
                    _ => return Err(Error::Shape),
                })
            }
            Node::PolicyFrequency(table) => {
                let mut n = 0;
                for p in self.pool.policies.clone() {
                    let a = self.small(p.a, 4)?;
                    let b = self.small(p.b, 4)?;
                    n += usize::from(a * 5 + b == table as u64);
                }
                Val::from_usize(n)
            }
            Node::MaskBit(byte, bit) => Val::from_u8((self.input.mask[byte] >> bit) & 1),
            Node::MaskByte(byte) => Val::from_u8(self.input.mask[byte]),
            Node::MaskRead(read) => {
                let age = self.small(self.pool.reads[read].age, 255)? as usize;
                Val::from_bool(
                    self.pool.predicate && self.input.mask[age / 8] & (1 << (age % 8)) != 0,
                )
            }
            Node::MaskFrequency(byte, bit) => {
                let mut n = 0;
                if self.pool.predicate {
                    for r in self.pool.reads.clone() {
                        n += usize::from(self.small(r.age, 255)? == (byte * 8 + bit) as u64);
                    }
                }
                Val::from_usize(n)
            }
        })
    }
    fn hash(&mut self, h: usize) -> Result<()> {
        if self.hash_state[h] == 2 {
            return Ok(());
        }
        if self.hash_state[h] == 1 {
            return Err(Error::Cycle);
        }
        self.hash_state[h] = 1;
        let hash = self.pool.hashes[h].clone();
        let mut input = [Val::ZERO; 12];
        for (i, id) in hash.input.into_iter().enumerate() {
            input[i] = self.value(id)?;
        }
        let output = poseidon::write(&mut self.out.hashes[h], input);
        for (id, v) in hash.output.into_iter().zip(output) {
            self.out.values[id] = v;
            self.state[id] = 2;
        }
        self.hash_state[h] = 2;
        Ok(())
    }
    fn small(&mut self, id: usize, max: u64) -> Result<u64> {
        let x = self.value(id)?.as_canonical_u64();
        if x > max {
            return Err(Error::Arithmetic);
        }
        Ok(x)
    }
    fn limb64(&mut self, ids: [usize; 2]) -> Result<u64> {
        Ok(self.small(ids[0], u32::MAX as u64)? | (self.small(ids[1], u32::MAX as u64)? << 32))
    }
    fn set(&mut self, id: usize, v: Val) -> Result<()> {
        if self.state[id] == 2 && self.out.values[id] != v {
            return Err(Error::Origin);
        }
        self.out.values[id] = v;
        self.state[id] = 2;
        Ok(())
    }
    fn recipe(&mut self, index: usize) -> Result<()> {
        if self.recipe_state[index] == 2 {
            return Ok(());
        }
        if self.recipe_state[index] == 1 {
            return Err(Error::Cycle);
        }
        self.recipe_state[index] = 1;
        let r = self.origins.recipes[index].clone();
        match r {
            Recipe::Nonzero { out, sum, gate } => {
                let g = self.small(gate, 1)?;
                let x = self.value(sum)?;
                let inv = if g == 0 {
                    Val::ZERO
                } else {
                    if x == Val::ZERO {
                        return Err(Error::Arithmetic);
                    }
                    x.inverse()
                };
                self.set(out, inv)?;
            }
            Recipe::Equality { out, left, right } => {
                let d = self.value(left)? - self.value(right)?;
                self.set(out[0], Val::from_bool(d == Val::ZERO))?;
                self.set(
                    out[1],
                    if d == Val::ZERO {
                        Val::ZERO
                    } else {
                        d.inverse()
                    },
                )?;
            }
            Recipe::Compare {
                out,
                left,
                right,
                strict,
                gate,
            } => {
                let g = self.small(gate, 1)?;
                let mut z = [0u64; 4];
                if g == 1 {
                    let x = self.limb64(left)?;
                    let y = self.limb64(right)?;
                    let low = (y as u32 as i64) - (x as u32 as i64) - i64::from(strict);
                    z[2] = u64::from(low < 0);
                    z[0] = (low + (z[2] as i64) * (1i64 << 32)) as u64;
                    let high = (y >> 32) as i64 - (x >> 32) as i64 - z[2] as i64;
                    if high < 0 {
                        return Err(Error::Arithmetic);
                    }
                    z[1] = high as u64;
                }
                for (id, v) in out.into_iter().zip(z) {
                    self.set(id, Val::from_u64(v))?;
                }
            }
            Recipe::Increment { out, old, gate } => {
                let mut z = [0u64; 3];
                if self.small(gate, 1)? == 1 {
                    let x = self.limb64(old)?;
                    let y = x.checked_add(1).ok_or(Error::Arithmetic)?;
                    z = [y as u32 as u64, y >> 32, u64::from(x as u32 == u32::MAX)];
                }
                for (id, v) in out.into_iter().zip(z) {
                    self.set(id, Val::from_u64(v))?;
                }
            }
            Recipe::Small { out, left, right } => {
                let x = self.small(left, 4)?;
                let y = self.small(right, 4)?;
                let n = x + 8 - y;
                self.set(out[0], Val::from_u64(n % 8))?;
                self.set(out[1], Val::from_u64(n / 8))?;
            }
            Recipe::Principal { out, present, code } => {
                let p = self.small(present, 1)?;
                let c = self.small(code, 2)?;
                if (p == 0 && c != 0) || (p == 1 && c == 0) {
                    return Err(Error::Arithmetic);
                }
                self.set(out[0], Val::from_bool(p == 1 && c == 1))?;
                self.set(out[1], Val::from_bool(p == 1 && c == 2))?;
            }
        }
        self.recipe_state[index] = 2;
        Ok(())
    }
}
