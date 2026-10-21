//! Closed owner-math instruction graph. Test-private; never a proof/verifier API.
use super::recipes::{Built, Group, Origins, Primary, Recipe};
use crate::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ops::{Add, Mul, Neg, Sub},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ty {
    Gold,
    Bool,
    U32,
    Bits(u8),
    Mode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Op {
    Add,
    Sub,
    Mul,
    Neg,
}
#[derive(Clone, Debug)]
pub(super) enum Node {
    Constant(Val),
    Input(String, Ty),
    Arith(Op, usize, usize),
    Hash(usize, usize),
    Policy(usize, usize),
    PolicyFrequency(usize),
    MaskBit(usize, usize),
    MaskFrequency(usize, usize),
    MaskByte(usize),
    MaskRead(usize),
}
#[derive(Clone, Debug)]
pub(super) struct Hash {
    pub label: String,
    pub input: [usize; 12],
    pub output: [usize; 12],
}
#[derive(Clone, Debug)]
pub(super) struct Policy {
    pub a: usize,
    pub b: usize,
    pub output: [usize; 3],
}
#[derive(Clone, Debug)]
pub(super) struct MaskByte {
    pub bits: [usize; 8],
    pub frequencies: [usize; 8],
    pub byte: usize,
}
#[derive(Clone, Debug)]
pub(super) struct MaskRead {
    pub age: usize,
    pub output: usize,
}
#[derive(Clone, Default)]
pub(super) struct Pool {
    pub nodes: Vec<Node>,
    pub assertions: Vec<usize>,
    pub ranges: BTreeMap<usize, u8>,
    pub hashes: Vec<Hash>,
    pub policies: Vec<Policy>,
    pub mask: Vec<MaskByte>,
    pub reads: Vec<MaskRead>,
    pub fields: BTreeMap<String, usize>,
    pub errors: Vec<String>,
    pub mode_inputs: Vec<usize>,
    constants: BTreeMap<u64, usize>,
    arithmetic: BTreeMap<(Op, usize, usize), usize>,
    inputs: BTreeMap<String, usize>,
    policy_cache: BTreeMap<(usize, usize), usize>,
    fresh: usize,
    pub policy_frequencies: Vec<usize>,
    pub predicate: bool,
}
pub(super) struct Builder {
    pub pool: RefCell<Pool>,
    origins: RefCell<Origins>,
}
#[derive(Clone, Copy)]
pub(super) struct E<'a> {
    pub id: usize,
    pub b: &'a Builder,
}
impl Builder {
    pub fn new(predicate: bool) -> Self {
        let b = Self {
            origins: RefCell::new(Origins::default()),
            pool: RefCell::new(Pool {
                predicate,
                ..Pool::default()
            }),
        };
        b.c(0);
        b
    }
    fn node(&self, n: Node) -> E<'_> {
        let mut p = self.pool.borrow_mut();
        if p.nodes.len() >= 1_000_000 {
            p.errors.push("node-fuse".into());
            return E { id: 0, b: self };
        }
        let id = p.nodes.len();
        p.nodes.push(n);
        E { id, b: self }
    }
    pub fn e(&self, id: usize) -> E<'_> {
        E { id, b: self }
    }
    pub fn val(&self, v: Val) -> E<'_> {
        let n = v.as_canonical_u64();
        if let Some(id) = self.pool.borrow().constants.get(&n).copied() {
            return self.e(id);
        }
        let e = self.node(Node::Constant(v));
        self.pool.borrow_mut().constants.insert(n, e.id);
        e
    }
    pub fn c(&self, v: u64) -> E<'_> {
        self.val(Val::from_u64(v))
    }
    pub fn constant(&self, id: usize) -> Option<Val> {
        match self.pool.borrow().nodes[id] {
            Node::Constant(v) => Some(v),
            _ => None,
        }
    }
    pub fn fresh(&self, label: &str, ty: Ty) -> E<'_> {
        let n = {
            let mut p = self.pool.borrow_mut();
            let n = p.fresh;
            p.fresh += 1;
            n
        };
        self.input(&format!("aux/{label}/{n}"), ty)
    }
    pub fn input(&self, label: &str, ty: Ty) -> E<'_> {
        let duplicate = { self.pool.borrow().inputs.get(label).copied() };
        if let Some(id) = duplicate {
            self.pool
                .borrow_mut()
                .errors
                .push(format!("duplicate-input:{label}"));
            return self.e(id);
        }
        let e = self.node(Node::Input(label.into(), ty));
        self.pool.borrow_mut().inputs.insert(label.into(), e.id);
        match ty {
            Ty::Bool => self.boolean(e),
            Ty::U32 => self.range(e, 32),
            Ty::Bits(n) => self.range(e, n),
            Ty::Mode => self.pool.borrow_mut().mode_inputs.push(e.id),
            Ty::Gold => {}
        }
        e
    }
    pub fn input_primary(&self, label: &str, ty: Ty, group: Group, index: usize) -> E<'_> {
        let e = self.input(label, ty);
        self.origins
            .borrow_mut()
            .primary(e.id, Primary { group, index });
        e
    }
    pub fn onehot_primary<const N: usize>(&self, label: &str, group: Group) -> [E<'_>; N] {
        let a = self.onehot::<N>(label);
        for (i, e) in a.iter().enumerate() {
            self.origins
                .borrow_mut()
                .primary(e.id, Primary { group, index: i });
        }
        a
    }
    pub fn recipe(&self, r: Recipe) {
        self.origins.borrow_mut().recipe(r);
    }
    pub fn field(&self, label: String, e: E<'_>) {
        let duplicate = self
            .pool
            .borrow_mut()
            .fields
            .insert(label.clone(), e.id)
            .is_some();
        if duplicate {
            self.pool
                .borrow_mut()
                .errors
                .push(format!("duplicate-field:{label}"));
        }
    }
    pub fn zero(&self, e: E<'_>) {
        self.pool.borrow_mut().assertions.push(e.id);
    }
    pub fn eq(&self, a: E<'_>, b: E<'_>) {
        self.zero(a - b);
    }
    pub fn boolean(&self, e: E<'_>) {
        self.zero(e * (e - 1));
    }
    pub fn range(&self, e: E<'_>, bits: u8) {
        if bits == 0 || bits > 32 {
            self.pool.borrow_mut().errors.push("bad-range-width".into());
            return;
        }
        let mut p = self.pool.borrow_mut();
        p.ranges
            .entry(e.id)
            .and_modify(|n| *n = (*n).min(bits))
            .or_insert(bits);
    }
    pub fn gate(&self, g: E<'_>, e: E<'_>) {
        self.zero(g * e);
    }
    pub fn select<'a>(&'a self, g: E<'a>, yes: E<'a>, no: E<'a>) -> E<'a> {
        no + g * (yes - no)
    }
    pub fn sum<'a>(&'a self, v: impl IntoIterator<Item = E<'a>>) -> E<'a> {
        v.into_iter().fold(self.c(0), |a, b| a + b)
    }
    pub fn arith(&self, op: Op, a: usize, b: usize) -> E<'_> {
        let ca = self.constant(a);
        let cb = self.constant(b);
        if let (Some(x), Some(y)) = (ca, cb) {
            return self.val(match op {
                Op::Add => x + y,
                Op::Sub => x - y,
                Op::Mul => x * y,
                Op::Neg => -x,
            });
        }
        if op == Op::Add && ca == Some(Val::ZERO) {
            return self.e(b);
        }
        if (op == Op::Add || op == Op::Sub) && cb == Some(Val::ZERO) {
            return self.e(a);
        }
        if op == Op::Mul && (ca == Some(Val::ZERO) || cb == Some(Val::ZERO)) {
            return self.c(0);
        }
        if op == Op::Mul && ca == Some(Val::ONE) {
            return self.e(b);
        }
        if op == Op::Mul && cb == Some(Val::ONE) {
            return self.e(a);
        }
        let key = (op, a, b);
        if let Some(id) = self.pool.borrow().arithmetic.get(&key).copied() {
            return self.e(id);
        }
        let e = self.node(Node::Arith(op, a, b));
        self.pool.borrow_mut().arithmetic.insert(key, e.id);
        e
    }
    pub fn onehot<const N: usize>(&self, label: &str) -> [E<'_>; N] {
        let a = core::array::from_fn(|i| self.input(&format!("{label}/{i}"), Ty::Bool));
        self.eq(self.sum(a), self.c(1));
        a
    }
    pub fn code<'a>(&'a self, a: &[E<'a>]) -> E<'a> {
        self.sum(a.iter().enumerate().map(|(i, v)| *v * (i as u64)))
    }
    pub fn nonzero(&self, a: &[E<'_>], gate: E<'_>) {
        let inv = self.fresh("nonzero-inverse", Ty::Gold);
        let sum = self.sum(a.iter().copied());
        self.recipe(Recipe::Nonzero {
            out: inv.id,
            sum: sum.id,
            gate: gate.id,
        });
        self.gate(gate, sum * inv - 1);
        self.zero((self.c(1) - gate) * inv);
    }
    pub fn equal_words<'a>(&'a self, a: &[E<'a>], d: &[E<'a>]) -> E<'a> {
        if a.len() != d.len() {
            self.pool.borrow_mut().errors.push("equality-width".into());
            return self.c(0);
        }
        let mut all = self.c(1);
        for (x, y) in a.iter().zip(d) {
            let z = self.fresh("eq-word", Ty::Bool);
            let inv = self.fresh("eq-inverse", Ty::Gold);
            let delta = *x - *y;
            self.recipe(Recipe::Equality {
                out: [z.id, inv.id],
                left: x.id,
                right: y.id,
            });
            self.zero(delta * z);
            self.eq(delta * inv, self.c(1) - z);
            self.zero(z * inv);
            all = all * z;
        }
        all
    }
    pub fn compare64(&self, x: [E<'_>; 2], y: [E<'_>; 2], strict: bool, g: E<'_>) {
        let d = [
            self.fresh("compare-d0", Ty::U32),
            self.fresh("compare-d1", Ty::U32),
        ];
        let k = [
            self.fresh("borrow0", Ty::Bool),
            self.fresh("borrow1", Ty::Bool),
        ];
        self.recipe(Recipe::Compare {
            out: [d[0].id, d[1].id, k[0].id, k[1].id],
            left: x.map(|e| e.id),
            right: y.map(|e| e.id),
            strict,
            gate: g.id,
        });
        self.gate(
            g,
            d[0] - y[0] + x[0] + u64::from(strict) - k[0] * (1u64 << 32),
        );
        self.gate(g, d[1] - y[1] + x[1] + k[0] - k[1] * (1u64 << 32));
        self.gate(g, k[1]);
        for z in [d[0], d[1], k[0], k[1]] {
            self.zero((self.c(1) - g) * z);
        }
    }
    pub fn increment<'a>(&'a self, x: [E<'a>; 2], g: E<'a>) -> [E<'a>; 2] {
        let y = [
            self.fresh("increment-low", Ty::U32),
            self.fresh("increment-high", Ty::U32),
        ];
        let carry = self.fresh("increment-carry", Ty::Bool);
        self.recipe(Recipe::Increment {
            out: [y[0].id, y[1].id, carry.id],
            old: x.map(|e| e.id),
            gate: g.id,
        });
        self.gate(g, x[0] + 1 - y[0] - carry * (1u64 << 32));
        self.gate(g, x[1] + carry - y[1]);
        for z in [y[0], y[1], carry] {
            self.zero((self.c(1) - g) * z);
        }
        y
    }
    pub fn ge_small<'a>(&'a self, x: E<'a>, y: E<'a>) -> E<'a> {
        let d = self.fresh("small-difference", Ty::Bits(3));
        let c = self.fresh("small-carry", Ty::Bool);
        self.recipe(Recipe::Small {
            out: [d.id, c.id],
            left: x.id,
            right: y.id,
        });
        self.eq(x + 8 - y, d + c * 8);
        c
    }
    pub fn policy<'a>(&'a self, a: E<'a>, b: E<'a>) -> [E<'a>; 3] {
        if let Some(i) = self.pool.borrow().policy_cache.get(&(a.id, b.id)).copied() {
            let out = self.pool.borrow().policies[i].output;
            return out.map(|id| self.e(id));
        }
        let i = self.pool.borrow().policies.len();
        let out = core::array::from_fn(|k| self.node(Node::Policy(i, k)).id);
        {
            let mut p = self.pool.borrow_mut();
            p.policies.push(Policy {
                a: a.id,
                b: b.id,
                output: out,
            });
            p.policy_cache.insert((a.id, b.id), i);
        }
        out.map(|id| self.e(id))
    }
    pub fn hash<'a>(&'a self, label: &str, fields: &[E<'a>]) -> [E<'a>; 4] {
        if fields.is_empty() || !fields.len().is_multiple_of(8) {
            self.pool
                .borrow_mut()
                .errors
                .push(format!("hash-length:{label}"));
            return [self.c(0); 4];
        }
        let mut state = [self.c(0); 12];
        for (block, words) in fields.as_chunks::<8>().0.iter().enumerate() {
            state[..8].copy_from_slice(words);
            let n = self.pool.borrow().hashes.len();
            let out = core::array::from_fn(|w| self.node(Node::Hash(n, w)).id);
            self.pool.borrow_mut().hashes.push(Hash {
                label: format!("{label}/{block}"),
                input: state.map(|v| v.id),
                output: out,
            });
            state = out.map(|id| self.e(id));
        }
        core::array::from_fn(|i| state[i])
    }
    pub fn mask<'a>(&'a self) -> [E<'a>; 8] {
        for row in 0..32 {
            let bits = core::array::from_fn(|i| self.node(Node::MaskBit(row, i)).id);
            let frequencies = core::array::from_fn(|i| self.node(Node::MaskFrequency(row, i)).id);
            let byte = self.node(Node::MaskByte(row)).id;
            self.pool.borrow_mut().mask.push(MaskByte {
                bits,
                frequencies,
                byte,
            });
        }
        let bytes = self
            .pool
            .borrow()
            .mask
            .iter()
            .map(|m| m.byte)
            .collect::<Vec<_>>();
        core::array::from_fn(|w| {
            self.sum((0..4).map(|j| self.e(bytes[4 * w + j]) * (1u64 << (8 * j))))
        })
    }
    pub fn mask_read<'a>(&'a self, age: E<'a>) -> E<'a> {
        let i = self.pool.borrow().reads.len();
        let out = self.node(Node::MaskRead(i));
        self.pool.borrow_mut().reads.push(MaskRead {
            age: age.id,
            output: out.id,
        });
        out
    }
    pub fn close(&self) {
        let modes = self.pool.borrow().mode_inputs.clone();
        for id in modes {
            let x = self.e(id);
            let p = self.policy(x, self.c(0));
            self.eq(p[0], x);
        }
        let r = self.pool.borrow().policies.len();
        if r > u32::MAX as usize {
            self.pool.borrow_mut().errors.push("policy-count".into());
            return;
        }
        let mut hist = Vec::new();
        for i in 0..25 {
            let f = self.node(Node::PolicyFrequency(i));
            self.pool.borrow_mut().policy_frequencies.push(f.id);
            self.range(f, 32);
            let d = self.c(r as u64) - f;
            self.range(d, 32);
            hist.push(f);
        }
        self.eq(self.sum(hist), self.c(r as u64));
        let freq = self
            .pool
            .borrow()
            .mask
            .iter()
            .flat_map(|m| m.frequencies)
            .collect::<Vec<_>>();
        let predicate = self.pool.borrow().predicate;
        self.eq(
            self.sum(freq.into_iter().map(|id| self.e(id))),
            self.c(if predicate { 4 } else { 0 }),
        );
        if self.pool.borrow().reads.len() != 4 {
            self.pool.borrow_mut().errors.push("mask-read-count".into());
        }
    }
    pub fn take(self) -> Built {
        Built {
            pool: self.pool.into_inner(),
            origins: self.origins.into_inner(),
        }
    }
}
macro_rules! binary {
    ($t:ident,$m:ident,$o:ident) => {
        impl<'a> $t for E<'a> {
            type Output = Self;
            fn $m(self, rhs: Self) -> Self {
                if !std::ptr::eq(self.b, rhs.b) {
                    self.b
                        .pool
                        .borrow_mut()
                        .errors
                        .push("foreign-expression".into());
                    return self.b.c(0);
                }
                self.b.arith(Op::$o, self.id, rhs.id)
            }
        }
        impl<'a> $t<u64> for E<'a> {
            type Output = Self;
            fn $m(self, rhs: u64) -> Self {
                self.$m(self.b.c(rhs))
            }
        }
    };
}
binary!(Add, add, Add);
binary!(Sub, sub, Sub);
binary!(Mul, mul, Mul);
impl<'a> Neg for E<'a> {
    type Output = Self;
    fn neg(self) -> Self {
        self.b.arith(Op::Neg, self.id, self.id)
    }
}
