//! Exhaustive live semantic serialization used by mandatory literal native pins.
use super::expr::{self, Node};
pub(super) fn full_ir_bytes(pool: &expr::Pool) -> Vec<u8> {
    use p3_field::PrimeField64;
    fn size(v: &mut Vec<u8>, n: usize) {
        v.extend(u64::try_from(n).expect("bounded IR").to_le_bytes());
    }
    fn ids(v: &mut Vec<u8>, s: &[usize]) {
        size(v, s.len());
        for n in s {
            size(v, *n);
        }
    }
    fn text(v: &mut Vec<u8>, s: &str) {
        size(v, s.len());
        v.extend(s.as_bytes());
    }
    let mut v = b"DCS/research/word208/full-semantic-IR/v2/typed309PUBLIC".to_vec();
    v.push(u8::from(pool.predicate));
    size(&mut v, pool.nodes.len());
    for node in &pool.nodes {
        match node {
            Node::Public(a) => {
                v.push(10);
                size(&mut v, a.ordinal());
            }
            Node::Constant(x) => {
                v.push(0);
                v.extend(x.as_canonical_u64().to_le_bytes());
            }
            Node::Input(s, t) => {
                v.push(1);
                text(&mut v, s);
                match t {
                    expr::Ty::Gold => v.push(0),
                    expr::Ty::Bool => v.push(1),
                    expr::Ty::U32 => v.push(2),
                    expr::Ty::Bits(n) => {
                        v.push(3);
                        v.push(*n)
                    }
                    expr::Ty::Mode => v.push(4),
                }
            }
            Node::Arith(o, a, b) => {
                v.push(2);
                v.push(match o {
                    expr::Op::Add => 0,
                    expr::Op::Sub => 1,
                    expr::Op::Mul => 2,
                    expr::Op::Neg => 3,
                });
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::Hash(a, b) => {
                v.push(3);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::Policy(a, b) => {
                v.push(4);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::PolicyFrequency(a) => {
                v.push(5);
                size(&mut v, *a);
            }
            Node::MaskBit(a, b) => {
                v.push(6);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::MaskFrequency(a, b) => {
                v.push(7);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::MaskByte(a) => {
                v.push(8);
                size(&mut v, *a);
            }
            Node::MaskRead(a) => {
                v.push(9);
                size(&mut v, *a);
            }
        }
    }
    ids(&mut v, &pool.assertions);
    size(&mut v, pool.ranges.len());
    for (i, n) in &pool.ranges {
        size(&mut v, *i);
        v.push(*n);
    }
    size(&mut v, pool.hashes.len());
    for h in &pool.hashes {
        text(&mut v, &h.label);
        ids(&mut v, &h.input);
        ids(&mut v, &h.output);
    }
    size(&mut v, pool.policies.len());
    for p in &pool.policies {
        size(&mut v, p.a);
        size(&mut v, p.b);
        ids(&mut v, &p.output);
    }
    size(&mut v, pool.mask.len());
    for m in &pool.mask {
        ids(&mut v, &m.bits);
        ids(&mut v, &m.frequencies);
        size(&mut v, m.byte);
    }
    size(&mut v, pool.reads.len());
    for r in &pool.reads {
        size(&mut v, r.age);
        size(&mut v, r.output);
    }
    size(&mut v, pool.fields.len());
    for (s, i) in &pool.fields {
        text(&mut v, s);
        size(&mut v, *i);
    }
    size(&mut v, pool.errors.len());
    for s in &pool.errors {
        text(&mut v, s);
    }
    ids(&mut v, &pool.mode_inputs);
    ids(&mut v, &pool.policy_frequencies);
    v
}
