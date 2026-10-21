//! Both complete canonical word banks; no native model callback.
use super::{
    expr::{Builder, E, Ty},
    schema::*,
};
pub(super) fn bank<'a>(b: &'a Builder, s: &Bank<'a>, controllers: [[E<'a>; 8]; 2]) {
    b.compare64(s.allocator(), s.revision(), false, b.c(1));
    b.zero(s.tx(1).f[PRESENT] * (b.c(1) - s.tx(0).f[PRESENT]));
    b.compare64(
        s.tx(0).limbs(ID),
        s.tx(1).limbs(ID),
        true,
        s.tx(1).f[PRESENT],
    );
    for t in 0..2 {
        let tx = s.tx(t);
        let present = tx.f[PRESENT];
        let principal = [
            b.fresh("principal-one", Ty::Bool),
            b.fresh("principal-two", Ty::Bool),
        ];
        b.recipe(super::recipes::Recipe::Principal {
            out: principal.map(|e| e.id),
            present: present.id,
            code: tx.f[PRINCIPAL].id,
        });
        b.eq(principal[0] + principal[1], present);
        b.eq(tx.f[PRINCIPAL], principal[0] + principal[1] * 2);
        for (w, (&one, &two)) in controllers[0].iter().zip(&controllers[1]).enumerate() {
            b.eq(
                tx.f[CONTROLLER + w],
                principal[0] * one + principal[1] * two,
            );
        }
        b.nonzero(&tx.limbs(ID), present);
        b.nonzero(&tx.limbs(SEQUENCE), present);
        b.compare64(tx.limbs(ID), s.allocator(), false, b.c(1));
        for v in &tx.f[1..] {
            b.zero((b.c(1) - present) * *v);
        }
        let frames = [tx.frame(0), tx.frame(1)];
        b.zero(frames[1][0] * (b.c(1) - frames[0][0]));
        for f in frames {
            b.zero(f[0] * (b.c(1) - present));
            for v in &f[1..] {
                b.zero((b.c(1) - f[0]) * *v);
            }
        }
        for r in 0..4 {
            let h = tx.f[HELD + r];
            let a = frames[0][9 + r];
            let c = frames[1][9 + r];
            let ah = b.policy(a, h);
            let ch = b.policy(c, h);
            let ac = b.policy(a, c);
            b.eq(ah[1], b.c(1));
            b.eq(ch[1], b.c(1));
            b.gate(frames[1][0], b.c(1) - ac[1]);
            let latest = frames[1][0] * c + (frames[0][0] - frames[1][0]) * a;
            b.zero(tx.f[FAILED] * (h - latest));
        }
        let p = s.progress(t);
        b.zero(p[0] * (b.c(1) - present));
        b.zero(p[0] * tx.f[FAILED]);
        for root in &p[1..] {
            b.zero((b.c(1) - p[0]) * *root);
        }
    }
    for r in 0..4 {
        let policy = b.policy(s.tx(0).f[HELD + r], s.tx(1).f[HELD + r]);
        b.zero(policy[2]);
    }
}
