//! Exact packed-word authorization, newest-name targeting and all-field writes.
use super::recipes::{CmdField, Group};
use super::{
    expr::{Builder, E, Ty},
    schema::*,
};
pub(super) const BEGIN: usize = 0;
pub(super) const ACQUIRE: usize = 1;
pub(super) const FAIL: usize = 2;
pub(super) const SAVE: usize = 3;
pub(super) const ROLLBACK: usize = 4;
pub(super) const RELEASE: usize = 5;
pub(super) const END: usize = 6;
pub(super) struct Command<'a> {
    pub op: [E<'a>; 7],
    pub actor: [E<'a>; 2],
    pub principal: E<'a>,
    pub principal_bits: [E<'a>; 2],
    pub id: [E<'a>; 2],
    pub name: [E<'a>; 8],
    pub mask: [E<'a>; 8],
    pub mode: E<'a>,
    pub wait: [E<'a>; 3],
    pub offset: E<'a>,
    pub limit: E<'a>,
    pub projection: E<'a>,
    pub abort: E<'a>,
    pub target: [E<'a>; 2],
    pub own: Tx<'a>,
    pub allocation: [E<'a>; 2],
    pub sequence: [E<'a>; 2],
}
impl<'a> Command<'a> {
    pub fn new(b: &'a Builder, old: &Bank<'a>, predicate: bool) -> Self {
        let op = if predicate {
            core::array::from_fn(|i| b.c(u64::from(i == ACQUIRE)))
        } else {
            let a = b.onehot_primary::<7>("cmd/op", Group::Command(CmdField::Op));
            b.zero(a[ACQUIRE]);
            b.zero(a[FAIL]);
            a
        };
        let actor = [
            b.input_primary("cmd/actor/0", Ty::Bool, Group::Command(CmdField::Actor), 0),
            b.input_primary("cmd/actor/1", Ty::Bool, Group::Command(CmdField::Actor), 1),
        ];
        b.eq(actor[0] + actor[1], b.c(1) - op[BEGIN]);
        let principal_bits =
            b.onehot_primary::<2>("cmd/principal", Group::Command(CmdField::Principal));
        let principal = principal_bits[0] + principal_bits[1] * 2;
        let id = core::array::from_fn(|i| {
            b.input_primary(
                &format!("cmd/id/{i}"),
                Ty::U32,
                Group::Command(CmdField::Id),
                i,
            )
        });
        b.nonzero(&id, b.c(1));
        let name = core::array::from_fn(|i| {
            b.input_primary(
                &format!("cmd/name/{i}"),
                Ty::U32,
                Group::Command(CmdField::Name),
                i,
            )
        });
        for n in name {
            b.zero((b.c(1) - op[SAVE] - op[ROLLBACK] - op[RELEASE]) * n);
        }
        let mask = b.mask();
        if !predicate {
            for v in mask {
                b.zero(v);
            }
        }
        let (mode, wait, offset, limit, projection) = if predicate {
            let m = b.onehot_primary::<4>("query/mode", Group::Command(CmdField::Mode));
            let w = b.onehot_primary::<3>("query/wait", Group::Command(CmdField::Wait));
            let off = b.onehot_primary::<5>("query/offset", Group::Command(CmdField::Offset));
            let lim = b.onehot_primary::<5>("query/limit", Group::Command(CmdField::Limit));
            let p = [
                b.input_primary(
                    "query/projection/0",
                    Ty::Bool,
                    Group::Command(CmdField::Projection),
                    0,
                ),
                b.input_primary(
                    "query/projection/1",
                    Ty::Bool,
                    Group::Command(CmdField::Projection),
                    1,
                ),
            ];
            b.zero((b.c(1) - p[0]) * (b.c(1) - p[1]));
            (
                b.code(&m) + 1,
                w,
                b.code(&off),
                b.code(&lim),
                p[0] + p[1] * 2,
            )
        } else {
            (b.c(0), [b.c(0); 3], b.c(0), b.c(0), b.c(0))
        };
        let abort = if predicate {
            b.c(0)
        } else {
            b.input_primary("cmd/abort", Ty::Bool, Group::Command(CmdField::Abort), 0)
        };
        b.zero((b.c(1) - op[END]) * abort);
        for (t, &selected) in actor.iter().enumerate() {
            let tx = old.tx(t);
            b.zero(selected * (b.c(1) - tx.f[PRESENT]));
            for (i, &part) in id.iter().enumerate() {
                b.gate(selected, part - tx.f[ID + i]);
            }
            b.gate(selected, principal - tx.f[PRINCIPAL]);
            b.zero(selected * tx.f[FAILED] * (b.c(1) - op[ROLLBACK] - op[END]));
        }
        let own = select_tx(old, actor);
        let allocation = b.increment(old.allocator(), op[BEGIN]);
        for i in 0..2 {
            b.gate(op[BEGIN], id[i] - allocation[i]);
        }
        b.zero(op[BEGIN] * old.tx(1).f[PRESENT]);
        let sequence = b.increment(own.limbs(SEQUENCE), b.c(1) - op[BEGIN] - op[END]);
        let equal: [E<'a>; 2] = core::array::from_fn(|f| b.equal_words(&own.frame(f)[1..9], &name));
        let target1 = own.frame(1)[0] * equal[1];
        let target0 = own.frame(0)[0] * equal[0] * (b.c(1) - target1);
        let target = [target0, target1];
        b.gate(op[ROLLBACK] + op[RELEASE], target0 + target1 - 1);
        b.zero(op[SAVE] * own.frame(1)[0]);
        let p = select_progress(old, actor);
        if !predicate {
            b.zero(p[0] * (b.c(1) - op[END]));
            b.zero(p[0] * (b.c(1) - abort));
        }
        Self {
            op,
            actor,
            principal,
            principal_bits,
            id,
            name,
            mask,
            mode,
            wait,
            offset,
            limit,
            projection,
            abort,
            target,
            own,
            allocation,
            sequence,
        }
    }
}
pub(super) struct Effect<'a> {
    pub failed: E<'a>,
    pub visit: [E<'a>; 4],
    pub desired: [E<'a>; 4],
    pub parked: E<'a>,
    pub new_progress: [E<'a>; 4],
}
pub(super) fn apply<'a>(
    b: &'a Builder,
    old: &Bank<'a>,
    new: &Bank<'a>,
    c: &Command<'a>,
    effect: &Effect<'a>,
    parent: [E<'a>; 8],
    controllers: [[E<'a>; 8]; 2],
) {
    let predicate = b.pool.borrow().predicate;
    let rev = b.increment(old.revision(), b.c(1));
    for (i, &revision) in rev.iter().enumerate() {
        b.eq(new.revision()[i], revision);
        b.derive(new.revision()[i], revision);
        let allocator = b.select(c.op[BEGIN], c.allocation[i], old.allocator()[i]);
        b.eq(new.allocator()[i], allocator);
        b.derive(new.allocator()[i], allocator);
    }
    let acquire = if predicate {
        b.c(1) - effect.failed
    } else {
        b.c(0)
    };
    for t in 0..2 {
        let tx = old.tx(t);
        let n = new.tx(t);
        let frames = [tx.frame(0), tx.frame(1)];
        for p in 0..53 {
            let oldv = tx.f[p];
            let mut changed = oldv;
            match p {
                SEQUENCE..=13 => {
                    changed = oldv
                        + (b.c(1) - c.op[BEGIN] - c.op[END]) * (c.sequence[p - SEQUENCE] - oldv);
                }
                FAILED => {
                    changed = oldv + effect.failed * (b.c(1) - oldv) - c.op[ROLLBACK] * oldv;
                }
                HELD..=26 => {
                    let r = p - HELD;
                    let latest = frames[1][0] * frames[1][9 + r]
                        + (frames[0][0] - frames[1][0]) * frames[0][9 + r];
                    let saved = c.target[0] * frames[0][9 + r] + c.target[1] * frames[1][9 + r];
                    changed = oldv
                        + acquire * effect.visit[r] * (effect.desired[r] - oldv)
                        + effect.failed * (latest - oldv)
                        + c.op[ROLLBACK] * (saved - oldv);
                }
                FRAME0..=52 => {
                    let f = (p - FRAME0) / 13;
                    let part = (p - FRAME0) % 13;
                    let push = if f == 0 {
                        b.c(1) - frames[0][0]
                    } else {
                        frames[0][0]
                    };
                    let inserted = match part {
                        0 => b.c(1),
                        1..=8 => c.name[part - 1],
                        9..=12 => tx.f[HELD + part - 9],
                        _ => unreachable!(),
                    };
                    let remove = if f == 0 {
                        c.op[RELEASE] * c.target[0]
                    } else {
                        c.op[RELEASE] + c.op[ROLLBACK] * c.target[0]
                    };
                    changed = oldv + c.op[SAVE] * push * (inserted - oldv) - remove * oldv;
                }
                _ => {}
            }
            let mut expected = oldv + c.actor[t] * (changed - oldv);
            let append = if t == 0 {
                c.op[BEGIN] * (b.c(1) - old.tx(0).f[PRESENT])
            } else {
                c.op[BEGIN] * old.tx(0).f[PRESENT]
            };
            let fresh = match p {
                PRESENT => b.c(1),
                ID..=2 => c.id[p - ID],
                PRINCIPAL => c.principal,
                CONTROLLER..=11 => {
                    c.principal_bits[0] * controllers[0][p - CONTROLLER]
                        + c.principal_bits[1] * controllers[1][p - CONTROLLER]
                }
                SEQUENCE => b.c(1),
                SNAPSHOT..=22 => parent[p - SNAPSHOT],
                _ => b.c(0),
            };
            expected = expected + append * fresh;
            let ended = if t == 0 {
                (b.c(1) - c.actor[0]) * old.tx(0).f[p] + c.actor[0] * old.tx(1).f[p]
            } else {
                b.c(0)
            };
            expected = expected + c.op[END] * (ended - oldv);
            b.eq(n.f[p], expected);
            b.derive(n.f[p], expected);
        }
        for p in 0..5 {
            let oldp = old.progress(t)[p];
            let expected = if predicate {
                let selected = if p == 0 {
                    effect.parked
                } else {
                    effect.parked * effect.new_progress[p - 1]
                };
                (b.c(1) - c.actor[t]) * oldp + c.actor[t] * selected
            } else {
                let ended = if t == 0 {
                    (b.c(1) - c.actor[0]) * old.progress(0)[p] + c.actor[0] * old.progress(1)[p]
                } else {
                    b.c(0)
                };
                oldp + c.op[END] * (ended - oldp)
            };
            b.eq(new.progress(t)[p], expected);
            b.derive(new.progress(t)[p], expected);
        }
    }
}
