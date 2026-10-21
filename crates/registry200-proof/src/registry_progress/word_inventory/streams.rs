//! Complete fixed preimages over the SAME SSA values used by semantic constraints.
use super::recipes::{Group, SaltField};
use super::{
    Metadata,
    control::{BEGIN, Command, END, Effect},
    expr::{Builder, E, Ty},
    predicate::Walk,
    schema::*,
};
use p3_field::PrimeCharacteristicRing;
fn header<'a>(b: &'a Builder, label: &str) -> Vec<E<'a>> {
    super::header(label).into_iter().map(|v| b.val(v)).collect()
}
fn fields<'a>(b: &'a Builder, label: &str, v: &[E<'a>], size: usize) -> Vec<E<'a>> {
    assert_eq!(v.len(), size);
    for (i, e) in v.iter().enumerate() {
        b.field(format!("stream/{label}/{i}"), *e);
    }
    v.to_vec()
}
fn capture(b: &Builder, g: E<'_>, actual: [E<'_>; 4], expected: [E<'_>; 4]) {
    for i in 0..4 {
        b.gate(g, actual[i] - expected[i]);
    }
}
fn selected_controller<'a>(c: &Command<'a>, controllers: [[E<'a>; 8]; 2]) -> [E<'a>; 8] {
    core::array::from_fn(|i| {
        c.principal_bits[0] * controllers[0][i] + c.principal_bits[1] * controllers[1][i]
    })
}
pub(super) struct Links<'a> {
    pub statement: [E<'a>; 4],
    pub new_progress: [E<'a>; 4],
}
pub(super) fn source_and_enrollment<'a>(
    b: &'a Builder,
    m: &Metadata,
    s: &Source<'a>,
    controllers: [[E<'a>; 8]; 2],
) {
    let mut state = crate::source::commitment::prefix(m.source.statement(), [crate::Val::ZERO; 4])
        .into_iter()
        .map(|v| b.val(v))
        .collect::<Vec<_>>();
    state[83..87].copy_from_slice(&s.salt);
    state.extend(s.words);
    state.extend([b.c(0); 6]);
    let state = fields(b, "source", &state, 680);
    capture(
        b,
        b.c(1),
        b.hash("source", &state),
        m.source.statement().open_commitment.map(|v| b.val(v)),
    );
    let mut enrollment = m.enrollment_header.map(|v| b.val(v)).to_vec();
    enrollment.extend(s.table);
    enrollment.extend([b.c(2), b.c(1)]);
    enrollment.extend(controllers[0]);
    enrollment.push(b.c(2));
    enrollment.extend(controllers[1]);
    enrollment.extend((0..4).map(|i| {
        b.input_primary(
            &format!("enrollment/salt/{i}"),
            Ty::Gold,
            Group::Salt(SaltField::Enrollment),
            i,
        )
    }));
    let enrollment = fields(b, "enrollment", &enrollment, 64);
    capture(
        b,
        b.c(1),
        b.hash("enrollment", &enrollment),
        m.enrollment.map(|v| b.val(v)),
    );
}
pub(super) fn command<'a>(
    b: &'a Builder,
    m: &Metadata,
    old: &Bank<'a>,
    c: &Command<'a>,
    controllers: [[E<'a>; 8]; 2],
    parent: [E<'a>; 8],
) {
    let mut v = super::domain("command").map(|x| b.val(x)).to_vec();
    v.push(b.c(1));
    v.extend(m.context.map(|x| b.val(x)));
    v.extend(m.old.map(|x| b.val(x)));
    v.push(b.code(&c.op));
    v.extend(c.id);
    v.push(c.principal);
    v.extend(selected_controller(c, controllers));
    v.extend(old.revision());
    v.extend(c.own.limbs(SEQUENCE));
    v.extend(c.mask);
    v.extend([c.mode, b.code(&c.wait), c.offset, c.limit, c.projection]);
    v.extend(c.name);
    v.extend(parent.map(|x| c.op[BEGIN] * x));
    v.push(c.abort);
    v.extend((0..4).map(|i| {
        b.input_primary(
            &format!("command/salt/{i}"),
            Ty::Gold,
            Group::Salt(SaltField::Command),
            i,
        )
    }));
    v.push(b.c(0));
    let v = fields(b, "command", &v, 160);
    capture(
        b,
        b.c(1),
        b.hash("command", &v),
        m.command.map(|x| b.val(x)),
    );
}
fn progress<'a>(
    b: &'a Builder,
    stmt: [E<'a>; 4],
    c: &Command<'a>,
    w: &Walk<'a>,
    old: &Bank<'a>,
    new: bool,
) -> Vec<E<'a>> {
    let mut v = header(b, "progress");
    v.extend(stmt);
    v.extend(c.id);
    v.push(c.principal);
    v.extend(w.call);
    v.extend(if new { w.micro } else { w.old_micro });
    let cursor = if new { w.cursor } else { w.old_cursor };
    v.push(cursor);
    v.extend(if new { w.visited } else { w.old_visited });
    v.extend(if new { w.selected } else { w.old_selected });
    v.push(b.c(1));
    v.push(cursor);
    v.extend(if new { w.holder } else { w.old_holder });
    v.push(if new {
        w.holder_mode
    } else {
        w.old_holder_mode
    });
    v.extend(if new {
        old.revision()
    } else {
        w.old_block_revision
    });
    v.extend(if new { w.new_salt } else { w.old_salt });
    v.extend([b.c(0); 4]);
    assert_eq!(v.len(), 48);
    v
}
pub(super) fn statement_and_progress<'a>(
    b: &'a Builder,
    m: &Metadata,
    old: &Bank<'a>,
    c: &Command<'a>,
    w: &Walk<'a>,
    controllers: [[E<'a>; 8]; 2],
) -> Links<'a> {
    let gate = b.c(u64::from(m.predicate));
    let mut v = header(b, "statement");
    v.extend(m.scope.map(|x| b.val(x)));
    v.extend(m.enrollment.map(|x| b.val(x)));
    v.extend(w.client);
    v.extend(w.call);
    v.extend(c.id);
    v.push(c.principal);
    v.extend(selected_controller(c, controllers));
    v.extend(w.invocation);
    v.extend(w.sql);
    v.extend(c.own.words::<8>(SNAPSHOT));
    v.extend(c.mask);
    v.extend([c.mode, b.code(&c.wait), c.offset, c.limit, c.projection]);
    v.extend(w.statement_salt);
    v.push(b.c(0));
    let v = fields(b, "statement", &v, 96);
    let statement = b.hash("statement", &v);
    capture(b, gate, statement, m.statement.map(|x| b.val(x)));
    let p = progress(b, statement, c, w, old, false);
    let p = fields(b, "old-progress", &p, 48);
    let old_hash = b.hash("old-progress", &p);
    let old_selected = select_progress(old, c.actor);
    capture(
        b,
        w.resume,
        old_hash,
        core::array::from_fn(|i| old_selected[i + 1]),
    );
    let p = progress(b, statement, c, w, old, true);
    let p = fields(b, "new-progress", &p, 48);
    let new_progress = b.hash("new-progress", &p);
    Links {
        statement: statement.map(|x| gate * x),
        new_progress,
    }
}
pub(super) fn bank(b: &Builder, m: &Metadata, bank: &Bank<'_>, new: bool) {
    let name = if new { "new" } else { "old" };
    let values = fields(b, name, &bank.f, 208);
    let root = b.hash(name, &values);
    capture(
        b,
        b.c(1),
        root,
        if new { m.next } else { m.old }.map(|x| b.val(x)),
    );
}
pub(super) fn result<'a>(
    b: &'a Builder,
    m: &Metadata,
    old: &Bank<'a>,
    new: &Bank<'a>,
    c: &Command<'a>,
    w: &Walk<'a>,
    links: &Links<'a>,
) {
    let mut v = super::domain("result").map(|x| b.val(x)).to_vec();
    v.push(b.c(1));
    v.extend(m.context.map(|x| b.val(x)));
    v.extend(m.old.map(|x| b.val(x)));
    v.extend(m.next.map(|x| b.val(x)));
    v.extend(links.statement);
    let action = if m.predicate {
        w.resume
    } else {
        b.code(&c.op) + 2
    };
    let status = if m.predicate {
        w.status[1] + w.status[2] * 2
    } else {
        b.c(1) + c.op[END] * (c.abort + c.own.f[FAILED] - c.abort * c.own.f[FAILED]) * 2
    };
    v.extend([action, status]);
    v.extend(c.id);
    v.extend([w.old_cursor, w.cursor]);
    v.extend(w.visited);
    v.extend(w.selected);
    v.extend(w.block);
    let old_p = select_progress(old, c.actor);
    let new_p = select_progress(new, c.actor);
    v.extend(old_p[1..].iter().copied());
    v.extend(new_p[1..].iter().map(|x| (b.c(1) - c.op[END]) * *x));
    v.extend(w.holder);
    v.push(w.holder_mode);
    v.extend(w.call);
    v.extend(w.micro);
    v.extend((0..4).map(|i| {
        b.input_primary(
            &format!("result/salt/{i}"),
            Ty::Gold,
            Group::Salt(SaltField::Result),
            i,
        )
    }));
    v.extend([b.c(0); 6]);
    let v = fields(b, "result", &v, 160);
    capture(b, b.c(1), b.hash("result", &v), m.result.map(|x| b.val(x)));
}
pub(super) fn effect<'a>(w: &Walk<'a>, l: &Links<'a>) -> Effect<'a> {
    Effect {
        failed: w.status[2],
        visit: w.visit,
        desired: w.desired,
        parked: w.status[0],
        new_progress: l.new_progress,
    }
}
