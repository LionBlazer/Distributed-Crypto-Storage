//! Physical four-row scan and exact original WAIT continuation. Never an owner model.
use super::recipes::{Group, WalkField};
use super::{
    control::Command,
    expr::{Builder, E, Ty},
    schema::*,
};
pub(super) struct Walk<'a> {
    pub resume: E<'a>,
    pub status: [E<'a>; 3],
    pub old_cursor: E<'a>,
    pub cursor: E<'a>,
    pub old_micro: [E<'a>; 2],
    pub micro: [E<'a>; 2],
    pub old_visited: [E<'a>; 4],
    pub old_selected: [E<'a>; 4],
    pub visited: [E<'a>; 4],
    pub selected: [E<'a>; 4],
    pub search: [E<'a>; 4],
    pub visit: [E<'a>; 4],
    pub skipped: [E<'a>; 4],
    pub block: [E<'a>; 4],
    pub old_holder: [E<'a>; 2],
    pub old_holder_mode: E<'a>,
    pub old_block_revision: [E<'a>; 2],
    pub holder: [E<'a>; 2],
    pub holder_mode: E<'a>,
    pub old_salt: [E<'a>; 4],
    pub new_salt: [E<'a>; 4],
    pub statement_salt: [E<'a>; 4],
    pub client: [E<'a>; 8],
    pub call: [E<'a>; 2],
    pub invocation: [E<'a>; 8],
    pub sql: [E<'a>; 8],
    pub desired: [E<'a>; 4],
}
impl<'a> Walk<'a> {
    pub fn new(
        b: &'a Builder,
        old: &Bank<'a>,
        c: &Command<'a>,
        matched: [E<'a>; 4],
        blind_sql: [E<'a>; 8],
        predicate: bool,
    ) -> Self {
        if !predicate {
            for v in matched {
                b.zero(v);
            }
            return Self::zero(b);
        }
        let p = select_progress(old, c.actor);
        let resume = p[0];
        let client = core::array::from_fn(|i| {
            b.input_primary(
                &format!("statement/client/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Client),
                i,
            )
        });
        let call = core::array::from_fn(|i| {
            b.input_primary(
                &format!("statement/call/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Call),
                i,
            )
        });
        let invocation = core::array::from_fn(|i| {
            b.input_primary(
                &format!("statement/invocation/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Invocation),
                i,
            )
        });
        let sql = core::array::from_fn(|i| {
            b.input_primary(
                &format!("statement/sql/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Sql),
                i,
            )
        });
        b.nonzero(&client, b.c(1));
        b.nonzero(&call, b.c(1));
        b.nonzero(&invocation, b.c(1));
        for i in 0..8 {
            b.gate(b.c(1) - resume, sql[i] - blind_sql[i]);
        }
        let old_pos = b.onehot_primary::<5>("progress/old-cursor", Group::Walk(WalkField::Cursor));
        let old_cursor = b.code(&old_pos);
        b.zero(old_pos[4]);
        b.zero((b.c(1) - resume) * (b.c(1) - old_pos[0]));
        b.zero(resume * (c.wait[1] + c.wait[2]));
        let old_micro = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/old-micro/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Micro),
                i,
            )
        });
        let old_holder = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/old-holder/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Holder),
                i,
            )
        });
        let old_holder_mode = b.input_primary(
            "progress/old-holder-mode",
            Ty::Mode,
            Group::Walk(WalkField::Mode),
            0,
        );
        let old_block_revision = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/old-block-revision/{i}"),
                Ty::U32,
                Group::Walk(WalkField::Revision),
                i,
            )
        });
        let old_salt = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/old-salt/{i}"),
                Ty::Gold,
                Group::Walk(WalkField::OldSalt),
                i,
            )
        });
        let new_salt = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/new-salt/{i}"),
                Ty::Gold,
                Group::Walk(WalkField::NewSalt),
                i,
            )
        });
        let statement_salt = core::array::from_fn(|i| {
            b.input_primary(
                &format!("statement/salt/{i}"),
                Ty::Gold,
                Group::Walk(WalkField::StatementSalt),
                i,
            )
        });
        for v in old_micro
            .into_iter()
            .chain(old_holder)
            .chain(old_block_revision)
            .chain(old_salt)
            .chain([old_holder_mode])
        {
            b.zero((b.c(1) - resume) * v);
        }
        b.nonzero(&old_micro, resume);
        b.nonzero(&old_holder, resume);
        let same = b.equal_words(&old_holder, &c.id);
        b.zero(resume * same);
        let historical = b.policy(c.mode, old_holder_mode);
        b.eq(historical[2], resume);
        b.compare64(old_block_revision, old.revision(), true, resume);
        let micro = b.increment(old_micro, b.c(1));
        let old_visited = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/old-visited/{i}"),
                Ty::Bool,
                Group::Walk(WalkField::Visited),
                i,
            )
        });
        let old_selected = core::array::from_fn(|i| {
            b.input_primary(
                &format!("progress/old-selected/{i}"),
                Ty::Bool,
                Group::Walk(WalkField::Selected),
                i,
            )
        });
        let mut visited = [b.c(0); 4];
        let mut selected = [b.c(0); 4];
        let mut search = [b.c(0); 4];
        let mut visit = [b.c(0); 4];
        let mut skipped = [b.c(0); 4];
        let mut block = [b.c(0); 4];
        let mut desired = [b.c(0); 4];
        for i in 0..4 {
            let before = b.sum(old_pos[i + 1..].iter().copied());
            b.eq(old_visited[i], resume * before * matched[i]);
            let qualified = b.ge_small(b.sum(old_visited[..i].iter().copied()), c.offset);
            b.eq(old_selected[i], old_visited[i] * qualified);
            let adequate = b.policy(c.mode, c.own.f[HELD + i]);
            b.zero(old_visited[i] * (b.c(1) - adequate[1]));
            let other = c.actor[0] * old.tx(1).f[HELD + i] + c.actor[1] * old.tx(0).f[HELD + i];
            let conflict = b.policy(c.mode, other)[2];
            let limit_met = b.ge_small(b.sum(selected[..i].iter().copied()), c.limit);
            let offset_met = b.ge_small(b.sum(visited[..i].iter().copied()), c.offset);
            search[i] = (b.c(1) - before)
                * (b.c(1) - b.sum(block[..i].iter().copied()))
                * (b.c(1) - limit_met);
            let attempt = search[i] * matched[i];
            block[i] = attempt * conflict * (b.c(1) - c.wait[2]);
            skipped[i] = attempt * conflict * c.wait[2];
            visit[i] = attempt * (b.c(1) - conflict);
            visited[i] = old_visited[i] + visit[i];
            selected[i] = old_selected[i] + visit[i] * offset_met;
            for v in [
                search[i],
                block[i],
                skipped[i],
                visit[i],
                visited[i],
                selected[i],
            ] {
                b.boolean(v);
            }
            desired[i] = b.policy(c.own.f[HELD + i], c.mode)[0];
        }
        let old_limit_met = b.ge_small(b.sum(old_selected), c.limit);
        b.zero(resume * old_limit_met);
        let blocked = b.sum(block);
        b.boolean(blocked);
        let status = [blocked * c.wait[0], b.c(1) - blocked, blocked * c.wait[1]];
        let cursor = old_cursor + b.sum(search) - blocked;
        b.range(cursor, 3);
        let holder = core::array::from_fn(|w| {
            blocked * (c.actor[0] * old.tx(1).f[ID + w] + c.actor[1] * old.tx(0).f[ID + w])
        });
        let holder_mode = b.sum((0..4).map(|i| {
            block[i] * (c.actor[0] * old.tx(1).f[HELD + i] + c.actor[1] * old.tx(0).f[HELD + i])
        }));
        for v in new_salt {
            b.zero((b.c(1) - status[0]) * v);
        }
        let out = Self {
            resume,
            status,
            old_cursor,
            cursor,
            old_micro,
            micro,
            old_visited,
            old_selected,
            visited,
            selected,
            search,
            visit,
            skipped,
            block,
            old_holder,
            old_holder_mode,
            old_block_revision,
            holder,
            holder_mode,
            old_salt,
            new_salt,
            statement_salt,
            client,
            call,
            invocation,
            sql,
            desired,
        };
        for i in 0..4 {
            b.field(format!("scan/search/{i}"), out.search[i]);
            b.field(format!("scan/skipped/{i}"), out.skipped[i]);
        }
        out
    }
    fn zero(b: &'a Builder) -> Self {
        Self {
            resume: b.c(0),
            status: [b.c(0); 3],
            old_cursor: b.c(0),
            cursor: b.c(0),
            old_micro: [b.c(0); 2],
            micro: [b.c(0); 2],
            old_visited: [b.c(0); 4],
            old_selected: [b.c(0); 4],
            visited: [b.c(0); 4],
            selected: [b.c(0); 4],
            search: [b.c(0); 4],
            visit: [b.c(0); 4],
            skipped: [b.c(0); 4],
            block: [b.c(0); 4],
            old_holder: [b.c(0); 2],
            old_holder_mode: b.c(0),
            old_block_revision: [b.c(0); 2],
            holder: [b.c(0); 2],
            holder_mode: b.c(0),
            old_salt: [b.c(0); 4],
            new_salt: [b.c(0); 4],
            statement_salt: [b.c(0); 4],
            client: [b.c(0); 8],
            call: [b.c(0); 2],
            invocation: [b.c(0); 8],
            sql: [b.c(0); 8],
            desired: [b.c(0); 4],
        }
    }
}
