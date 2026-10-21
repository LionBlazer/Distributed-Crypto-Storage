//! Independent bounded NONSECRET owner examples, never a runtime/query answer.
//! Typed old/next banks and explicit outcomes are retained BEFORE evaluator/proof.
use super::{
    Metadata, Val, domain, header,
    owner::{self, PrimaryInputs},
};
use crate::registry_progress::word::{CommandInput, WalkInput};
use p3_field::PrimeCharacteristicRing;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::registry_progress) enum Kind {
    ConflictBeforeOffset,
    SkipBeforeOffset,
    LimitZero,
    ResumePrefix,
    NoWaitLatest,
    EndCompact,
}
impl Kind {
    pub const ALL: [Self; 6] = [
        Self::ConflictBeforeOffset,
        Self::SkipBeforeOffset,
        Self::LimitZero,
        Self::ResumePrefix,
        Self::NoWaitLatest,
        Self::EndCompact,
    ];
    pub fn predicate(self) -> bool {
        self != Self::EndCompact
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::ConflictBeforeOffset => "conflict-before-offset",
            Self::SkipBeforeOffset => "skip-before-offset",
            Self::LimitZero => "limit-zero",
            Self::ResumePrefix => "resume-prefix",
            Self::NoWaitLatest => "nowait-latest-savepoint",
            Self::EndCompact => "end-stable-compaction",
        }
    }
}
// Clone is confined to these PUBLIC fixture values, never protected owner inputs.
#[derive(Clone)]
pub(in crate::registry_progress) struct Frame {
    pub name: [u32; 8],
    pub saved: [u8; 4],
}
#[derive(Clone)]
pub(in crate::registry_progress) struct Slot {
    pub id: u64,
    pub principal: usize,
    pub sequence: u64,
    pub failed: bool,
    pub snapshot: [Val; 8],
    pub held: [u8; 4],
    pub frames: [Option<Frame>; 2],
    pub progress: Option<[Val; 4]>,
}
impl Slot {
    fn words(&self, controllers: &[[Val; 8]; 2]) -> [Val; 53] {
        assert!((1..=2).contains(&self.principal));
        let mut a = [Val::ZERO; 53];
        a[0] = Val::ONE;
        put64(&mut a[1..3], self.id);
        a[3] = Val::from_usize(self.principal);
        a[4..12].copy_from_slice(&controllers[self.principal - 1]);
        put64(&mut a[12..14], self.sequence);
        a[14] = Val::from_bool(self.failed);
        a[15..23].copy_from_slice(&self.snapshot);
        for (out, x) in a[23..27].iter_mut().zip(self.held) {
            *out = Val::from_u8(x)
        }
        for (i, frame) in self.frames.iter().enumerate() {
            if let Some(frame) = frame {
                let f = &mut a[27 + 13 * i..40 + 13 * i];
                f[0] = Val::ONE;
                for (out, x) in f[1..9].iter_mut().zip(frame.name) {
                    *out = Val::from_u32(x)
                }
                for (out, x) in f[9..13].iter_mut().zip(frame.saved) {
                    *out = Val::from_u8(x)
                }
            }
        }
        a
    }
}
#[derive(Clone)]
pub(in crate::registry_progress) struct Bank {
    pub revision: u64,
    pub allocator: u64,
    pub slots: [Option<Slot>; 2],
    pub salt: [Val; 4],
}
impl Bank {
    fn words(&self, m: &Metadata, p: &PrimaryInputs) -> [Val; 208] {
        let mut a = [Val::ZERO; 208];
        a[..33].copy_from_slice(&m.registry_header);
        a[33..37].copy_from_slice(&m.enrollment);
        a[37..45].copy_from_slice(&p.source[31..39]);
        a[45..77].copy_from_slice(&p.source[555..587]);
        a[77..80].copy_from_slice(&[Val::TWO, Val::from_u8(4), Val::TWO]);
        put64(&mut a[80..82], self.revision);
        put64(&mut a[82..84], self.allocator);
        a[190..194].copy_from_slice(&self.salt);
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(slot) = slot {
                a[84 + 53 * i..137 + 53 * i].copy_from_slice(&slot.words(&p.controllers));
                if let Some(root) = slot.progress {
                    a[194 + 5 * i] = Val::ONE;
                    a[195 + 5 * i..199 + 5 * i].copy_from_slice(&root)
                }
            }
        }
        a
    }
}
#[derive(Clone)]
pub(in crate::registry_progress) struct Outcome {
    pub action: u8,
    pub status: u8,
    pub cursor: u8,
    pub micro: u64,
    pub search: [bool; 4],
    pub skipped: [bool; 4],
    pub visited: [bool; 4],
    pub selected: [bool; 4],
    pub block: [bool; 4],
    pub holder: u64,
    pub holder_mode: u8,
}
struct Progress {
    cursor: u8,
    micro: u64,
    visited: [bool; 4],
    selected: [bool; 4],
    holder: u64,
    mode: u8,
    revision: u64,
    salt: [Val; 4],
}
pub(in crate::registry_progress) struct Case {
    pub kind: Kind,
    pub metadata: Metadata,
    pub input: PrimaryInputs,
    pub old: Bank,
    pub next: Bank,
    pub outcome: Outcome,
}
fn put64(a: &mut [Val], x: u64) {
    assert_eq!(a.len(), 2);
    a[0] = Val::from_u32(x as u32);
    a[1] = Val::from_u32((x >> 32) as u32)
}
fn bits(v: &mut Vec<Val>, a: [bool; 4]) {
    v.extend(a.map(Val::from_bool))
}
fn own<'a>(bank: &'a Bank, p: &PrimaryInputs) -> &'a Slot {
    bank.slots[p.command.actor.expect("existing actor")]
        .as_ref()
        .expect("present actor")
}
pub(in crate::registry_progress) fn statement(
    m: &Metadata,
    p: &PrimaryInputs,
    old: &Bank,
) -> Vec<Val> {
    let c = &p.command;
    let w = &p.walk;
    let mut v = header("statement");
    v.extend(m.scope);
    v.extend(m.enrollment);
    v.extend(w.client);
    owner::append64(&mut v, w.call);
    owner::append64(&mut v, c.id);
    v.push(Val::from_usize(c.principal));
    v.extend(p.controllers[c.principal - 1]);
    v.extend(w.invocation);
    v.extend(w.sql);
    v.extend(own(old, p).snapshot);
    v.extend(owner::words(&p.mask));
    v.extend([
        Val::from_u8(c.mode),
        Val::from_u8(c.wait),
        Val::from_u8(c.offset),
        Val::from_u8(c.limit),
        Val::from_u8(c.projection),
    ]);
    v.extend(w.statement_salt);
    v.push(Val::ZERO);
    assert_eq!(v.len(), 96);
    v
}
fn progress(p: &PrimaryInputs, stmt: [Val; 4], o: &Progress) -> Vec<Val> {
    let mut v = header("progress");
    v.extend(stmt);
    owner::append64(&mut v, p.command.id);
    v.push(Val::from_usize(p.command.principal));
    owner::append64(&mut v, p.walk.call);
    owner::append64(&mut v, o.micro);
    v.push(Val::from_u8(o.cursor));
    bits(&mut v, o.visited);
    bits(&mut v, o.selected);
    v.push(Val::ONE);
    v.push(Val::from_u8(o.cursor));
    owner::append64(&mut v, o.holder);
    v.push(Val::from_u8(o.mode));
    owner::append64(&mut v, o.revision);
    v.extend(o.salt);
    v.extend([Val::ZERO; 4]);
    assert_eq!(v.len(), 48);
    v
}
fn command(m: &Metadata, p: &PrimaryInputs, old: &Bank) -> Vec<Val> {
    let c = &p.command;
    let mut v = domain("command").to_vec();
    v.push(Val::ONE);
    v.extend(m.context);
    v.extend(m.old);
    v.push(Val::from_usize(c.op));
    owner::append64(&mut v, c.id);
    v.push(Val::from_usize(c.principal));
    v.extend(p.controllers[c.principal - 1]);
    owner::append64(&mut v, old.revision);
    owner::append64(&mut v, own(old, p).sequence);
    v.extend(owner::words(&p.mask));
    v.extend([
        Val::from_u8(c.mode),
        Val::from_u8(c.wait),
        Val::from_u8(c.offset),
        Val::from_u8(c.limit),
        Val::from_u8(c.projection),
    ]);
    v.extend(c.name.map(Val::from_u32));
    v.extend(if c.op == 0 { m.parent } else { [Val::ZERO; 8] });
    v.push(Val::from_bool(c.abort));
    v.extend(p.salts[1]);
    v.push(Val::ZERO);
    assert_eq!(v.len(), 160);
    v
}
fn result(case: &Case) -> Vec<Val> {
    let m = &case.metadata;
    let p = &case.input;
    let o = &case.outcome;
    let old_p = own(&case.old, p).progress.unwrap_or([Val::ZERO; 4]);
    // End's selected-actor new progress is ZERO even when slot0 receives B.
    let new_p = if p.command.op == 6 {
        [Val::ZERO; 4]
    } else {
        own(&case.next, p).progress.unwrap_or([Val::ZERO; 4])
    };
    let mut v = domain("result").to_vec();
    v.push(Val::ONE);
    v.extend(m.context);
    v.extend(m.old);
    v.extend(m.next);
    v.extend(m.statement);
    v.extend([Val::from_u8(o.action), Val::from_u8(o.status)]);
    owner::append64(&mut v, p.command.id);
    v.extend([Val::from_u8(p.walk.cursor), Val::from_u8(o.cursor)]);
    bits(&mut v, o.visited);
    bits(&mut v, o.selected);
    bits(&mut v, o.block);
    v.extend(old_p);
    v.extend(new_p);
    owner::append64(&mut v, o.holder);
    v.push(Val::from_u8(o.holder_mode));
    owner::append64(&mut v, p.walk.call);
    owner::append64(&mut v, o.micro);
    v.extend(p.salts[2]);
    v.extend([Val::ZERO; 6]);
    assert_eq!(v.len(), 160);
    v
}
impl Case {
    /// Rebuild all downstream claims after typed hostile changes. No Evaluator,
    /// State::step, native trace or cached verdict supplies an expectation. The old
    /// historical P stays independently retained when original walk fields change.
    pub fn rebuild(&mut self) {
        let mut stmt = statement(&self.metadata, &self.input, &self.old);
        let root = owner::hash(&stmt);
        self.metadata.statement = if self.kind.predicate() {
            root
        } else {
            [Val::ZERO; 4]
        };
        stmt.fill(Val::ZERO);
        if self.kind.predicate() {
            let new_p = if self.outcome.status == 0 {
                let o = &self.outcome;
                let opening = Progress {
                    cursor: o.cursor,
                    micro: o.micro,
                    visited: o.visited,
                    selected: o.selected,
                    holder: o.holder,
                    mode: o.holder_mode,
                    revision: self.old.revision,
                    salt: self.input.walk.new_salt,
                };
                let mut v = progress(&self.input, root, &opening);
                let r = owner::hash(&v);
                v.fill(Val::ZERO);
                Some(r)
            } else {
                None
            };
            self.next.slots[0].as_mut().expect("A").progress = new_p;
        }
        self.input.banks = [
            self.old.words(&self.metadata, &self.input),
            self.next.words(&self.metadata, &self.input),
        ];
        self.metadata.old = owner::hash(&self.input.banks[0]);
        self.metadata.next = owner::hash(&self.input.banks[1]);
        let mut cmd = command(&self.metadata, &self.input, &self.old);
        self.metadata.command = owner::hash(&cmd);
        cmd.fill(Val::ZERO);
        let mut r = result(self);
        self.metadata.result = owner::hash(&r);
        r.fill(Val::ZERO);
    }
}
fn slot(id: u64, principal: usize, snapshot: [Val; 8]) -> Slot {
    Slot {
        id,
        principal,
        sequence: 1,
        failed: false,
        snapshot,
        held: [0; 4],
        frames: [None, None],
        progress: None,
    }
}
pub(in crate::registry_progress) fn case(kind: Kind) -> Case {
    let (mut metadata, mut input) = owner::public_case(kind.predicate());
    let snapshot = metadata.parent;
    let mut old = Bank {
        revision: 2,
        allocator: 2,
        slots: [Some(slot(1, 1, snapshot)), Some(slot(2, 2, snapshot))],
        salt: [Val::from_u8(6); 4],
    };
    input.command = CommandInput {
        op: if kind.predicate() { 1 } else { 6 },
        actor: Some(0),
        principal: 1,
        id: 1,
        mode: if kind.predicate() { 4 } else { 0 },
        wait: 0,
        offset: if kind.predicate() { 1 } else { 0 },
        limit: if kind.predicate() { 1 } else { 0 },
        projection: if kind.predicate() { 3 } else { 0 },
        ..CommandInput::default()
    };
    input.mask = if kind.predicate() { [255; 32] } else { [0; 32] };
    if !kind.predicate() {
        input.walk = WalkInput::default()
    }
    // These literal outcomes are hand expectations, not Evaluator/model results.
    let mut outcome = Outcome {
        action: if kind.predicate() { 0 } else { 8 },
        status: 1,
        cursor: 0,
        micro: u64::from(kind.predicate()),
        search: [false; 4],
        skipped: [false; 4],
        visited: [false; 4],
        selected: [false; 4],
        block: [false; 4],
        holder: 0,
        holder_mode: 0,
    };
    old.slots[1].as_mut().unwrap().held = [4, 0, 0, 0];
    let mut next = old.clone();
    next.revision = 3;
    next.slots[0].as_mut().unwrap().sequence = 2;
    match kind {
        Kind::ConflictBeforeOffset => {
            outcome.status = 0;
            outcome.search = [true, false, false, false];
            outcome.block = [true, false, false, false];
            outcome.holder = 2;
            outcome.holder_mode = 4;
            input.walk.new_salt = [Val::from_u8(9); 4];
        }
        Kind::SkipBeforeOffset => {
            input.command.wait = 2;
            outcome.cursor = 3;
            outcome.search = [true, true, true, false];
            outcome.skipped = [true, false, false, false];
            outcome.visited = [false, true, true, false];
            outcome.selected = [false, false, true, false];
            next.slots[0].as_mut().unwrap().held = [0, 4, 4, 0];
        }
        Kind::LimitZero => {
            input.command.limit = 0;
        }
        Kind::ResumePrefix => {
            // Original Park locked row0 and blocked on B row1. EndB changes only the
            // agreed old bank/revision; A/P and original snapshot/statement survive.
            old.revision = 3;
            old.slots[1] = None;
            let a = old.slots[0].as_mut().unwrap();
            a.sequence = 2;
            a.held = [4, 0, 0, 0];
            input.command.limit = 2;
            input.walk.cursor = 1;
            input.walk.micro = 1;
            input.walk.holder = 2;
            input.walk.mode = 4;
            input.walk.revision = 2;
            input.walk.old_salt = [Val::from_u8(9); 4];
            input.walk.visited = [true, false, false, false];
            input.walk.selected = [false; 4];
            metadata.parent[0] += Val::from_u8(17);
            metadata.context[16..24].copy_from_slice(&metadata.parent);
            let mut st = statement(&metadata, &input, &old);
            let sr = owner::hash(&st);
            st.fill(Val::ZERO);
            let w = &input.walk;
            let previous = Progress {
                cursor: w.cursor,
                micro: w.micro,
                visited: w.visited,
                selected: w.selected,
                holder: w.holder,
                mode: w.mode,
                revision: w.revision,
                salt: w.old_salt,
            };
            let mut pp = progress(&input, sr, &previous);
            let root = owner::hash(&pp);
            pp.fill(Val::ZERO);
            old.slots[0].as_mut().unwrap().progress = Some(root);
            next = old.clone();
            next.revision = 4;
            let a = next.slots[0].as_mut().unwrap();
            a.sequence = 3;
            a.held = [4, 4, 4, 0];
            a.progress = None;
            outcome.action = 1;
            outcome.cursor = 3;
            outcome.micro = 2;
            outcome.search = [false, true, true, false];
            outcome.visited = [true, true, true, false];
            outcome.selected = [false, true, true, false];
        }
        Kind::NoWaitLatest => {
            input.command.wait = 1;
            input.command.offset = 0;
            input.command.limit = 4;
            let a = old.slots[0].as_mut().unwrap();
            a.held = [4, 0, 4, 0];
            let name = [0x6162_6364; 8];
            a.frames = [
                Some(Frame {
                    name,
                    saved: [0; 4],
                }),
                Some(Frame {
                    name,
                    saved: [4, 0, 0, 0],
                }),
            ];
            old.slots[1].as_mut().unwrap().held = [0, 4, 0, 0];
            next = old.clone();
            next.revision = 3;
            let a = next.slots[0].as_mut().unwrap();
            a.sequence = 2;
            a.failed = true;
            a.held = [4, 0, 0, 0];
            outcome.status = 2;
            outcome.cursor = 1;
            outcome.search = [true, true, false, false];
            outcome.visited = [true, false, false, false];
            outcome.selected = [true, false, false, false];
            outcome.block = [false, true, false, false];
            outcome.holder = 2;
            outcome.holder_mode = 4;
        }
        Kind::EndCompact => {
            let b = old.slots[1].as_mut().unwrap();
            b.sequence = 9;
            b.snapshot = core::array::from_fn(|i| Val::from_u32(0x7700 + i as u32));
            b.held = [0, 4, 0, 0];
            b.frames[0] = Some(Frame {
                name: core::array::from_fn(|i| 21 + i as u32),
                saved: [0; 4],
            });
            // Unopened nonactor P is carried only under independently confirmed OldRoot
            // bootstrap/history induction; this fixture is not its provenance proof.
            b.progress = Some([31, 37, 41, 43].map(Val::from_u8));
            next = Bank {
                revision: 3,
                allocator: 2,
                slots: [old.slots[1].clone(), None],
                salt: old.salt,
            };
        }
    }
    let mut case = Case {
        kind,
        metadata,
        input,
        old,
        next,
        outcome,
    };
    case.rebuild();
    case
}
