//! Private witness origins. These never select constraints or confer authority.
use super::expr::{Node, Pool};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug)]
pub(super) enum CmdField {
    Op,
    Actor,
    Principal,
    Id,
    Name,
    Mode,
    Wait,
    Offset,
    Limit,
    Projection,
    Abort,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum WalkField {
    Client,
    Call,
    Invocation,
    Sql,
    Cursor,
    Micro,
    Holder,
    Mode,
    Revision,
    OldSalt,
    NewSalt,
    StatementSalt,
    Visited,
    Selected,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum SaltField {
    Enrollment,
    Command,
    Result,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Group {
    SourceWord,
    SourceSalt,
    SourceByte,
    Controller(usize),
    Bank(bool),
    Command(CmdField),
    Walk(WalkField),
    Salt(SaltField),
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Primary {
    pub group: Group,
    pub index: usize,
}
#[derive(Clone, Debug)]
pub(super) enum Recipe {
    Nonzero {
        out: usize,
        sum: usize,
        gate: usize,
    },
    Equality {
        out: [usize; 2],
        left: usize,
        right: usize,
    },
    Compare {
        out: [usize; 4],
        left: [usize; 2],
        right: [usize; 2],
        strict: bool,
        gate: usize,
    },
    Increment {
        out: [usize; 3],
        old: [usize; 2],
        gate: usize,
    },
    Small {
        out: [usize; 2],
        left: usize,
        right: usize,
    },
    Principal {
        out: [usize; 2],
        present: usize,
        code: usize,
    },
}
impl Recipe {
    pub fn targets(&self) -> Vec<usize> {
        match self {
            Self::Nonzero { out, .. } => vec![*out],
            Self::Equality { out, .. } | Self::Small { out, .. } | Self::Principal { out, .. } => {
                out.to_vec()
            }
            Self::Compare { out, .. } => out.to_vec(),
            Self::Increment { out, .. } => out.to_vec(),
        }
    }
}
#[derive(Default)]
pub(super) struct Origins {
    pub primary: BTreeMap<usize, Primary>,
    pub recipes: Vec<Recipe>,
    pub targets: BTreeMap<usize, usize>,
    pub errors: Vec<&'static str>,
    // Producer-only directions for existing equalities. No AIR/PP/wire change.
    pub derived: BTreeMap<usize, usize>,
}
impl Origins {
    pub fn primary(&mut self, id: usize, p: Primary) {
        if self.primary.insert(id, p).is_some() || self.targets.contains_key(&id) {
            self.errors.push("duplicate-primary");
        }
    }
    pub fn recipe(&mut self, r: Recipe) {
        let index = self.recipes.len();
        for id in r.targets() {
            if self.primary.contains_key(&id) || self.targets.insert(id, index).is_some() {
                self.errors.push("duplicate-recipe");
            }
        }
        self.recipes.push(r);
    }
    pub fn require_complete(&self, p: &Pool) -> Result<(), String> {
        if !self.errors.is_empty() {
            return Err(self.errors.join(","));
        }
        for (i, n) in p.nodes.iter().enumerate() {
            let origins = usize::from(self.primary.contains_key(&i))
                + usize::from(self.targets.contains_key(&i));
            if matches!(n, Node::Input(..)) {
                if origins != 1 {
                    return Err(format!("input-origin:{i}:{origins}"));
                }
            } else if origins != 0 {
                return Err(format!("origin-for-noninput:{i}"));
            }
        }
        if self.derived.len() != if p.predicate { 140 } else { 136 } {
            return Err("transition-direction-count".into());
        }
        for (&target, &value) in &self.derived {
            let allowed = self.primary.get(&target).is_some_and(|primary| {
                matches!(primary.group, Group::Bank(true))
                    && matches!(primary.index, 80..=189 | 194..=203)
            }) || matches!(p.nodes.get(target), Some(Node::Public(a)) if a.transition_root());
            if !allowed || target == value || value >= p.nodes.len() {
                return Err("transition-direction-origin".into());
            }
        }
        Ok(())
    }
}
pub(super) struct Built {
    pub pool: Pool,
    pub origins: Origins,
}
