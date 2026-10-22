//! Independently derived PUBLIC values. No private mask/program/salt becomes PV.
use super::{
    Metadata, Val,
    expr::{Builder, E},
};
use p3_field::PrimeCharacteristicRing;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Group {
    SourcePrefix,
    SourceOpen,
    RegistryHeader,
    EnrollmentHeader,
    Context,
    Scope,
    Parent,
    Enrollment,
    Old,
    Command,
    Statement,
    Next,
    Result,
    BlindSql,
}
pub(super) const GROUPS: [Group; 14] = [
    Group::SourcePrefix,
    Group::SourceOpen,
    Group::RegistryHeader,
    Group::EnrollmentHeader,
    Group::Context,
    Group::Scope,
    Group::Parent,
    Group::Enrollment,
    Group::Old,
    Group::Command,
    Group::Statement,
    Group::Next,
    Group::Result,
    Group::BlindSql,
];
pub(super) const COUNT: usize = 309;
impl Group {
    pub fn len(self) -> usize {
        match self {
            Self::SourcePrefix => 83,
            Self::RegistryHeader | Self::EnrollmentHeader => 33,
            Self::Context => 100,
            Self::Scope => 16,
            Self::Parent | Self::BlindSql => 8,
            _ => 4,
        }
    }
    pub fn offset(self) -> usize {
        let mut n = 0;
        for g in GROUPS {
            if g == self {
                return n;
            }
            n += g.len();
        }
        unreachable!("closed group")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Address {
    group: Group,
    index: usize,
}
impl Address {
    pub fn transition_root(self) -> bool {
        matches!(
            self.group,
            Group::Old | Group::Command | Group::Statement | Group::Next | Group::Result
        )
    }
    pub fn new(group: Group, index: usize) -> Self {
        assert!(index < group.len(), "closed public address");
        Self { group, index }
    }
    pub fn ordinal(self) -> usize {
        self.group.offset() + self.index
    }
    pub fn from_ordinal(n: usize) -> Self {
        assert!(n < COUNT);
        for g in GROUPS {
            let start = g.offset();
            if n < start + g.len() {
                return Self::new(g, n - start);
            }
        }
        unreachable!("complete309")
    }
}
pub(super) fn array<const N: usize>(b: &Builder, g: Group) -> [E<'_>; N] {
    assert_eq!(g.len(), N);
    core::array::from_fn(|i| b.public(Address::new(g, i)))
}
/// Metadata only; deriving this tuple does not verify Source or grant freshness.
/// This type is not deserialized or minted by the proof frame.
pub(super) struct Expected {
    values: [Val; COUNT],
}
impl Expected {
    pub fn checked(m: &Metadata) -> Result<Self, String> {
        m.source
            .statement()
            .reaudit()
            .map_err(|_| "public-source-shape")?;
        let mut values = [Val::ZERO; COUNT];
        for g in GROUPS {
            let start = g.offset();
            let out = &mut values[start..start + g.len()];
            match g {
                Group::SourcePrefix => out.copy_from_slice(
                    &crate::source::commitment::prefix(m.source.statement(), [Val::ZERO; 4])[..83],
                ),
                Group::SourceOpen => out.copy_from_slice(&m.source.statement().open_commitment),
                Group::RegistryHeader => out.copy_from_slice(&m.registry_header),
                Group::EnrollmentHeader => out.copy_from_slice(&m.enrollment_header),
                Group::Context => out.copy_from_slice(&m.context),
                Group::Scope => out.copy_from_slice(&m.scope),
                Group::Parent => out.copy_from_slice(&m.parent),
                Group::Enrollment => out.copy_from_slice(&m.enrollment),
                Group::Old => out.copy_from_slice(&m.old),
                Group::Command => out.copy_from_slice(&m.command),
                Group::Statement => out.copy_from_slice(&m.statement),
                Group::Next => out.copy_from_slice(&m.next),
                Group::Result => out.copy_from_slice(&m.result),
                Group::BlindSql => out.copy_from_slice(&m.blind_sql),
            }
        }
        Ok(Self { values })
    }
    pub fn values(&self) -> &[Val; COUNT] {
        &self.values
    }
    pub fn value(&self, a: Address) -> Val {
        self.values[a.ordinal()]
    }
}
