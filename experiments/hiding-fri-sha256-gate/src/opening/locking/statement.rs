//! Independently pinned public inputs and fixed, domain-separated encodings.
use super::{
    air,
    trace::{Registry, Witness},
};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{commitment, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};

pub(super) const PUBLIC_VALUES: usize = 116;
pub(super) const OLD: usize = 96;
pub(super) const PLAN: usize = 100;
pub(super) const RETURNED: usize = 104;
pub(super) const OWNED: usize = 108;
pub(super) const NEW: usize = 112;
pub(in crate::opening) const REGISTRY_DOMAIN: [u8; 16] = *b"DCS/LKREG/N4/v1!";
pub(super) const PLAN_DOMAIN: [u8; 16] = *b"DCS/LKPLAN/N4/v1";
pub(super) const RETURN_DOMAIN: [u8; 16] = *b"DCS/LKRET/N4/v1!";
pub(super) const OWNED_DOMAIN: [u8; 16] = *b"DCS/LKOWN/N4/v1!";

/// PUBLIC expected context supplied independently of the proposed proof/witness.
/// This research caller does not establish controller authorization or finality.
#[derive(Clone, PartialEq, Eq)]
enum SourceContract {
    CanonicalRequest,
    CertifiedState { query_request: [u8; 32] },
}

#[derive(Clone)]
pub(in crate::opening) struct Expected {
    contract: SourceContract,
    pub(in crate::opening) source: source::Statement,
    pub(in crate::opening) genesis: [u8; 32],
    pub(in crate::opening) parent: [u8; 32],
    pub(in crate::opening) old: [Val; 4],
    pub(in crate::opening) plan: [Val; 4],
}
impl Expected {
    pub(in crate::opening) fn checked(
        source: &source::Statement,
        genesis: [u8; 32],
        parent: [u8; 32],
        old: [u8; 32],
        plan: [u8; 32],
    ) -> Result<Self, Error> {
        if source.relation != crate::opening::Relation::CanonicalIndex {
            return Err(Error::Shape);
        }
        Ok(Self {
            contract: SourceContract::CanonicalRequest,
            source: source.clone(),
            genesis,
            parent,
            old: source::decode_digest(old)?,
            plan: source::decode_digest(plan)?,
        })
    }
    pub(in crate::opening) fn for_state(
        state: &crate::opening::state::StateStatement,
        request: [u8; 32],
        genesis: [u8; 32],
        parent: [u8; 32],
        old: [u8; 32],
        plan: [u8; 32],
    ) -> Result<Self, Error> {
        let out = Self {
            contract: SourceContract::CertifiedState {
                query_request: request,
            },
            source: state.source().clone(),
            genesis,
            parent,
            old: source::decode_digest(old)?,
            plan: source::decode_digest(plan)?,
        };
        out.require_contract()?;
        Ok(out)
    }
    fn require_contract(&self) -> Result<(), Error> {
        use crate::opening::Relation;
        match self.contract {
            SourceContract::CanonicalRequest
                if self.source.relation == Relation::CanonicalIndex =>
            {
                Ok(())
            }
            SourceContract::CertifiedState { .. }
                if self.source.relation == Relation::StateCertificate
                    && self.source.request == crate::opening::state::version_tag(&self.source) =>
            {
                Ok(())
            }
            _ => Err(Error::Shape),
        }
    }
    pub(in crate::opening) fn kind(&self) -> Kind {
        match self.contract {
            SourceContract::CanonicalRequest => Kind::LockingSelection,
            SourceContract::CertifiedState { .. } => Kind::VersionLockingSelection,
        }
    }
    pub(in crate::opening) fn request(&self) -> &[u8; 32] {
        match &self.contract {
            SourceContract::CanonicalRequest => &self.source.request,
            SourceContract::CertifiedState { query_request } => query_request,
        }
    }
    pub(in crate::opening) fn plan_domain(&self) -> &[u8; 16] {
        match self.contract {
            SourceContract::CanonicalRequest => &PLAN_DOMAIN,
            SourceContract::CertifiedState { .. } => &crate::opening::state::locking::PLAN_DOMAIN,
        }
    }
    pub(in crate::opening) fn output_domain(&self, owned: bool) -> &[u8; 16] {
        match (&self.contract, owned) {
            (SourceContract::CanonicalRequest, true) => &OWNED_DOMAIN,
            (SourceContract::CanonicalRequest, false) => &RETURN_DOMAIN,
            (SourceContract::CertifiedState { .. }, true) => {
                &crate::opening::state::locking::OWNED_DOMAIN
            }
            (SourceContract::CertifiedState { .. }, false) => {
                &crate::opening::state::locking::RETURN_DOMAIN
            }
        }
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(in crate::opening) expected: Expected,
    pub(in crate::opening) returned: [Val; 4],
    pub(in crate::opening) owned: [Val; 4],
    pub(in crate::opening) next: [Val; 4],
}
impl Statement {
    pub(in crate::opening) fn checked(
        expected: &Expected,
        returned: [u8; 32],
        owned: [u8; 32],
        next: [u8; 32],
    ) -> Result<Self, Error> {
        expected.require_contract()?;
        Ok(Self {
            expected: expected.clone(),
            returned: source::decode_digest(returned)?,
            owned: source::decode_digest(owned)?,
            next: source::decode_digest(next)?,
        })
    }
    pub(in crate::opening) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        self.expected.require_contract()?;
        expected.require_contract()?;
        if self.expected.contract != expected.contract
            || self.expected.source.relation != expected.source.relation
            || self.expected.source.request != expected.source.request
            || self.expected.source.heads != expected.source.heads
            || self.expected.source.packets != expected.source.packets
            || self.expected.source.key_commitment != expected.source.key_commitment
            || self.expected.source.open_commitment != expected.source.open_commitment
            || self.expected.genesis != expected.genesis
            || self.expected.parent != expected.parent
            || self.expected.old != expected.old
            || self.expected.plan != expected.plan
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening) fn context(&self) -> Vec<Val> {
        context(&self.expected)
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        self.expected.kind()
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Locking(Box::new(air::LockingAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        self.context()
            .into_iter()
            .chain(self.expected.old)
            .chain(self.expected.plan)
            .chain(self.returned)
            .chain(self.owned)
            .chain(self.next)
            .collect()
    }
}
pub(in crate::opening) fn context(e: &Expected) -> Vec<Val> {
    source::words(&profile_digest(e.kind()))
        .chain(source::words(e.request()))
        .chain(e.source.heads.iter().flat_map(|h| source::words(h)))
        .chain(e.source.key_commitment)
        .chain(e.source.open_commitment)
        .chain(source::words(&e.genesis))
        .chain(source::words(&e.parent))
        .collect()
}
pub(in crate::opening) fn registry_profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/private-effective-registry/N4-T2/v1");
    h.update(b"P2-12/rate8/overwrite/digest4/fixed112/old-new-same-domain");
    h.update(
        b"u32-id-sorted-positive/u32-seq-positive/u32-revision/controller256-nonzero/failed-bit",
    );
    h.update(
        b"four-ordinal-RowIds/two-existing-transactions/absent-K-S-N-U/candidate-counter-admission",
    );
    h.finalize().into()
}
/// Stable before the request: no parent/request/current heads/opening/plan here.
pub(in crate::opening) fn registry_fields(
    e: &Expected,
    w: &Witness,
    r: &Registry,
    salt: [Val; 4],
) -> Vec<Val> {
    registry_fields_opening(
        &RegistryScope {
            genesis: &e.genesis,
            source: &e.source,
            table: &w.plan.table,
            row_ids: w.plain[2220..2348].try_into().unwrap(),
        },
        r,
        salt,
    )
}
/// Private stable registry opening shared with the initialization relation.
/// This scope deliberately contains no query plan, request or current parent.
pub(in crate::opening) struct RegistryScope<'a> {
    pub(in crate::opening) genesis: &'a [u8; 32],
    pub(in crate::opening) source: &'a source::Statement,
    pub(in crate::opening) table: &'a [u8; 32],
    pub(in crate::opening) row_ids: &'a [u8; 128],
}
pub(in crate::opening) fn registry_fields_opening(
    scope: &RegistryScope<'_>,
    r: &Registry,
    salt: [Val; 4],
) -> Vec<Val> {
    let mut out: Vec<_> = source::words(&REGISTRY_DOMAIN)
        .chain([Val::ONE])
        .chain(source::words(&registry_profile()))
        .chain(source::words(scope.genesis))
        .chain(source::words(&scope.source.heads[0][8..40]))
        .chain(scope.source.key_commitment)
        .chain(source::words(scope.table))
        .collect();
    out.extend(source::words(scope.row_ids));
    out.extend([Val::from_u8(2), Val::from_u8(4), Val::from_u32(r.revision)]);
    for tx in &r.tx {
        out.push(Val::from_u32(tx.id));
        out.extend(source::words(&tx.controller));
        out.extend([Val::from_u32(tx.sequence), Val::from_bool(tx.failed)]);
        out.extend(tx.held.map(Val::from_u8));
    }
    out.extend(salt);
    out.extend([Val::ZERO; 2]);
    assert_eq!(out.len(), 112);
    out
}
/// Client-owned commitment opening, not controller authorization or a registry.
pub(in crate::opening) struct PlanOpening {
    pub(in crate::opening) table: [u8; 32],
    pub(in crate::opening) transaction: u32,
    pub(in crate::opening) controller: [u8; 32],
    pub(in crate::opening) sequence: u32,
    pub(in crate::opening) revision: u32,
    pub(in crate::opening) salt: [Val; 4],
}
pub(in crate::opening) fn plan_fields(e: &Expected, w: &Witness) -> Vec<Val> {
    let tx = &w.old.tx[usize::from(w.plan.actor)];
    plan_fields_opening(
        e,
        &w.plan,
        &PlanOpening {
            table: w.plan.table,
            transaction: tx.id,
            controller: tx.controller,
            sequence: tx.sequence,
            revision: w.old.revision,
            salt: w.salts[2],
        },
    )
}
pub(in crate::opening) fn plan_fields_opening(
    e: &Expected,
    plan: &super::trace::Plan,
    opening: &PlanOpening,
) -> Vec<Val> {
    let mut out: Vec<_> = source::words(e.plan_domain())
        .chain([Val::ONE])
        .chain(context(e))
        .chain(e.old)
        .chain(source::words(&opening.table))
        .chain(source::words(&plan.mask))
        .chain([Val::from_u32(opening.transaction)])
        .chain(source::words(&opening.controller))
        .chain([
            Val::from_u32(opening.sequence),
            Val::from_u32(opening.revision),
            Val::from_u8(plan.mode),
            Val::from_u8(plan.wait),
            Val::from_u8(plan.offset),
            Val::from_u8(plan.limit),
            Val::from_u8(plan.projection),
        ])
        .chain(opening.salt)
        .collect();
    out.extend([Val::ZERO; 3]);
    assert_eq!(out.len(), 144);
    out
}
pub(in crate::opening) fn output_fields(
    s: &Statement,
    w: &Witness,
    owned: bool,
) -> Result<Vec<Val>, Error> {
    let result = w.walk()?;
    let mut out: Vec<_> = source::words(s.expected.output_domain(owned))
        .chain([Val::ONE])
        .chain(s.context())
        .chain(s.expected.old)
        .chain(s.expected.plan)
        .chain(s.next)
        .chain([Val::from_u8(4), Val::from_u8(result.outcome)])
        .chain(w.salts[if owned { 4 } else { 5 }])
        .collect();
    let kept = if owned { result.visit } else { result.returned };
    let rows: Vec<_> = (0..4).filter(|i| result.outcome == 0 && kept[*i]).collect();
    for slot in 0..4 {
        if let Some(&i) = rows.get(slot) {
            out.extend([Val::ONE, Val::from_usize(i)]);
            let id = source::words(&w.plain[2220 + i * 32..2252 + i * 32]);
            if owned {
                out.extend(id);
                out.extend([
                    Val::from_u8(w.old.tx[usize::from(w.plan.actor)].held[i]),
                    Val::from_u8(result.next.tx[usize::from(w.plan.actor)].held[i]),
                ]);
            } else {
                out.extend([
                    Val::from_u8(w.plain[3 * i]),
                    Val::from_u16(u16::from_le_bytes([w.plain[3 * i + 1], w.plain[3 * i + 2]])),
                ]);
                out.extend(id);
            }
        } else {
            out.extend([Val::ZERO; 12]);
        }
    }
    out.push(Val::ZERO);
    assert_eq!(out.len(), 168);
    Ok(out)
}
pub(in crate::opening) fn encoded(d: [Val; 4]) -> [u8; 32] {
    use p3_field::PrimeField64;
    let mut out = [0; 32];
    for (i, v) in d.into_iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&v.as_canonical_u64().to_le_bytes());
    }
    out
}
pub(in crate::opening) fn proposed(e: &Expected, w: &Witness) -> Result<Statement, Error> {
    let result = w.walk()?;
    let salt = if result.outcome == 0 {
        w.salts[3]
    } else {
        w.salts[1]
    };
    let next = commitment::digest(&registry_fields(e, w, &result.next, salt));
    let mut s = Statement::checked(e, [0; 32], [0; 32], encoded(next))?;
    s.owned = commitment::digest(&output_fields(&s, w, true)?);
    s.returned = commitment::digest(&output_fields(&s, w, false)?);
    Ok(s)
}
