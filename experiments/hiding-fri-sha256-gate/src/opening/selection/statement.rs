//! Public verifier context and independently authorized private-plan commitment.
use super::{PLAN_DOMAIN, SELECT_DOMAIN, VERSION, air, trace::Witness};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{Relation, commitment, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;

pub(in crate::opening) const OPEN: usize = 76;
pub(in crate::opening) const PLAN: usize = 80;
pub(in crate::opening) const SELECTED: usize = 84;
pub(in crate::opening) const PUBLIC_VALUES: usize = 88;

/// This private research descriptor is the client compiler's final TRUE set,
/// never SQL text, a peer predicate, a typed/nullable plan or a projected answer.
pub(in crate::opening) struct Plan {
    pub(in crate::opening) table: [u8; 32],
    pub(in crate::opening) mask: [u8; 32],
    pub(in crate::opening) projection: u8,
    pub(in crate::opening) limit: u8,
}
impl Plan {
    pub(in crate::opening) fn new(
        table: [u8; 32],
        mask: [u8; 32],
        projection: u8,
        limit: Option<usize>,
    ) -> Result<Self, Error> {
        if table == [0; 32] || projection > 3 {
            return Err(Error::Shape);
        }
        Ok(Self {
            table,
            mask,
            projection,
            // All larger LIMIT values and None are equivalent on exactly N4.
            limit: limit.unwrap_or(4).min(4) as u8,
        })
    }
}

/// Contains PUBLIC values only. Expected C_plan belongs to the authorized client,
/// not to the prover. Neither constructor nor selection-only verification confers
/// source authority: verify_composite must check the canonical source proof first.
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(in crate::opening) source: source::Statement,
    pub(in crate::opening) plan: [Val; 4],
    pub(in crate::opening) selected: [Val; 4],
    query_request: Option<[u8; 32]>,
}
impl Statement {
    pub(in crate::opening) fn checked(
        source: &source::Statement,
        expected_plan: [u8; 32],
        selected: [u8; 32],
    ) -> Result<Self, Error> {
        if source.relation != Relation::CanonicalIndex {
            return Err(Error::Shape);
        }
        Ok(Self {
            source: source.clone(),
            query_request: None,
            plan: source::decode_digest(expected_plan)?,
            selected: source::decode_digest(selected)?,
        })
    }
    pub(in crate::opening) fn for_state(
        state: &crate::opening::state::StateStatement,
        request: [u8; 32],
        expected_plan: [u8; 32],
        selected: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            source: state.source().clone(),
            query_request: Some(request),
            plan: source::decode_digest(expected_plan)?,
            selected: source::decode_digest(selected)?,
        })
    }
    pub(in crate::opening) fn request(&self) -> [u8; 32] {
        self.query_request.unwrap_or(self.source.request)
    }
    pub(super) fn plan_domain(&self) -> [u8; 16] {
        if self.query_request.is_some() {
            crate::opening::state::PLAN_DOMAIN
        } else {
            PLAN_DOMAIN
        }
    }
    pub(super) fn selected_domain(&self) -> [u8; 16] {
        if self.query_request.is_some() {
            crate::opening::state::SELECT_DOMAIN
        } else {
            SELECT_DOMAIN
        }
    }
    pub(in crate::opening) fn require_source(
        &self,
        expected: &source::Statement,
    ) -> Result<(), Error> {
        if expected.relation
            != (if self.query_request.is_some() {
                Relation::StateCertificate
            } else {
                Relation::CanonicalIndex
            })
            || self.source.public_values() != expected.public_values()
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening) fn context(&self) -> Vec<Val> {
        source::words(&profile_digest(self.kind()))
            .chain(source::words(&self.request()))
            .chain(self.source.heads.iter().flat_map(|h| source::words(h)))
            .chain(self.source.key_commitment)
            .chain(self.source.open_commitment)
            .collect()
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        if self.query_request.is_some() {
            Kind::VersionSelection
        } else {
            Kind::SelectionOpening
        }
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Selection(Box::new(air::SelectionAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        self.context()
            .into_iter()
            .chain(self.plan)
            .chain(self.selected)
            .collect()
    }
}

pub(in crate::opening) fn plan_fields(statement: &Statement, witness: &Witness) -> Vec<Val> {
    source::words(&statement.plan_domain())
        .chain([Val::from_u32(VERSION)])
        .chain(statement.context())
        .chain(source::words(&witness.plan.table))
        .chain(source::words(&witness.plan.mask))
        .chain([
            Val::from_u8(witness.plan.limit),
            Val::from_u8(witness.plan.projection),
        ])
        .chain(witness.salts[1])
        .chain([Val::ZERO; 5])
        .collect()
}
pub(in crate::opening) fn selected_fields(statement: &Statement, witness: &Witness) -> Vec<Val> {
    let mut fields: Vec<_> = source::words(&statement.selected_domain())
        .chain([Val::from_u32(VERSION)])
        .chain(source::words(&profile_digest(statement.kind())))
        .chain(source::words(&statement.request()))
        .chain(statement.source.open_commitment)
        .chain(statement.plan)
        .chain([Val::from_u8(4)])
        .chain(witness.salts[2])
        .collect();
    let retained: Vec<_> = (0..4)
        .filter(|i| {
            let age = witness.plain[3 * i];
            witness.plan.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0
        })
        .take(witness.plan.limit as usize)
        .collect();
    for slot in 0..4 {
        if let Some(&i) = retained.get(slot) {
            fields.extend([
                Val::ONE,
                Val::from_usize(i),
                Val::from_u8(witness.plain[i * 3]),
                Val::from_u16(u16::from_le_bytes([
                    witness.plain[i * 3 + 1],
                    witness.plain[i * 3 + 2],
                ])),
            ]);
            fields.extend(source::words(
                &witness.plain[12 + 2208 + i * 32..12 + 2240 + i * 32],
            ));
        } else {
            fields.extend([Val::ZERO; 12]);
        }
    }
    fields.extend([Val::ZERO; 6]);
    assert_eq!(fields.len(), 88);
    fields
}

pub(in crate::opening) fn commitments(
    source: &source::Statement,
    witness: &Witness,
) -> Result<Statement, Error> {
    let mut statement = Statement::checked(source, [0; 32], [0; 32])?;
    statement.plan = commitment::digest(&plan_fields(&statement, witness));
    statement.selected = commitment::digest(&selected_fields(&statement, witness));
    Ok(statement)
}
