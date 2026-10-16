//! Public verifier context and independently authorized private-plan commitment.
use super::{PLAN_DOMAIN, SELECT_DOMAIN, VERSION, air, trace::Witness};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{Relation, commitment, statement as source};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;

pub(super) const OPEN: usize = 76;
pub(super) const PLAN: usize = 80;
pub(super) const SELECTED: usize = 84;
pub(super) const PUBLIC_VALUES: usize = 88;

/// This private research descriptor is the client compiler's final TRUE set,
/// never SQL text, a peer predicate, a typed/nullable plan or a projected answer.
pub(super) struct Plan {
    pub(super) table: [u8; 32],
    pub(super) mask: [u8; 32],
    pub(super) projection: u8,
    pub(super) limit: u8,
}
impl Plan {
    pub(super) fn new(
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
pub(super) struct Statement {
    pub(super) source: source::Statement,
    pub(super) plan: [Val; 4],
    pub(super) selected: [Val; 4],
}
impl Statement {
    pub(super) fn checked(
        source: &source::Statement,
        expected_plan: [u8; 32],
        selected: [u8; 32],
    ) -> Result<Self, Error> {
        if source.relation != Relation::CanonicalIndex {
            return Err(Error::Shape);
        }
        Ok(Self {
            source: source.clone(),
            plan: source::decode_digest(expected_plan)?,
            selected: source::decode_digest(selected)?,
        })
    }
    pub(super) fn require_source(&self, expected: &source::Statement) -> Result<(), Error> {
        if expected.relation != Relation::CanonicalIndex
            || self.source.public_values() != expected.public_values()
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn context(&self) -> Vec<Val> {
        source::words(&profile_digest(Kind::SelectionOpening))
            .chain(source::words(&self.source.request))
            .chain(self.source.heads.iter().flat_map(|h| source::words(h)))
            .chain(self.source.key_commitment)
            .chain(self.source.open_commitment)
            .collect()
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::SelectionOpening
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

pub(super) fn plan_fields(statement: &Statement, witness: &Witness) -> Vec<Val> {
    source::words(&PLAN_DOMAIN)
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
pub(super) fn selected_fields(statement: &Statement, witness: &Witness) -> Vec<Val> {
    let mut fields: Vec<_> = source::words(&SELECT_DOMAIN)
        .chain([Val::from_u32(VERSION)])
        .chain(source::words(&profile_digest(Kind::SelectionOpening)))
        .chain(source::words(&statement.source.request))
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

pub(super) fn commitments(
    source: &source::Statement,
    witness: &Witness,
) -> Result<Statement, Error> {
    let mut statement = Statement::checked(source, [0; 32], [0; 32])?;
    statement.plan = commitment::digest(&plan_fields(&statement, witness));
    statement.selected = commitment::digest(&selected_fields(&statement, witness));
    Ok(statement)
}
