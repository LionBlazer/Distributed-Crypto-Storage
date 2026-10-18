//! Experiment Kind policy around the actual shared public claim and AIR.
use crate::backend::Val;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use registry200_proof::source::{Relation, Statement, air::OpeningAir};
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        match self.relation {
            Relation::Bytes => Kind::PairOpening,
            Relation::CanonicalIndex => Kind::CanonicalIndexOpening,
            Relation::PackedCanonicalIndex => Kind::PackedCanonicalIndexOpening,
            Relation::FactorizedPackedCanonicalIndex => Kind::FactorizedPackedCanonicalIndexOpening,
            Relation::StateCertificate => Kind::StateCertificate,
        }
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Opening(Box::new(OpeningAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        Statement::values(self)
    }
}
