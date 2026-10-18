//! Local Kind adapter over the one shared WriteImage mathematical claim.
use crate::{
    backend::Val,
    primitive::{Kind, PrimitiveAir, PublicStatement},
};
pub(in crate::opening::registry_lifecycle) use registry200_proof::write::statement::{
    Expected, Parent, Statement,
};
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::RegistryWriteImage
    }
    fn public_values(&self) -> Vec<Val> {
        Statement::values(self)
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::WriteImage(Box::new(registry200_proof::write::air::WriteAir::new(self)))
    }
}
