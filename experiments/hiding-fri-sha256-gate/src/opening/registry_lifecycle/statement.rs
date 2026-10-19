//! Experimental trait adaptation; all private field builders are owned by Core.
use crate::backend::Val;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
#[cfg(test)]
pub(super) use registry200_proof::lifecycle::circuit::commitment::result_fields;
pub(super) use registry200_proof::lifecycle::circuit::commitment::{
    CommandFieldsOpening, command_fields, command_fields_opening, enrollment_fields,
    registry_fields,
};
#[cfg(test)]
pub(super) use registry200_proof::lifecycle::statement::registry_profile;
pub(super) use registry200_proof::lifecycle::statement::{
    Expected, Phase, RESULT_DOMAIN, Statement, digest, encoded,
};
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        if self.expected.is_bootstrap() {
            Kind::RegistryLifecycleBootstrap
        } else {
            Kind::RegistryLifecycle
        }
    }
    fn public_values(&self) -> Vec<Val> {
        Statement::values(self)
    }
    fn air(&self) -> PrimitiveAir {
        if self.expected.is_bootstrap() {
            PrimitiveAir::LifecycleBootstrap(Box::new(super::bootstrap::BootstrapAir::new(self)))
        } else {
            PrimitiveAir::Lifecycle(Box::new(super::air::LifecycleAir::new(self)))
        }
    }
}
