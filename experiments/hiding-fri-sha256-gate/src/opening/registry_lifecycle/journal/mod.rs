//! Owner-authorized Registry200 Journal research. No controller delegation/live grant.
use registry200_journal::control;
#[cfg(test)]
mod encoding_tests;
mod fixture;
mod formation_scenario;
mod owner;
mod peer_control;
mod projection_context;
mod projection_scenario;
use registry200_journal::request;
#[cfg(test)]
mod tests;
use control::{Application, Control};
use request::{Operation, Request};
#[cfg(test)]
use version_journal::Genesis;
use version_journal::{Error, Hash, Result};

use registry200_journal::RegistryVerifier as PrivateVerifier;
fn backend<T>(value: std::result::Result<T, crate::backend::Error>) -> Result<T> {
    value.map_err(|_| Error::RejectedComputationProof)
}
pub(super) fn gate(mode: &str) -> std::result::Result<(), crate::backend::Error> {
    fixture::gate(mode)
}

pub(super) use formation_scenario::EncodingProduct as FormationEncodingProduct;
pub(super) fn formation_input(
    limit: u8,
) -> std::result::Result<FormationEncodingProduct, crate::backend::Error> {
    formation_scenario::produce(limit)
}

#[cfg(test)]
pub(super) fn formation_input_with_alternate(
    limit: u8,
) -> std::result::Result<FormationEncodingProduct, crate::backend::Error> {
    formation_scenario::produce_with_alternate(limit)
}

pub(super) use projection_context::ProjectionContext;

pub(super) use projection_scenario::ProjectionHistory;
pub(super) fn projection_input(
    limit: u8,
    other_limit: u8,
) -> std::result::Result<(ProjectionHistory, FormationEncodingProduct), crate::backend::Error> {
    projection_scenario::produce(limit, other_limit)
}

pub(super) fn peer_control_gate(
    mode: &str,
    executable: Option<&std::path::Path>,
) -> std::result::Result<(), crate::backend::Error> {
    peer_control::gate(mode, executable)
}
