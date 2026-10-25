mod air;
mod assessment;
mod dense_backend;
mod descriptor;
mod pp;
#[cfg(test)]
mod public_image_ring;
#[cfg(test)]
mod research_hash;
use super::{Error, Result};
pub(super) use air::ProgramAir;
pub(super) use assessment::{Assessment, assess};
use descriptor::Descriptor;
pub(super) const HEIGHT: usize = 8192;
pub(super) const LOG_HEIGHT: usize = 13;
pub(super) const DEGREE_BITS: usize = 14;
pub(super) const WIDTH: usize = 512;
pub(super) const PP_WIDTH: usize = 272;
pub(super) const PUBLIC_VALUES: usize = 36;
pub(super) const PORTS: usize = 128;
pub(super) const RANGE_FIRST: usize = 4352;
pub(super) const SOURCE_FIRST: usize = 6400;
pub(super) const MASK_FIRST: usize = 6914;
pub(super) const CS_FIRST: usize = 7428;
pub(super) const PADDING_FIRST: usize = 7494;
pub(super) const BITS: usize = 128;
pub(super) const CHECKPOINT: usize = 496;
pub(super) const ACCUMULATOR: usize = 508;
pub(super) const BUS: &str = "dcs/gold-formation-full-program/v1/node-value";

#[cfg(test)]
mod data_snapshot_capture;

pub(super) mod dense_data_inventory;
mod range_equations;

#[cfg(test)]
mod role_coefficient_inventory;

pub(in crate::gold) mod query_formation;
