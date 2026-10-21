//! Full fixed Formation AIR descriptor and native prescreen. No proving/admission API.
mod air;
mod assessment;
mod descriptor;
mod pp;

use air::ProgramAir;
use descriptor::Descriptor;
#[derive(Debug)]
pub(super) enum Error {
    Shape,
    Arithmetic,
    Binding,
    Resource,
    Security,
    Backend,
}
impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Shape => Self::Shape,
            crate::Error::Arithmetic => Self::Arithmetic,
            crate::Error::Binding => Self::Binding,
            crate::Error::Resource => Self::Resource,
            crate::Error::Backend => Self::Backend,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Formation AIR prescreen: {self:?}")
    }
}
impl std::error::Error for Error {}
pub(super) type Result<T> = std::result::Result<T, Error>;
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

/// Actual native symbolic/security/resource inspection only. It produces no proof,
/// success token, mathematical input certificate or protocol/SQL permission.
pub(super) fn inspect(
    original: &crate::statement::Statement,
    pair: Option<&registry200_proof::two_lane_encoding::wire::VerifiedPair>,
) -> Result<assessment::Assessment> {
    let descriptor = if let Some(pair) = pair {
        let descriptor = Descriptor::from_claims(
            original,
            pair.source().statement().clone(),
            pair.private_mask().statement().clone(),
        )?;
        descriptor.require_pair(pair)?;
        descriptor
    } else {
        Descriptor::unverified_geometry(original)?
    };
    let air = ProgramAir::new(descriptor)?;
    assessment::assess(&air)
}
