//! Concrete fixed-five transcript inventory; no proof or crypto-model approval.
use super::{
    Expected,
    classical::{Error, Result},
};
use crate::fixed::Backend;
use bfv_ciphertext_formation::gold;
use bfv_hiding_stark::transcript::ArgumentManifest;

/// Inspect actual closed native metadata in SourceVersion, Role3, dense DATA,
/// Predicate Word, fused Query order. No caller supplies a numeric report,
/// separator, geometry or claimed verdict. No PP, private input or RNG is used.
/// The snapshots pin framing and geometry, not the shared-permutation reduction,
/// native proof validity, source authorization, fresh finality or SQL admission.
pub fn inspect(expected: &Expected) -> Result<[ArgumentManifest; 5]> {
    Ok([
        Backend::source_version_manifest(expected.word.source()).map_err(|_| Error::Metadata)?,
        Backend::two_lane_manifest(expected.data.source()).map_err(|_| Error::Metadata)?,
        gold::data::dense_transcript_manifest(expected.data.core_expected())
            .map_err(|_| Error::Metadata)?,
        super::super::probe::transcript_manifest(expected.word.role().predicate())
            .map_err(|_| Error::Metadata)?,
        gold::query::transcript_manifest(&expected.query).map_err(|_| Error::Metadata)?,
    ])
}
