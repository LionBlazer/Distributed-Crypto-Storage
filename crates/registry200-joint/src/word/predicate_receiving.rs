//! One exact immutable native DATA theorem; fresh per-query proofs on every call.
use super::{Error, Result, predicate::BorrowedPredicate};
use registry200_proof::{
    registry_progress::word::{self, read},
    source::version::SourceVersionExpected,
    two_lane_encoding::data_formation::hash::CheckedData,
};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct PredicateReceiver {
    retained: Mutex<Option<RetainedData>>,
}
struct RetainedData {
    theorem: CheckedData,
    frames: [Box<[u8]>; 3],
}
impl RetainedData {
    fn matches(&self, expected: &read::Expected, evidence: &read::Evidence<'_>) -> bool {
        self.theorem
            .require_expected(expected.data_expected())
            .is_ok()
            && self
                .frames
                .iter()
                .zip([evidence.state, evidence.child, evidence.data])
                .all(|(original, incoming)| original.as_ref() == incoming)
    }
}
impl PredicateReceiver {
    pub(super) fn append_transport(
        &self,
        source: &SourceVersionExpected,
        compact: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let parsed = super::predicate::transport::Borrowed::parse(source, compact)?;
        let retained = self
            .retained
            .lock()
            .map_err(|_| Error::RejectedComputationProof)?;
        let original = retained.as_ref().ok_or(Error::MissingComputationProof)?;
        original
            .theorem
            .require_expected(parsed.data_expected())
            .map_err(|_| Error::RejectedComputationProof)?;
        parsed.append_full(
            original.frames.each_ref().map(|frame| frame.as_ref()),
            output,
        )
    }

    pub(super) fn check(
        &self,
        source: &SourceVersionExpected,
        word: &word::Expected,
        packet: &[u8],
    ) -> Result<()> {
        // Parse and bind the complete original candidate on every invocation.
        // The bounded packet also bounds the total three retained frame sizes.
        let parsed = BorrowedPredicate::parse(source, packet)?;
        let expected = parsed.expected(word)?;
        let evidence = parsed.evidence();
        // Serialize retention in this verifier, bounding concurrent miss setup.
        // A poisoned mutex fails closed; no query verdict or import is retained.
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| Error::RejectedComputationProof)?;
        // A new complete query gets independently reconstructed PUBLIC setup.
        // Only the immutable theorem/three exact frames survive this call.
        let receiving =
            read::hash::Verifier::new(&expected).map_err(|_| Error::RejectedComputationProof)?;
        if let Some(original) = retained.as_ref()
            && original.matches(&expected, &evidence)
        {
            drop(
                receiving
                    .verify_retained(&original.theorem, evidence.query())
                    .map_err(|_| Error::RejectedComputationProof)?,
            );
        } else {
            let (checked, theorem) = receiving
                .verify_and_retain(evidence)
                .map_err(|_| Error::RejectedComputationProof)?;
            drop(checked);
            let evidence = parsed.evidence();
            // Replace only after full native success. Invalid queries/proofs
            // cannot evict a previously checked immutable theorem.
            drop(retained.take());
            *retained = Some(RetainedData {
                theorem,
                frames: [evidence.state, evidence.child, evidence.data]
                    .map(|bytes| bytes.to_vec().into_boxed_slice()),
            });
        }
        Ok(())
    }
}
