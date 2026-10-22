//! One exact immutable native DATA theorem; fresh per-query proofs on every call.
use super::{Error, Result, predicate::BorrowedPredicate};
use registry200_proof::{
    registry_progress::word::{self, read},
    source::version::SourceVersionExpected,
    two_lane_encoding::data_formation::VerifiedDataFormation,
};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct PredicateReceiver {
    retained: Mutex<Option<RetainedData>>,
}
struct RetainedData {
    theorem: VerifiedDataFormation,
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
        if let Some(original) = retained.as_ref()
            && original.matches(&expected, &evidence)
        {
            drop(
                read::verify_retained(&expected, &original.theorem, evidence.query())
                    .map_err(|_| Error::RejectedComputationProof)?,
            );
        } else {
            let (checked, theorem) = read::verify_and_retain(&expected, evidence)
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
