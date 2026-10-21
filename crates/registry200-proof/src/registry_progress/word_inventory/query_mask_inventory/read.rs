//! Closed conditional mathematical read composition, not SQL or fresh-head admission.
use super::formation;
use crate::{
    registry_progress::word_inventory::{Metadata, probe, probe_wire},
    two_lane_encoding::{data_formation as installed, wire},
};
use bfv_ciphertext_formation::gold::{self, data, query};
use bfv_unrelinearized_product as product;
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;

#[derive(Debug)]
pub(super) enum Error {
    Binding,
    Resource,
    Data(installed::Error),
    Word(probe::Error),
    Query(formation::Error),
    Product(product::Error),
}
type Result<T> = core::result::Result<T, Error>;

fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/Word-Source-DATA-FusedQuery-Product/read/v1/conditional-no-SQL-no-current-head");
    h.update(installed::dense_profile_digest());
    h.update(super::super::profile());
    h.update(probe_wire::profile());
    h.update(query::profile_digest());
    h.update(product::profile_digest());
    h.update(b"full-original-State-heads-packets-values;original-Word-Stmt96;original-ordered-pair-and-nonce;same-DATA-Cs;fresh-State-Role3-DATA-Word-Query-native-every-receive;full-original-CT3-arithmetic;no-supplied-verdict");
    h.finalize().into()
}

/// All independently retained public endpoints. No claimed proof is inspected here.
pub(super) struct Expected<'a> {
    word: &'a Metadata,
    data: installed::Expected,
    query: formation::Expected,
    product: product::Expected,
}
impl<'a> Expected<'a> {
    pub(super) fn checked(
        word: &'a Metadata,
        data: &installed::Expected,
        request: &gold::Request,
        vector: [crate::Val; 4],
        output: Vec<u8>,
    ) -> Result<Self> {
        let claim = data.source().expected.source_claim();
        let original = word.source.statement();
        if !word.predicate
            || claim.values() != original.values()
            || claim.heads != original.heads
            || claim.packets != original.packets
        {
            return Err(Error::Binding);
        }
        let query =
            formation::Expected::checked(request, data.core_expected(), word.statement, vector)
                .map_err(Error::Query)?;
        let product = product::Expected::checked(
            request.nonce(),
            request.ciphertexts().map(<[u8]>::to_vec),
            output,
        )
        .map_err(Error::Product)?;
        Ok(Self {
            word,
            data: data.clone(),
            query,
            product,
        })
    }
}
/// Six independently bounded UNVERIFIED frames. No verification token is accepted.
pub(super) struct Evidence<'a> {
    pub(super) state: &'a [u8],
    pub(super) child: &'a [u8],
    pub(super) data: &'a [u8],
    pub(super) word: &'a [u8],
    pub(super) query: &'a [u8],
    pub(super) product: &'a [u8],
}
impl Evidence<'_> {
    fn require_bounds(&self) -> Result<()> {
        for (bytes, limit) in [
            (self.state, wire::MAX_SOURCE),
            (self.child, wire::MAX_CHILD),
            (self.data, data::MAX_DENSE_EVIDENCE_BYTES),
            (self.word, probe_wire::MAX_FRAME_BYTES),
            (self.query, query::MAX_EVIDENCE_BYTES),
        ] {
            if bytes.is_empty() || bytes.len() > limit {
                return Err(Error::Resource);
            }
        }
        if self.product.len() != product::CERTIFICATE_BYTES {
            return Err(Error::Resource);
        }
        Ok(())
    }
}
/// Move-only result borrowing public metadata. No SQL, freshness or security grant.
/// Only the closed receiving function in this module can construct this type.
pub(super) struct ArithmeticCheckedRead<'a> {
    expected: &'a Expected<'a>,
}
impl ArithmeticCheckedRead<'_> {
    pub(super) fn output(&self) -> &[u8] {
        self.expected.product.output_wire()
    }
}
pub(super) fn verify<'a>(
    expected: &'a Expected<'a>,
    evidence: Evidence<'_>,
) -> Result<ArithmeticCheckedRead<'a>> {
    evidence.require_bounds()?;
    // Reject cheap public arithmetic before native proofs. Neither this result
    // nor any producer/owner claim can replace the five required native checks.
    drop(product::check_arithmetic(&expected.product, evidence.product).map_err(Error::Product)?);
    let prerequisites =
        installed::Prerequisites::checked(evidence.state, evidence.child).map_err(Error::Data)?;
    drop(
        installed::verify_dense(
            &expected.data,
            expected.data.request(),
            prerequisites,
            evidence.data,
        )
        .map_err(Error::Data)?,
    );
    probe::verify(expected.word, evidence.word).map_err(Error::Word)?;
    formation::verify_bytes(&expected.query, evidence.query).map_err(Error::Query)?;
    Ok(ArithmeticCheckedRead { expected })
}
