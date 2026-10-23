//! Five actual SHA-suite AIR proofs plus the original product certificate.
//! Distinct conditional mathematics; no SQL, current head, lock or old-suite grant.
use super::{Evidence, Expected, QueryEvidence, fused, installed, product};
use crate::registry_progress::word;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Resource,
    Data(installed::hash::Error),
    Word(word::Error),
    Query(bfv_ciphertext_formation::gold::Error),
    Product(product::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hash read candidate rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/hash-five-AIR-original-product/read/v1/no-live-admission\0");
    hash.update(super::profile_digest());
    hash.update(installed::hash::profile_digest());
    hash.update(word::hash::profile_digest());
    hash.update(fused::hash::profile_digest());
    hash.update(product::profile_digest());
    hash.finalize().into()
}

/// The same independently captured full public endpoints used by the existing
/// read constructor; no incoming frame can choose its statement or setup.
pub struct Verifier<'a> {
    expected: &'a Expected,
    word: word::hash::Verifier,
    query: fused::hash::Verifier,
}
impl<'a> Verifier<'a> {
    pub fn new(expected: &'a Expected) -> Result<Self> {
        Ok(Self {
            expected,
            word: word::hash::Verifier::new().map_err(Error::Word)?,
            query: fused::hash::Verifier::new(expected.query_expected()).map_err(Error::Query)?,
        })
    }

    /// Cold receiving freshly checks all five native proofs and the original
    /// product; only the immutable DATA theorem may subsequently be retained.
    pub fn verify_and_retain(
        &self,
        evidence: Evidence<'_>,
    ) -> Result<(ArithmeticCheckedRead<'a>, installed::hash::CheckedData)> {
        evidence.require_bounds().map_err(|_| Error::Resource)?;
        let product = product::check_arithmetic(self.expected.product_expected(), evidence.product)
            .map_err(Error::Product)?;
        let prerequisites = installed::hash::Prerequisites::checked(evidence.state, evidence.child)
            .map_err(Error::Data)?;
        let retained = installed::hash::verify(
            self.expected.data_expected(),
            self.expected.data_expected().request(),
            prerequisites,
            evidence.data,
        )
        .map_err(Error::Data)?;
        self.fresh_query(evidence.query())?;
        Ok((
            ArithmeticCheckedRead {
                expected: self.expected,
                product,
            },
            retained,
        ))
    }

    /// Retention binds every immutable endpoint. Word, Query and product checks
    /// remain fresh on every call, including after an earlier success/failure.
    pub fn verify_retained(
        &self,
        retained: &installed::hash::CheckedData,
        evidence: QueryEvidence<'_>,
    ) -> Result<ArithmeticCheckedRead<'a>> {
        evidence.require_bounds().map_err(|_| Error::Resource)?;
        retained
            .require_expected(self.expected.data_expected())
            .map_err(Error::Data)?;
        let product = product::check_arithmetic(self.expected.product_expected(), evidence.product)
            .map_err(Error::Product)?;
        self.fresh_query(evidence)?;
        Ok(ArithmeticCheckedRead {
            expected: self.expected,
            product,
        })
    }

    fn fresh_query(&self, evidence: QueryEvidence<'_>) -> Result<()> {
        // Both native checks borrow only their captured public expectations.
        // Join every job before returning, retaining Word-first error priority.
        let (word, query) = bfv_hiding_stark::hash::join(
            || {
                self.word
                    .verify(self.expected.word_expected(), evidence.word)
                    .map(drop)
                    .map_err(Error::Word)
            },
            || self.query.verify(evidence.query).map_err(Error::Query),
        );
        word?;
        query
    }
}

/// Move-only mathematical result of this candidate, not an old read/journal token.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::hash::ArithmeticCheckedRead;
/// fn forge() { let _ = ArithmeticCheckedRead {}; }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::hash::ArithmeticCheckedRead;
/// fn duplicate<'a>(value: &ArithmeticCheckedRead<'a>) -> ArithmeticCheckedRead<'a> { value.clone() }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::{self, hash};
/// fn relabel<'a>(value: hash::ArithmeticCheckedRead<'a>) -> read::ArithmeticCheckedRead<'a> { value }
/// ```
pub struct ArithmeticCheckedRead<'a> {
    expected: &'a Expected,
    product: product::ArithmeticCheckedProduct,
}
impl ArithmeticCheckedRead<'_> {
    pub fn expected(&self) -> &Expected {
        self.expected
    }
    pub fn product(&self) -> &product::ArithmeticCheckedProduct {
        &self.product
    }
    pub fn output(&self) -> &[u8] {
        self.expected.product_expected().output_wire()
    }
}

#[cfg(test)]
#[path = "hash_tests.rs"]
mod tests;
