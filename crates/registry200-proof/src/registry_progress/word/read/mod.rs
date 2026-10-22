//! Conditional fixed Word/DATA/Query/FHE mathematics, without SQL or fresh-head admission.
pub mod classical;
#[cfg(feature = "owner-read")]
pub mod owner;
pub mod query;
#[cfg(test)]
mod tests;
pub mod transcript;
use super::{Expected as WordExpected, Role};
use crate::{
    Val,
    two_lane_encoding::{data_formation as installed, wire},
};
use bfv_ciphertext_formation::gold::{self, data, query as fused};
use bfv_unrelinearized_product as product;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Binding,
    Resource,
    Data(installed::Error),
    Word(super::Error),
    Query(query::Error),
    Formation(gold::Error),
    Product(product::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "conditional Word read rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/Word-Source-DATA-FusedQuery-Product/read/v1/conditional-no-SQL-no-current-head");
    h.update(installed::dense_profile_digest());
    h.update(super::profile_digest());
    h.update(super::wire_profile_digest());
    h.update(fused::profile_digest());
    h.update(product::profile_digest());
    h.update(b"full-original-State-heads-packets-values;original-Word-Stmt96;original-ordered-pair-and-nonce;same-DATA-Cs;fresh-State-Role3-DATA-Word-Query-native-every-receive;full-original-CT3-arithmetic;no-supplied-verdict");
    h.finalize().into()
}
/// Independently retained complete public endpoints. This verifies no proof,
/// authenticates no Source/OldRoot/key and establishes no current network head.
pub struct Expected {
    word: WordExpected,
    data: installed::Expected,
    query: fused::Expected,
    product: product::Expected,
}
impl Expected {
    pub fn checked(
        word: &WordExpected,
        data: &installed::Expected,
        request: &gold::Request,
        vector: [Val; 4],
        output: Vec<u8>,
    ) -> Result<Self> {
        let claim = data.source().expected.source_claim();
        let original = word.source().statement();
        if word.role() != Role::Predicate
            || claim.values() != original.values()
            || claim.heads != original.heads
            || claim.packets != original.packets
        {
            return Err(Error::Binding);
        }
        let query = query::expected(
            request,
            data.core_expected(),
            word.claims().statement,
            vector,
        )
        .map_err(Error::Query)?;
        let product = product::Expected::checked(
            request.nonce(),
            request.ciphertexts().map(<[u8]>::to_vec),
            output,
        )
        .map_err(Error::Product)?;
        Ok(Self {
            word: word.clone(),
            data: data.clone(),
            query,
            product,
        })
    }
    pub fn word_expected(&self) -> &WordExpected {
        &self.word
    }
    pub fn data_expected(&self) -> &installed::Expected {
        &self.data
    }
    pub fn query_expected(&self) -> &fused::Expected {
        &self.query
    }
    pub fn product_expected(&self) -> &product::Expected {
        &self.product
    }
}
/// Six borrowed UNVERIFIED frames. No setup, callback, accepted flag or SQL grant.
pub struct Evidence<'a> {
    pub state: &'a [u8],
    pub child: &'a [u8],
    pub data: &'a [u8],
    pub word: &'a [u8],
    pub query: &'a [u8],
    pub product: &'a [u8],
}
impl Evidence<'_> {
    fn require_bounds(&self) -> Result<()> {
        for (bytes, limit) in [
            (self.state, wire::MAX_SOURCE),
            (self.child, wire::MAX_CHILD),
            (self.data, data::MAX_DENSE_EVIDENCE_BYTES),
        ] {
            if bytes.is_empty() || bytes.len() > limit {
                return Err(Error::Resource);
            }
        }
        self.query().require_bounds()
    }
    pub fn query(&self) -> QueryEvidence<'_> {
        QueryEvidence {
            word: self.word,
            query: self.query,
            product: self.product,
        }
    }
}
/// Unverified per-query bytes after retaining an actual immutable DATA theorem.
pub struct QueryEvidence<'a> {
    pub word: &'a [u8],
    pub query: &'a [u8],
    pub product: &'a [u8],
}
impl QueryEvidence<'_> {
    fn require_bounds(&self) -> Result<()> {
        if self.word.is_empty()
            || self.word.len() > super::MAX_EVIDENCE_BYTES
            || self.query.is_empty()
            || self.query.len() > fused::MAX_EVIDENCE_BYTES
            || self.product.len() != product::CERTIFICATE_BYTES
        {
            return Err(Error::Resource);
        }
        Ok(())
    }
}
/// Move-only result of actual native checks and conditional product arithmetic.
/// This is NOT assessed cryptographic security, SQL admission or fresh finality.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::{Expected, ArithmeticCheckedRead};
/// fn forge(expected: &Expected) { let _ = ArithmeticCheckedRead { expected }; }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::ArithmeticCheckedRead;
/// fn duplicate<'a>(x: &ArithmeticCheckedRead<'a>) -> ArithmeticCheckedRead<'a> { x.clone() }
/// ```
pub struct ArithmeticCheckedRead<'a> {
    expected: &'a Expected,
    product: product::ArithmeticCheckedProduct,
}
impl ArithmeticCheckedRead<'_> {
    pub fn expected(&self) -> &Expected {
        self.expected
    }
    pub fn output(&self) -> &[u8] {
        self.product.expected().output_wire()
    }
    /// Actual sealed product result from this invocation's complete verification.
    pub fn product(&self) -> &product::ArithmeticCheckedProduct {
        &self.product
    }
}
pub fn verify<'a>(
    expected: &'a Expected,
    evidence: Evidence<'_>,
) -> Result<ArithmeticCheckedRead<'a>> {
    verify_and_retain(expected, evidence).map(|(checked, _)| checked)
}
/// Freshly check all six proofs, returning the actual immutable DATA theorem
/// alongside this call's read result. Both are released only after every check
/// succeeds. Retaining DATA grants no new query, authorization or head status.
pub fn verify_and_retain<'a>(
    expected: &'a Expected,
    evidence: Evidence<'_>,
) -> Result<(ArithmeticCheckedRead<'a>, installed::VerifiedDataFormation)> {
    evidence.require_bounds()?;
    let product =
        product::check_arithmetic(&expected.product, evidence.product).map_err(Error::Product)?;
    let prerequisites =
        installed::Prerequisites::checked(evidence.state, evidence.child).map_err(Error::Data)?;
    let retained = installed::verify_dense(
        &expected.data,
        expected.data.request(),
        prerequisites,
        evidence.data,
    )
    .map_err(Error::Data)?;
    verify_query_proofs(expected, &evidence.query())?;
    Ok((ArithmeticCheckedRead { expected, product }, retained))
}
/// Retains only an actual private State/Role3/DATA verification result. Complete
/// DATA equality is mandatory; Word, Query and product are checked on EVERY call.
pub fn verify_retained<'a>(
    expected: &'a Expected,
    retained: &installed::VerifiedDataFormation,
    evidence: QueryEvidence<'_>,
) -> Result<ArithmeticCheckedRead<'a>> {
    evidence.require_bounds()?;
    retained
        .require_expected(&expected.data)
        .map_err(Error::Data)?;
    let product =
        product::check_arithmetic(&expected.product, evidence.product).map_err(Error::Product)?;
    verify_query_proofs(expected, &evidence)?;
    Ok(ArithmeticCheckedRead { expected, product })
}
fn verify_query_proofs(expected: &Expected, evidence: &QueryEvidence<'_>) -> Result<()> {
    drop(super::verify(&expected.word, evidence.word).map_err(Error::Word)?);
    drop(fused::verify(&expected.query, evidence.query).map_err(Error::Formation)?);
    Ok(())
}
/// Independent public preparation for ONE complete retained-DATA read. Preparing
/// this object checks no proof; its cost belongs to the current query's budget.
/// The caller can start it before per-query proofs arrive. No setup is imported.
pub struct Verifier<'a> {
    expected: &'a Expected,
    word: super::Verifier,
    query: fused::Verifier,
}
impl<'a> Verifier<'a> {
    pub fn new(expected: &'a Expected) -> Result<Self> {
        Ok(Self {
            expected,
            word: super::Verifier::new(Role::Predicate).map_err(Error::Word)?,
            query: fused::Verifier::new(&expected.query).map_err(Error::Formation)?,
        })
    }
    /// Full original immutable DATA equality and actual fresh Word/Query/product
    /// checks on EVERY invocation, including after an earlier success or failure.
    pub fn verify_retained(
        &self,
        retained: &installed::VerifiedDataFormation,
        evidence: QueryEvidence<'_>,
    ) -> Result<ArithmeticCheckedRead<'a>> {
        evidence.require_bounds()?;
        retained
            .require_expected(&self.expected.data)
            .map_err(Error::Data)?;
        let product = product::check_arithmetic(&self.expected.product, evidence.product)
            .map_err(Error::Product)?;
        drop(
            self.word
                .verify(&self.expected.word, evidence.word)
                .map_err(Error::Word)?,
        );
        drop(
            self.query
                .verify(evidence.query)
                .map_err(Error::Formation)?,
        );
        Ok(ArithmeticCheckedRead {
            expected: self.expected,
            product,
        })
    }
}
