//! Closed fresh Formation plus conditional public-product arithmetic.
//! Success grants no assessed cryptographic security, SQL, key admission or current head.
use super::{formation, statement, wire};
use bfv_ciphertext_formation::gold;
use bfv_unrelinearized_product as arithmetic;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Binding,
    ResourceLimit,
    Formation(formation::Error),
    Arithmetic(arithmetic::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Binding => f.write_str("Two-lane product association mismatch"),
            Self::ResourceLimit => f.write_str("Two-lane product resource limit"),
            Self::Formation(e) => write!(f, "Two-lane product Formation: {e}"),
            Self::Arithmetic(e) => write!(f, "Two-lane product arithmetic: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<formation::Error> for Error {
    fn from(value: formation::Error) -> Self {
        Self::Formation(value)
    }
}
impl From<arithmetic::Error> for Error {
    fn from(value: arithmetic::Error) -> Self {
        Self::Arithmetic(value)
    }
}
pub type Result<T> = core::result::Result<T, Error>;

/// Distinct composition label above unchanged mathematical profiles/codecs.
/// It does not turn the eighteen-point UNASSESSED product into a security grant.
pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/two-lane-CoreGold/product-composition/v1/ARITHMETIC-ONLY-UNASSESSED");
    hash.update(formation::profile_digest());
    hash.update(arithmetic::profile_digest());
    hash.update(b"same-literal-ordered-CT2/nonce;GFMRQ001-not-UCPITQ01;full-public-product-then-fresh-Source-children-Formation;canonical-claimed-CT3;no-SQL-no-freshness-no-cached-verdict");
    hash.finalize().into()
}

/// Complete independently retained public metadata; its constructor verifies no proof.
/// Claimed Ct3 is untrusted until the fixed receiving path completes.
#[derive(Clone)]
pub struct Expected {
    formation: formation::Expected,
    product: arithmetic::Expected,
}
impl Expected {
    pub fn checked(
        request: &gold::Request,
        source: &statement::Statement,
        mask: &statement::Statement,
        claimed_output: Vec<u8>,
    ) -> Result<Self> {
        let formation = formation::Expected::checked(request, source, mask)?;
        // Borrow the SAME canonical literal bytes. Never reconstruct endpoints
        // from polynomials, reinterpret a request header, or compare unlike q.
        let ciphertexts = request.ciphertexts();
        let product = arithmetic::Expected::checked(
            request.nonce(),
            ciphertexts.map(<[u8]>::to_vec),
            claimed_output,
        )?;
        Ok(Self { formation, product })
    }
    pub fn formation(&self) -> &formation::Expected {
        &self.formation
    }
    pub fn product(&self) -> &arithmetic::Expected {
        &self.product
    }
}

/// Five bounded UNVERIFIED borrowed frames, never a supplied verdict or admission token.
pub struct BorrowedPrerequisites<'a> {
    source: &'a [u8],
    source_child: &'a [u8],
    mask_child: &'a [u8],
    formation: &'a [u8],
    product: &'a [u8],
}
impl<'a> BorrowedPrerequisites<'a> {
    pub fn checked(
        source: &'a [u8],
        source_child: &'a [u8],
        mask_child: &'a [u8],
        formation: &'a [u8],
        product: &'a [u8],
    ) -> Result<Self> {
        if source.is_empty()
            || source.len() > wire::MAX_SOURCE
            || source_child.is_empty()
            || source_child.len() > wire::MAX_CHILD
            || mask_child.is_empty()
            || mask_child.len() > wire::MAX_CHILD
            || formation.is_empty()
            || formation.len() > gold::MAX_EVIDENCE_BYTES
            || product.len() != arithmetic::CERTIFICATE_BYTES
        {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            source,
            source_child,
            mask_child,
            formation,
            product,
        })
    }
}

/// Move-only result of actual fresh Formation and complete conditional arithmetic.
/// It contains public expectation only, no client plaintext, response verdict cache,
/// current-head/QC, SQL status or cryptographic-security assessment.
///
/// Its private field is not a public accepting constructor:
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::product::{Expected, ArithmeticCheckedQuery};
/// fn forge(expected: Expected) -> ArithmeticCheckedQuery { ArithmeticCheckedQuery { expected } }
/// ```
/// It cannot be duplicated:
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::product::ArithmeticCheckedQuery;
/// fn duplicate(value: &ArithmeticCheckedQuery) -> ArithmeticCheckedQuery { value.clone() }
/// ```
pub struct ArithmeticCheckedQuery {
    expected: Expected,
}
impl ArithmeticCheckedQuery {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}

/// One closed receiving operation. No lower checked object can be supplied as
/// a callback, serialized capability or replacement for either actual verifier.
pub fn verify(
    expected: &Expected,
    evidence: BorrowedPrerequisites<'_>,
) -> Result<ArithmeticCheckedQuery> {
    // Public arithmetic is cheap and fully bounded; reject it before expensive
    // native Formation. Its temporary result never substitutes the latter.
    let checked = arithmetic::check_arithmetic(&expected.product, evidence.product)?;
    if checked.expected().request_wire() != expected.product.request_wire()
        || checked.expected().output_wire() != expected.product.output_wire()
        || checked.expected().nonce() != expected.formation.request().nonce()
    {
        return Err(Error::Binding);
    }
    drop(checked);
    let prerequisites = formation::Prerequisites::checked(
        evidence.source,
        evidence.source_child,
        evidence.mask_child,
    )?;
    let verified_formation = formation::verify(
        &expected.formation,
        expected.formation.request(),
        prerequisites,
        evidence.formation,
    )?;
    drop(verified_formation);
    Ok(ArithmeticCheckedQuery {
        expected: expected.clone(),
    })
}
