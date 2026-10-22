//! Public N4096/Q2/P2 unrelinearized-product arithmetic certificates.
//! This library retains the experimental UNASSESSED profile. A checked result
//! proves no Source, encryption-key validity, hidden program, freshness, SQL
//! admission, lattice security or assessed Fiat-Shamir security.
#![forbid(unsafe_code)]

mod certificate;
mod geometry;
mod modular;
mod pit;
mod scale;
mod statement;
#[cfg(test)]
mod tests;

pub use geometry::{N, P, Q, QP, T};
use sha2::{Digest, Sha512};
pub use statement::Expected;

/// Basis-major canonical public coefficients; no secret or acceptance capability.
pub type Polynomial = Vec<Vec<u64>>;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Arithmetic,
    Binding,
    Resource,
    Backend,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "public arithmetic experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}

/// Exact fixed-size UCPITC02 wire; its original full logical witness is recovered.
pub const CERTIFICATE_BYTES: usize = certificate::FRAME_BYTES;
pub const POINTS: usize = pit::POINTS;
/// Canonical transport identity, separate from the unchanged arithmetic relation.
pub fn wire_profile_digest() -> [u8; 32] {
    certificate::wire_profile_digest()
}
pub fn profile_digest() -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/UNREL-PUBLIC-CERTIFICATE-EXPERIMENT/v1/UNASSESSED/");
    for n in [geometry::N as u64, geometry::T] {
        h.update(n.to_le_bytes());
    }
    for p in geometry::QP {
        h.update(p.to_le_bytes());
    }
    h.update(scale::profile_digest(scale::Role::Extend2To4));
    h.update(scale::profile_digest(scale::Role::Scale4To2));
    h.update(b"unseededCT2+2/CT3;lvl0;NttTagStoredPB;nonce32;ProtoCanonicalAllResidues;Extend4ExactQCopies;RNSProducts3xQP;C0=A0B0,C1=A0B1+A1B0,C2=A1B1;ordinary2N;HlengthN-1;YlengthN;F=AB-Y-(xN+1)H;Scale3Exact;all7CompactIntegerCertificates;allDataBeforeFS;SHA512fullMessagePrefixClone;basisU32LE/sampleU32LE;OS2IP512modp;noNTTverifier;noSDKqueryreplay;fixedPackedWidths30,30,62,62;fullEOF;noProofOrSourceOrSQLOrSecurityGrant;");
    h.update((pit::POINTS as u64).to_le_bytes());
    h.update((certificate::LOGICAL_FRAME_BYTES as u64).to_le_bytes());
    h.finalize().into()
}
/// Canonical producer bytes. This type carries no checked arithmetic authority.
pub struct UnverifiedEvidence {
    bytes: Vec<u8>,
}
impl UnverifiedEvidence {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Move-only mathematical result, created only by the complete cold checker.
/// Its PIT conclusion is conditional on the unassessed Fiat-Shamir model.
/// It is not an admitted DCS computation proof or a fresh-head/key/SQL grant.
///
/// The actual private result field cannot be forged:
/// ```compile_fail
/// use bfv_unrelinearized_product::{Expected, ArithmeticCheckedProduct};
/// fn forge(expected: Expected) { let _ = ArithmeticCheckedProduct { expected }; }
/// ```
/// The result is move-only:
/// ```compile_fail
/// use bfv_unrelinearized_product::ArithmeticCheckedProduct;
/// fn duplicate(value: ArithmeticCheckedProduct) { let _: ArithmeticCheckedProduct = value.clone(); }
/// ```
pub struct ArithmeticCheckedProduct {
    expected: Expected,
}
impl ArithmeticCheckedProduct {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}

/// Generate the public certificate for the independently retained endpoints.
/// No Source, key or client plaintext is supplied to this producer.
pub fn produce(expected: &Expected) -> Result<UnverifiedEvidence> {
    Ok(UnverifiedEvidence {
        bytes: certificate::produce(expected)?,
    })
}

/// Decode the exact compact frame and reconstruct the original logical frame.
/// Check all deterministic integer relations, then check product identities with
/// challenges from that complete original logical transcript.
/// Never takes a callback, caller-chosen challenge or serialized checked flag.
pub fn check_arithmetic(expected: &Expected, frame: &[u8]) -> Result<ArithmeticCheckedProduct> {
    certificate::check(expected, frame)?;
    Ok(ArithmeticCheckedProduct {
        expected: expected.clone(),
    })
}
