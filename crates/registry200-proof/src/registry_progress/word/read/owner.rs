//! Originating owner's private premise joined to actual public Word/DATA/product checks.
//! Distinct from a public Query proof. No peer, SQL, current-head or lock admission.
use super::{Role, WordExpected, installed};
use bfv_query_core::gold::{self as protected, OriginatingStatement};
use bfv_unrelinearized_product as product;
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Binding,
    Resource,
    Input(protected::Error),
    Data(installed::Error),
    Word(super::super::Error),
    Product(product::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "originating owner read rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

/// Immutable, role-only public setup. No query, private data or cached verdict.
pub struct Verifier {
    word: super::super::Verifier,
}
impl Verifier {
    pub fn new() -> Result<Self> {
        Ok(Self {
            word: super::super::Verifier::new(Role::Predicate).map_err(Error::Word)?,
        })
    }
    /// Fresh full Word/product checks for the exact originating private input.
    /// The retained DATA theorem must still match every original immutable endpoint.
    pub fn verify<'s, 'q>(
        &self,
        input: &'s OriginatingStatement<'q>,
        word: &WordExpected,
        data: &installed::Expected,
        retained: &installed::VerifiedDataFormation,
        evidence: Evidence<'_>,
    ) -> Result<OwnerCheckedRead<'s, 'q>> {
        if evidence.word.is_empty()
            || evidence.word.len() > super::super::MAX_EVIDENCE_BYTES
            || evidence.product.len() != product::CERTIFICATE_BYTES
            || evidence.output.is_empty()
            || evidence.output.len() > 128 * 1024
        {
            return Err(Error::Resource);
        }
        let claim = data.source().expected.source_claim();
        let source = word.source().statement();
        let original = input.data_expected();
        let core = data.core_expected();
        let context: [u8; 32] = Sha256::digest(word.binding()).into();
        if word.role() != Role::Predicate
            || input.public_request().binding().context() != context
            || claim.values() != source.values()
            || claim.heads != source.heads
            || claim.packets != source.packets
            || original.binding() != core.binding()
            || original.request().nonce() != core.request().nonce()
            || original.request().ciphertext() != core.request().ciphertext()
            || original.contexts() != core.contexts()
            || original.roots() != core.roots()
            || input.root() != word.claims().statement.map(|v| v.as_canonical_u64())
            || input.header() != super::super::statement_header().map(|v| v.as_canonical_u64())
        {
            return Err(Error::Binding);
        }
        retained.require_expected(data).map_err(Error::Data)?;
        let request = input
            .public_request()
            .formation_request()
            .map_err(Error::Input)?;
        let expected = product::Expected::checked(
            request.nonce(),
            request.ciphertexts().map(<[u8]>::to_vec),
            evidence.output.to_vec(),
        )
        .map_err(Error::Product)?;
        let product =
            product::check_arithmetic(&expected, evidence.product).map_err(Error::Product)?;
        drop(self.word.verify(word, evidence.word).map_err(Error::Word)?);
        Ok(OwnerCheckedRead { input, product })
    }
}
/// Unverified bounded peer output, conditional arithmetic certificate and Word proof.
pub struct Evidence<'a> {
    pub word: &'a [u8],
    pub output: &'a [u8],
    pub product: &'a [u8],
}
/// Non-transferable owner result: it does NOT claim a public Query proof was checked.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::owner::OwnerCheckedRead;
/// fn duplicate<'s, 'q>(x: &OwnerCheckedRead<'s, 'q>) -> OwnerCheckedRead<'s, 'q> { x.clone() }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::read::owner::OwnerCheckedRead;
/// fn forge() { let _ = OwnerCheckedRead {}; }
/// ```
pub struct OwnerCheckedRead<'s, 'q> {
    input: &'s OriginatingStatement<'q>,
    product: product::ArithmeticCheckedProduct,
}
impl OwnerCheckedRead<'_, '_> {
    /// Exact original nonce and ordered pair checked again before owner decryption.
    pub fn complete(&self, owner: &protected::Owner) -> Result<protected::DecryptedProduct> {
        self.input
            .complete_checked_product(owner, &self.product)
            .map_err(Error::Input)
    }
}
