//! One real DATA Ct2 Formation. Mathematical evidence supplies no Source/key/current-head/SQL authority.
use super::{
    Error, Result, ScaledOpening, SecretOpening, Val,
    geometry::{N, Polynomial, Q, SCALE, T},
    relation::ExpectedRef,
    request,
    witness::Preparation,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Arc;
#[cfg(test)]
#[path = "data_tests.rs"]
mod tests;
pub const MAX_EVIDENCE_BYTES: usize = super::wire::MAX_FRAME_BYTES;
const MAGIC: &[u8; 8] = b"GFMDQ001";
const HEADER: usize = 76;
const MAX_CT: usize = 128 * 1024;
/// Separate single-DATA identity; never a Pair/query/SourceVersion cast.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/CoreGold/DATA-Formation/v1/N4096/Q2/one-real-Ct2/no-SQL-admission");
    h.update(b"GFMDQ001;literal-unseeded-CT2;admission-nonce32;Cw4112;Cs528;already-scaled;S/E+-20;shared-E-Q2;K-symmetric524287;Sforward+2pointwise+2inverse;81920gates/2560rows;range2048/Cw514/Cs66/active5188;H8192/MAIN512/PP272/PV32/128Count4;soleterminal0;native0.8-defaultpack;GoldEF5/Q192/blowup3/salt4/random5/zero-grind");
    for v in [
        N as u64,
        Q[0],
        Q[1],
        T,
        SCALE,
        super::geometry::DELTA[0],
        super::geometry::DELTA[1],
        super::fft::PSI,
    ] {
        h.update(v.to_le_bytes());
    }
    h.update(super::program::BUS.as_bytes());
    h.finalize().into()
}
/// Canonical PUBLIC single-ciphertext input. This authenticates no Source or key.
#[derive(Clone)]
pub struct Request {
    inner: Arc<RequestData>,
}
struct RequestData {
    nonce: [u8; 32],
    bytes: Vec<u8>,
    inputs: [Polynomial; 2],
}
impl Request {
    pub fn checked(nonce: [u8; 32], ciphertext: Vec<u8>) -> Result<Self> {
        if nonce == [0; 32] {
            return Err(Error::Binding);
        }
        let inputs = request::parse(&ciphertext)?;
        let mut bytes = Vec::with_capacity(HEADER + ciphertext.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&profile_digest());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&ciphertext);
        Ok(Self {
            inner: Arc::new(RequestData {
                nonce,
                bytes,
                inputs,
            }),
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER || bytes.len() > HEADER + MAX_CT {
            return Err(Error::Resource);
        }
        if &bytes[..8] != MAGIC || bytes[8..40] != profile_digest() {
            return Err(Error::Encoding);
        }
        let len =
            u32::from_le_bytes(bytes[72..76].try_into().map_err(|_| Error::Encoding)?) as usize;
        if len == 0 || len > MAX_CT || HEADER + len != bytes.len() {
            return Err(Error::Encoding);
        }
        let request = Self::checked(
            bytes[40..72].try_into().map_err(|_| Error::Encoding)?,
            bytes[HEADER..].to_vec(),
        )?;
        if request.bytes() != bytes {
            return Err(Error::Encoding);
        }
        Ok(request)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.inner.nonce
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.inner.bytes[HEADER..]
    }
    /// Public PB components0/1, each Q0/Q1. No second operand exists.
    pub fn input(&self, component: usize) -> &[Vec<u64>] {
        &self.inner.inputs[component]
    }
}
/// Independent complete public metadata. Own contexts are acyclic and caller-retained.
#[derive(Clone)]
pub struct Expected {
    request: Request,
    association: [u8; 64],
    contexts: [[Val; 8]; 2],
    roots: [[Val; 4]; 2],
    binding: [u8; 64],
    values: Vec<Val>,
}
impl Expected {
    pub fn checked(
        request: Request,
        association: [u8; 64],
        contexts: [[Val; 8]; 2],
        roots: [[Val; 4]; 2],
    ) -> Result<Self> {
        let mut h = Sha512::new();
        h.update(b"DCS/CoreGold/DATA-complete-Expected/v1");
        h.update(profile_digest());
        h.update((request.bytes().len() as u64).to_le_bytes());
        h.update(request.bytes());
        h.update(association);
        for row in &contexts {
            for v in row {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        for row in &roots {
            for v in row {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        let binding: [u8; 64] = h.finalize().into();
        let mut values = Vec::with_capacity(32);
        for word in profile_digest().as_chunks::<4>().0 {
            values.push(Val::from_u32(u32::from_le_bytes(*word)));
        }
        for word in binding.as_chunks::<4>().0 {
            values.push(Val::from_u32(u32::from_le_bytes(*word)));
        }
        for root in [roots[1], roots[0]] {
            values.extend(root);
        }
        if values.len() != 32 {
            return Err(Error::Shape);
        }
        Ok(Self {
            request,
            association,
            contexts,
            roots,
            binding,
            values,
        })
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn contexts(&self) -> [[Val; 8]; 2] {
        self.contexts
    }
    pub fn roots(&self) -> [[Val; 4]; 2] {
        self.roots
    }
    pub fn values(&self) -> &[Val] {
        &self.values
    }
    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }
    pub(super) fn require_same(&self, other: &Self) -> Result<()> {
        if self.request.bytes() != other.request.bytes()
            || self.association != other.association
            || self.contexts != other.contexts
            || self.roots != other.roots
            || self.values != other.values
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
/// Consumes exactly ONE actual W opening and the original SDK secret/Cs opening.
pub struct Prepared {
    pub(super) inner: Preparation,
}
impl Prepared {
    pub fn new(expected: &Expected, opening: ScaledOpening, key: SecretOpening) -> Result<Self> {
        Ok(Self {
            inner: Preparation::new(ExpectedRef::Data(expected), vec![opening], key)?,
        })
    }
    /// Consume the original private inputs and check their complete algebraic
    /// consistency against this SAME captured expectation, without PP or MAIN.
    ///
    /// This also supports a one-Ct owner-private query input. Unit success is not
    /// a proof, DATA admission, encryption-randomness assessment or SQL authority;
    /// it cannot replace prove() or the mandatory receiving native verify().
    pub fn check_private_consistency(self, expected: &Expected) -> Result<()> {
        self.inner
            .check_private_consistency(ExpectedRef::Data(expected))
    }
    pub(in crate::gold) fn require_dense_expected(&self, expected: &Expected) -> Result<()> {
        self.inner.require_expected(ExpectedRef::Data(expected))
    }
    pub(in crate::gold) fn dense_trace(
        self,
        expected: &Expected,
    ) -> Result<super::witness::PrivateTrace> {
        self.inner.dense_trace(expected)
    }
}
/// Producer bytes are UNVERIFIED; no accepted/currentness label is serialized.
pub struct UnverifiedDataFormationEvidence {
    expected: Expected,
    bytes: Vec<u8>,
}
impl UnverifiedDataFormationEvidence {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
/// Move-only DATA mathematics from the actual cold native verifier.
/// ```compile_fail
/// use bfv_ciphertext_formation::gold::data::{Expected,VerifiedDataFormation};
/// fn forge(expected:Expected)->VerifiedDataFormation{VerifiedDataFormation{expected}}
/// ```
/// ```compile_fail
/// use bfv_ciphertext_formation::gold::data::VerifiedDataFormation;
/// fn duplicate(x:&VerifiedDataFormation)->VerifiedDataFormation{x.clone()}
/// ```
pub struct VerifiedDataFormation {
    expected: Expected,
}
impl VerifiedDataFormation {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
pub fn prove(expected: &Expected, prepared: Prepared) -> Result<UnverifiedDataFormationEvidence> {
    let bytes = super::evidence::prove_bytes(ExpectedRef::Data(expected), prepared.inner)?;
    Ok(UnverifiedDataFormationEvidence {
        expected: expected.clone(),
        bytes,
    })
}
pub fn verify(expected: &Expected, bytes: &[u8]) -> Result<VerifiedDataFormation> {
    super::evidence::verify_bytes(ExpectedRef::Data(expected), bytes)?;
    Ok(VerifiedDataFormation {
        expected: expected.clone(),
    })
}

/// Bound for the separate DCSGDD01 dense proof frame. No legacy-frame fallback.
pub const MAX_DENSE_EVIDENCE_BYTES: usize = super::program::dense_data_inventory::MAX_FRAME_BYTES;

/// Identifies the dense proof protocol, not a new key, Source or SQL capability.
pub fn dense_profile_digest() -> [u8; 32] {
    super::program::dense_data_inventory::profile()
}

/// Diagnose the fixed H2048 dense DATA AIR and its original lookup inventory.
/// This does not assess the separate H8192 prove()/verify() proof profile.
/// No native setup, private MAIN, proof or RNG is constructed. The conditional
/// algebraic report is neither mathematical evidence nor admission authority.
pub fn dense_classical_bound(
    expected: &Expected,
) -> Result<bfv_hiding_stark::classical::AlgebraicBound> {
    super::program::dense_data_inventory::classical_bound(expected)
}

/// Prove the SAME complete single-Ct relation using the fixed H2048 layout.
/// Consumes the original guarded W/Cs inputs; returns unverified bytes only.
///
/// The original prove()/verify() and their H8192 frame remain independent.
/// Both layouts are conditional mathematical components, without key/DATA
/// admission, lattice assurance, freshness or SQL authorization.
pub fn prove_dense(
    expected: &Expected,
    prepared: Prepared,
) -> Result<UnverifiedDataFormationEvidence> {
    let bytes = super::program::dense_data_inventory::produce(expected, prepared)?;
    Ok(UnverifiedDataFormationEvidence {
        expected: expected.clone(),
        bytes,
    })
}

/// Independently reconstruct PUBLIC PP, bound/decode the distinct dense frame,
/// and run the actual native verifier before returning mathematical evidence.
/// No producer-supplied setup, checked flag or alternate verifier is accepted.
pub fn verify_dense(expected: &Expected, bytes: &[u8]) -> Result<VerifiedDataFormation> {
    super::program::dense_data_inventory::receive(expected, bytes)?;
    Ok(VerifiedDataFormation {
        expected: expected.clone(),
    })
}

#[cfg(test)]
pub(super) fn dense_native_fixture() -> (Expected, Prepared, Prepared) {
    tests::dense_native_fixture()
}
#[cfg(test)]
pub(in crate::gold) fn fused_query_native_fixture(
    high: bool,
) -> (super::query::Expected, super::query::Prepared) {
    tests::fused_query_fixture(high)
}
