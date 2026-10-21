//! Fresh immutable-version DATA encoding plus actual single-ciphertext Formation.
//! This mathematical composition grants no current head, BFV security, SQL or lock authority.
use super::{Role, circuit::Witness, profile_digest as encoding_profile, statement, wire};
use bfv_ciphertext_formation::gold::{self, data};
use bfv_hiding_stark::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "data_formation_tests.rs"]
mod tests;

#[derive(Debug)]
pub enum Error {
    Binding,
    ResourceLimit,
    Prerequisite(wire::Error),
    Formation(gold::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Binding => f.write_str("DATA Formation association mismatch"),
            Self::ResourceLimit => f.write_str("DATA Formation resource limit"),
            Self::Prerequisite(error) => write!(f, "DATA Formation prerequisite: {error}"),
            Self::Formation(error) => write!(f, "DATA Formation proof: {error}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Self::Prerequisite(error)
    }
}
impl From<gold::Error> for Error {
    fn from(error: gold::Error) -> Self {
        Self::Formation(error)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Separate DATA composition identity; no existing Pair/query profile is relabeled.
pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/two-lane-CoreGold/consuming-DATA-Formation/v1/no-SQL-no-freshness");
    hash.update(encoding_profile(Role::VersionSourceAllOriginal));
    hash.update(data::profile_digest());
    hash.update(b"fresh-StateCertificate-and-one-Role3-child;complete-State-values-heads-packets-key29-Cstate-Cw;literal-GFMDQ001-one-Ct2;Cw4112-and-DATA-Cs528;consume-SAME-final-W-once-and-salts;already-scaled-no-double-SCALE;native-cold-receiving;no-pair-no-query-q-cast");
    hash.finalize().into()
}
fn words(digest: [u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            digest[4 * i..4 * i + 4]
                .try_into()
                .expect("fixed digest word"),
        ))
    })
}
/// Pure PUBLIC metadata for independently constructing the DATA-specific Cs.
/// Excludes its own Cs, Source/Cw and request; this authenticates no key or setup.
pub fn secret_context(key: &statement::KeyBinding) -> [Val; 8] {
    let values = key.values();
    let mut hash = Sha256::new();
    hash.update(b"DCS/GOLD-DATA-FORMATION/Cs528/N4096/packed-six-bit/v1");
    hash.update(data::profile_digest());
    for value in &values[..25] {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    words(hash.finalize().into())
}
/// Complete independently retained PUBLIC expectation; construction checks no proof.
#[derive(Clone)]
pub struct Expected {
    source: statement::Statement,
    core: data::Expected,
}
impl Expected {
    pub fn checked(request: &data::Request, source: &statement::Statement) -> Result<Self> {
        if source.expected.role() != Role::VersionSourceAllOriginal
            || source.expected.source_claim().relation != crate::source::Relation::StateCertificate
        {
            return Err(Error::Binding);
        }
        source
            .expected
            .source_claim()
            .reaudit()
            .map_err(|_| Error::Binding)?;
        let key = source.expected.key_binding().values();
        let contexts = [
            source.expected.encoding_context(),
            secret_context(source.expected.key_binding()),
        ];
        let roots = [
            source.encoded,
            key[25..29].try_into().map_err(|_| Error::Binding)?,
        ];
        let mut association = Sha512::new();
        association.update(b"DCS/two-lane-CoreGold/DATA-complete-association/v1");
        association.update(profile_digest());
        association.update((request.bytes().len() as u64).to_le_bytes());
        association.update(request.bytes());
        for value in source.values() {
            association.update(value.as_canonical_u64().to_le_bytes());
        }
        for bytes in source
            .expected
            .source_claim()
            .heads
            .iter()
            .map(|head| head.as_slice())
            .chain(
                source
                    .expected
                    .source_claim()
                    .packets
                    .iter()
                    .map(Vec::as_slice),
            )
        {
            association.update((bytes.len() as u64).to_le_bytes());
            association.update(bytes);
        }
        let core = data::Expected::checked(
            request.clone(),
            association.finalize().into(),
            contexts,
            roots,
        )?;
        Ok(Self {
            source: source.clone(),
            core,
        })
    }
    pub fn request(&self) -> &data::Request {
        self.core.request()
    }
    pub fn source(&self) -> &statement::Statement {
        &self.source
    }
    /// Read-only mathematical metadata for owner-side composition; no proof or
    /// Source/DATA admission, current head, key ownership or SQL permission.
    pub fn core_expected(&self) -> &data::Expected {
        &self.core
    }
    fn require_request(&self, request: &data::Request) -> Result<()> {
        if request.bytes() != self.request().bytes() {
            return Err(Error::Binding);
        }
        Ok(())
    }
    fn require_statement(&self, actual: &statement::Statement) -> Result<()> {
        actual
            .require_expected(&self.source.expected)
            .map_err(|_| Error::Binding)?;
        if actual.values() != self.source.values()
            || actual.expected.source_claim().heads != self.source.expected.source_claim().heads
            || actual.expected.source_claim().packets != self.source.expected.source_claim().packets
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
/// Bounded borrowed UNVERIFIED State and one child; no supplied verification token.
pub struct Prerequisites<'a> {
    state: &'a [u8],
    child: &'a [u8],
}
impl<'a> Prerequisites<'a> {
    pub fn checked(state: &'a [u8], child: &'a [u8]) -> Result<Self> {
        if state.is_empty()
            || state.len() > wire::MAX_SOURCE
            || child.is_empty()
            || child.len() > wire::MAX_CHILD
        {
            return Err(Error::ResourceLimit);
        }
        Ok(Self { state, child })
    }
    fn verify(&self, expected: &Expected) -> Result<wire::VerifiedEncoding> {
        let frame = wire::BorrowedFrame::parse(&expected.source.expected, self.child)?;
        expected.require_statement(frame.statement())?;
        let verified = wire::verify(&expected.source.expected, self.state, self.child)?;
        expected.require_statement(verified.statement())?;
        Ok(verified)
    }
}
/// Move-only owner-private final input. No raw-W/salt getter or public callback.
pub struct PrivateInputs {
    source: Witness,
    sdk_secret: Zeroizing<Vec<u8>>,
    cs_salt: Zeroizing<[u64; 4]>,
}
impl PrivateInputs {
    pub fn checked(
        source: Witness,
        sdk_secret: Zeroizing<Vec<u8>>,
        cs_salt: Zeroizing<[u64; 4]>,
    ) -> Result<Self> {
        if sdk_secret.len() != super::N + 3
            || sdk_secret[..3] != [0x0a, 0x80, 0x20]
            || sdk_secret[3..].iter().any(|byte| *byte > 40)
            || cs_salt.iter().any(|word| *word >= Val::ORDER_U64)
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            source,
            sdk_secret,
            cs_salt,
        })
    }
}
/// Explicit UNVERIFIED producer bytes; never SQL or source-version admission.
pub struct UnverifiedEvidence {
    core: data::UnverifiedDataFormationEvidence,
}
impl UnverifiedEvidence {
    pub fn as_bytes(&self) -> &[u8] {
        self.core.as_bytes()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.core.into_bytes()
    }
}
/// Freshly verify State+Role3, then consume the SAME final W/salt and SDK key.
/// Private MAIN is allocated only by the actual lower resource-gated producer.
pub fn prove(
    expected: &Expected,
    request: &data::Request,
    prerequisites: Prerequisites<'_>,
    private: PrivateInputs,
) -> Result<UnverifiedEvidence> {
    expected.require_request(request)?;
    private
        .source
        .require_expected(&expected.source.expected)
        .map_err(|_| Error::Binding)?;
    let verified = prerequisites.verify(expected)?;
    let PrivateInputs {
        source,
        sdk_secret,
        cs_salt,
    } = private;
    let opening = source.into_formation_opening(&expected.source)?;
    let secret = gold::SecretOpening::checked(
        expected.core.contexts()[1],
        expected.core.roots()[1],
        sdk_secret,
        cs_salt,
    )?;
    drop(verified);
    let prepared = data::Prepared::new(&expected.core, opening, secret)?;
    Ok(UnverifiedEvidence {
        core: data::prove(&expected.core, prepared)?,
    })
}
/// Move-only fresh mathematical DATA result; PUBLIC metadata only, no SQL/head grant.
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::data_formation::{Expected, VerifiedDataFormation};
/// fn forge(expected: Expected) -> VerifiedDataFormation { VerifiedDataFormation { expected } }
/// ```
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::data_formation::VerifiedDataFormation;
/// fn duplicate(value: &VerifiedDataFormation) -> VerifiedDataFormation { value.clone() }
/// ```
pub struct VerifiedDataFormation {
    expected: Expected,
}
impl VerifiedDataFormation {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
/// Fresh State+Role3 and actual cold DATA native verification on every invocation.
pub fn verify(
    expected: &Expected,
    request: &data::Request,
    prerequisites: Prerequisites<'_>,
    bytes: &[u8],
) -> Result<VerifiedDataFormation> {
    if bytes.is_empty() || bytes.len() > data::MAX_EVIDENCE_BYTES {
        return Err(Error::Formation(gold::Error::Resource));
    }
    expected.require_request(request)?;
    let verified = prerequisites.verify(expected)?;
    drop(verified);
    let verified = data::verify(&expected.core, bytes)?;
    drop(verified);
    Ok(VerifiedDataFormation {
        expected: expected.clone(),
    })
}
