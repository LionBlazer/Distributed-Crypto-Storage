//! Closed composition of fresh Source/encoding proofs with actual CoreGold Formation.
//! This mathematical boundary grants no SQL, authorization or version freshness.
use super::{Role, circuit::Witness, profile_digest as encoding_profile, statement, wire};
use bfv_ciphertext_formation::gold;
use bfv_hiding_stark::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "formation_tests.rs"]
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
            Self::Binding => f.write_str("Two-lane Formation association mismatch"),
            Self::ResourceLimit => f.write_str("Two-lane Formation resource limit"),
            Self::Prerequisite(e) => write!(f, "Two-lane Formation prerequisite: {e}"),
            Self::Formation(e) => write!(f, "Two-lane Formation proof: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<wire::Error> for Error {
    fn from(e: wire::Error) -> Self {
        Self::Prerequisite(e)
    }
}
impl From<gold::Error> for Error {
    fn from(e: gold::Error) -> Self {
        Self::Formation(e)
    }
}
type Result<T> = std::result::Result<T, Error>;

/// NEW upper composition identity, never an old Formation/App/profile relabel.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/two-lane-CoreGold/consuming-Formation/v1/no-SQL-no-freshness");
    h.update(encoding_profile(Role::SourceAllOriginal));
    h.update(encoding_profile(Role::PrivateMask));
    h.update(gold::profile_digest());
    h.update(b"fresh-original-Source-and-two-children/full-roles-values-heads-packets-key29;canonical-CoreGold-request-q-and-nonce;Cw4112-and-Cs528;consume-SAME-W-once-and-salts;no-double-SCALE;native-cold-receiving");
    h.finalize().into()
}
fn words(digest: [u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            digest[4 * i..4 * i + 4].try_into().expect("fixed word"),
        ))
    })
}
fn feed(h: &mut Sha512, values: impl IntoIterator<Item = Val>) {
    for v in values {
        h.update(v.as_canonical_u64().to_le_bytes());
    }
}
fn secret_context(key: &[Val]) -> Result<[Val; 8]> {
    if key.len() != 29 {
        return Err(Error::Binding);
    }
    let mut h = Sha256::new();
    h.update(b"DCS/GOLD-FORMATION/Cs528/N4096/packed-six-bit/v1");
    h.update(gold::profile_digest());
    for value in &key[..25] {
        h.update(value.as_canonical_u64().to_le_bytes());
    }
    Ok(words(h.finalize().into()))
}
/// Independently retained complete PUBLIC expectation. Its constructor verifies
/// metadata/canonical bytes, never the Source, key, Formation or current head.
#[derive(Clone)]
pub struct Expected {
    source: statement::Statement,
    mask: statement::Statement,
    core: gold::Expected,
}
impl Expected {
    pub fn checked(
        request: &gold::Request,
        source: &statement::Statement,
        mask: &statement::Statement,
    ) -> Result<Self> {
        source
            .expected
            .require_pair(&mask.expected)
            .map_err(|_| Error::Binding)?;
        source
            .expected
            .source_claim()
            .reaudit()
            .map_err(|_| Error::Binding)?;
        mask.expected
            .source_claim()
            .reaudit()
            .map_err(|_| Error::Binding)?;
        if source.expected.source_claim().request != request.q()
            || mask.expected.public_nonce() != request.nonce()
        {
            return Err(Error::Binding);
        }
        let key = source.expected.key_binding().values();
        if key.len() != 29 {
            return Err(Error::Binding);
        }
        // The first25 values are independent key identity. Cs is excluded from
        // its own context; request/q/Source/Cw are deliberately not in this scope.
        let contexts = [
            source.expected.encoding_context(),
            mask.expected.encoding_context(),
            secret_context(&key)?,
        ];
        let roots = [
            source.encoded,
            mask.encoded,
            key[25..29].try_into().map_err(|_| Error::Binding)?,
        ];
        let mut association = Sha512::new();
        association.update(b"DCS/two-lane-CoreGold/complete-association/v1");
        association.update(profile_digest());
        association.update((request.bytes().len() as u64).to_le_bytes());
        association.update(request.bytes());
        for s in [source, mask] {
            feed(&mut association, s.values());
            for bytes in s
                .expected
                .source_claim()
                .heads
                .iter()
                .map(|x| x.as_slice())
                .chain(s.expected.source_claim().packets.iter().map(Vec::as_slice))
            {
                association.update((bytes.len() as u64).to_le_bytes());
                association.update(bytes);
            }
        }
        let core = gold::Expected::checked(
            request.clone(),
            association.finalize().into(),
            contexts,
            roots,
        )?;
        Ok(Self {
            source: source.clone(),
            mask: mask.clone(),
            core,
        })
    }
    pub fn request(&self) -> &gold::Request {
        self.core.request()
    }
    pub fn source(&self) -> &statement::Statement {
        &self.source
    }
    pub fn private_mask(&self) -> &statement::Statement {
        &self.mask
    }
    fn require_request(&self, request: &gold::Request) -> Result<()> {
        if request.bytes() != self.request().bytes() {
            return Err(Error::Binding);
        }
        Ok(())
    }
    fn require_pair(&self, pair: &wire::VerifiedPair) -> Result<()> {
        self.require_statements(pair.source().statement(), pair.private_mask().statement())
    }
    fn require_statements(
        &self,
        source: &statement::Statement,
        mask: &statement::Statement,
    ) -> Result<()> {
        for (wanted, actual) in [(&self.source, source), (&self.mask, mask)] {
            actual
                .require_expected(&wanted.expected)
                .map_err(|_| Error::Binding)?;
            if actual.values() != wanted.values()
                || actual.expected.source_claim().heads != wanted.expected.source_claim().heads
                || actual.expected.source_claim().packets != wanted.expected.source_claim().packets
            {
                return Err(Error::Binding);
            }
        }
        Ok(())
    }
}

/// Borrowed UNVERIFIED evidence. Only size checks happen here; it is no receipt.
pub struct Prerequisites<'a> {
    original_source: &'a [u8],
    source_child: &'a [u8],
    mask_child: &'a [u8],
}
impl<'a> Prerequisites<'a> {
    pub fn checked(
        original_source: &'a [u8],
        source_child: &'a [u8],
        mask_child: &'a [u8],
    ) -> Result<Self> {
        if original_source.is_empty()
            || original_source.len() > wire::MAX_SOURCE
            || source_child.is_empty()
            || source_child.len() > wire::MAX_CHILD
            || mask_child.is_empty()
            || mask_child.len() > wire::MAX_CHILD
        {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            original_source,
            source_child,
            mask_child,
        })
    }
    fn verify(&self, expected: &Expected) -> Result<wire::VerifiedPair> {
        let source = wire::BorrowedFrame::parse(&expected.source.expected, self.source_child)?;
        let mask = wire::BorrowedFrame::parse(&expected.mask.expected, self.mask_child)?;
        expected.require_statements(source.statement(), mask.statement())?;
        let pair = wire::verify_pair(
            &expected.source.expected,
            &expected.mask.expected,
            self.original_source,
            self.source_child,
            self.mask_child,
        )?;
        expected.require_pair(&pair)?;
        Ok(pair)
    }
}

/// Move-only explicit owner inputs, never public coefficients or a stored grant.
/// The SDK key and salts are immediately consumed into the real lower builder.
pub struct PrivateInputs {
    source: Witness,
    mask: Witness,
    sdk_secret: Zeroizing<Vec<u8>>,
    cs_salt: Zeroizing<[u64; 4]>,
}
impl PrivateInputs {
    pub fn checked(
        source: Witness,
        mask: Witness,
        sdk_secret: Zeroizing<Vec<u8>>,
        cs_salt: Zeroizing<[u64; 4]>,
    ) -> Result<Self> {
        if sdk_secret.len() != super::N + 3
            || sdk_secret[..3] != [0x0a, 0x80, 0x20]
            || sdk_secret[3..].iter().any(|b| *b > 40)
            || cs_salt.iter().any(|v| *v >= Val::ORDER_U64)
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            source,
            mask,
            sdk_secret,
            cs_salt,
        })
    }
}

/// Explicit UNVERIFIED native Formation bytes; never a mathematical result.
pub struct UnverifiedEvidence {
    core: gold::UnverifiedFormationEvidence,
}
impl UnverifiedEvidence {
    pub fn as_bytes(&self) -> &[u8] {
        self.core.as_bytes()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.core.into_bytes()
    }
}

/// Consumes SAME final Source/mask Witnesses. Prerequisites are freshly verified
/// here, not supplied as an unchecked public status. No private MAIN is built
/// before complete context/pair/opening association and the lower resource gate.
pub fn prove(
    expected: &Expected,
    request: &gold::Request,
    prerequisites: Prerequisites<'_>,
    private: PrivateInputs,
) -> Result<UnverifiedEvidence> {
    expected.require_request(request)?;
    private
        .source
        .require_expected(&expected.source.expected)
        .map_err(|_| Error::Binding)?;
    private
        .mask
        .require_expected(&expected.mask.expected)
        .map_err(|_| Error::Binding)?;
    let PrivateInputs {
        source,
        mask,
        sdk_secret,
        cs_salt,
    } = private;
    let secret = gold::SecretOpening::checked(
        expected.core.contexts()[2],
        expected.core.roots()[2],
        sdk_secret,
        cs_salt,
    )?;
    let pair = prerequisites.verify(expected)?;
    // No callback/public getter can detach the salt or reinterpret role/scale.
    let source = source.into_formation_opening(&expected.source)?;
    let mask = mask.into_formation_opening(&expected.mask)?;
    drop(pair);
    let prepared = gold::Prepared::new(&expected.core, [source, mask], secret)?;
    Ok(UnverifiedEvidence {
        core: gold::prove(&expected.core, prepared)?,
    })
}

/// Fresh actual receiving composition, with no cache or serialized checked flag.
/// The result contains only independently retained public expectation metadata.
///
/// Consumers cannot forge the actual private result field:
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::formation::{Expected, VerifiedFormation};
/// fn forge(expected: Expected) -> VerifiedFormation { VerifiedFormation { expected } }
/// ```
/// The result is move-only:
/// ```compile_fail
/// use registry200_proof::two_lane_encoding::formation::VerifiedFormation;
/// fn duplicate(value: &VerifiedFormation) -> VerifiedFormation { value.clone() }
/// ```
pub struct VerifiedFormation {
    expected: Expected,
}
impl VerifiedFormation {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}
pub fn verify(
    expected: &Expected,
    request: &gold::Request,
    prerequisites: Prerequisites<'_>,
    bytes: &[u8],
) -> Result<VerifiedFormation> {
    if bytes.is_empty() || bytes.len() > gold::MAX_EVIDENCE_BYTES {
        return Err(Error::Formation(gold::Error::Resource));
    }
    expected.require_request(request)?;
    let pair = prerequisites.verify(expected)?;
    drop(pair);
    let verified = gold::verify(&expected.core, bytes)?;
    drop(verified);
    Ok(VerifiedFormation {
        expected: expected.clone(),
    })
}
