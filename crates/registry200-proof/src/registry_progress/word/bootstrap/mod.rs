//! SourceVersion-first EMPTY208 mathematics for the original Word registry domain.
//! No enrollment authorization, head freshness, consensus or SQL admission is granted.
mod backend;
#[cfg(test)]
mod tests;
use super::{Claims, Expected as WordExpected, Role, SourceOpening};
use crate::{
    Val,
    source::{self, version::SourceVersionExpected},
};
use bfv_hiding_stark::{self as engine, codec};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const HEADER_BYTES: usize = 120;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;
pub const PUBLIC_VALUES: usize = 265;
const MAGIC: &[u8; 8] = b"DCSWEB01";
const DOMAIN: &[u8] = b"DCS/Word208/EMPTY/StateVersion/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Binding,
    Resource,
    Encoding,
    Prerequisite,
    Backend(crate::BackendError),
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Word EMPTY208 rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<crate::BackendError> for Error {
    fn from(e: crate::BackendError) -> Self {
        Self::Backend(e)
    }
}
impl From<codec::Error> for Error {
    fn from(e: codec::Error) -> Self {
        match e {
            codec::Error::Shape => Self::Shape,
            codec::Error::Encoding => Self::Encoding,
            codec::Error::ResourceLimit => Self::Resource,
        }
    }
}
pub type Result<T> = core::result::Result<T, Error>;

pub fn profile_digest() -> [u8; 32] {
    let mut h = engine::profile_start(DOMAIN, b"Source680/Enrollment64/EmptyRegistry208");
    h.update(super::profile_digest());
    h.update(
        b"original-Word-headers/table-ids/source-opening/nonzero-controllers/full-empty-fields",
    );
    for n in [PUBLIC_VALUES, 680, 64, 208, 85, 93, 119] {
        h.update((n as u64).to_le_bytes());
    }
    engine::profile_finish(h, backend::WIDTH, 2)
}

/// Independently retained complete Source/genesis/enrollment/EMPTY-root claim.
/// Construction reaudits metadata but authenticates no proof or enrollment authority.
#[derive(Clone)]
pub struct Expected {
    word: WordExpected,
}
impl Expected {
    pub fn checked(
        source: &SourceVersionExpected,
        genesis: [u8; 32],
        enrollment: [Val; 4],
        root: [Val; 4],
    ) -> Result<Self> {
        let word = WordExpected::checked(
            source,
            Role::Control,
            genesis,
            [0; 32],
            enrollment,
            Claims {
                old: root,
                next: root,
                command: [Val::ZERO; 4],
                statement: [Val::ZERO; 4],
                result: [Val::ZERO; 4],
                blind_sql: [Val::ZERO; 8],
            },
        )
        .map_err(|_| Error::Shape)?;
        Ok(Self { word })
    }
    pub fn source(&self) -> &SourceVersionExpected {
        self.word.source()
    }
    pub fn root(&self) -> [Val; 4] {
        self.word.claims().old
    }
    pub fn enrollment(&self) -> [Val; 4] {
        self.word.inner.enrollment
    }
    pub fn registry_header(&self) -> &[Val; 33] {
        self.word.registry_header()
    }
    pub fn enrollment_header(&self) -> &[Val; 33] {
        self.word.enrollment_header()
    }
    pub fn binding(&self) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(DOMAIN);
        h.update(profile_digest());
        h.update(self.word.binding());
        h.finalize().into()
    }
    fn values(&self) -> [Val; PUBLIC_VALUES] {
        let s = self.source().statement();
        let mut v = source::statement::words(&profile_digest()).collect::<Vec<_>>();
        v.extend(self.word.context());
        v.extend(self.registry_header());
        v.extend(self.enrollment_header());
        v.extend(&source::commitment::prefix(s, [Val::ZERO; 4])[..83]);
        v.extend(s.open_commitment);
        v.extend(self.root());
        v.try_into().expect("fixed complete EMPTY265 public values")
    }
}

/// Move-only original private opening. No public raw access or serialization.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::bootstrap::PrivateInputs;
/// fn duplicate(value: &PrivateInputs) -> PrivateInputs { value.clone() }
/// ```
pub struct PrivateInputs {
    expected: Expected,
    plain: Zeroizing<[u8; 2348]>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 3]>,
}
impl PrivateInputs {
    /// SourceOpening supplies the Source salt; salts here are enrollment/registry.
    /// Fresh secret blinding belongs to the owner; this API never selects it.
    pub fn checked(
        expected: &Expected,
        source: SourceOpening,
        controllers: Zeroizing<[[u8; 32]; 2]>,
        salts: Zeroizing<[[u64; 4]; 2]>,
    ) -> Result<Self> {
        if controllers.contains(&[0; 32]) || salts.iter().flatten().any(|&x| x >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        let (plain, source_salt) = source.into_bootstrap();
        let salts = Zeroizing::new([*source_salt, salts[0], salts[1]]);
        let out = Self {
            expected: expected.clone(),
            plain,
            controllers,
            salts,
        };
        // Early owner diagnostics are not a verification capability. The same
        // actual preimages and fixed empty constants are constrained in the AIR.
        let native = out.salts.map(|s| s.map(Val::from_u64));
        let mut opening = source::commitment::opening_fields(
            expected.source().statement(),
            native[0],
            &out.plain[..],
        );
        let source_root = source::commitment::digest(&opening);
        opening.fill(Val::ZERO);
        if source_root != expected.source().statement().open_commitment {
            return Err(Error::Binding);
        }
        let mut enrollment = [Val::ZERO; 64];
        enrollment[..33].copy_from_slice(expected.enrollment_header());
        for (out, word) in enrollment[33..41]
            .iter_mut()
            .zip(source::statement::words(&out.plain[124..156]))
        {
            *out = word;
        }
        enrollment[41..43].copy_from_slice(&[Val::TWO, Val::ONE]);
        for (out, word) in enrollment[43..51]
            .iter_mut()
            .zip(source::statement::words(&out.controllers[0]))
        {
            *out = word;
        }
        enrollment[51] = Val::TWO;
        for (out, word) in enrollment[52..60]
            .iter_mut()
            .zip(source::statement::words(&out.controllers[1]))
        {
            *out = word;
        }
        enrollment[60..64].copy_from_slice(&native[1]);
        let enrollment_root = fixed_root(&enrollment);
        enrollment.fill(Val::ZERO);
        if enrollment_root != expected.enrollment() {
            return Err(Error::Binding);
        }
        let mut registry = [Val::ZERO; 208];
        registry[..33].copy_from_slice(expected.registry_header());
        registry[33..37].copy_from_slice(&expected.enrollment());
        for (out, word) in registry[37..45]
            .iter_mut()
            .zip(source::statement::words(&out.plain[124..156]))
        {
            *out = word;
        }
        for (out, word) in registry[45..77]
            .iter_mut()
            .zip(source::statement::words(&out.plain[2220..2348]))
        {
            *out = word;
        }
        registry[77..80].copy_from_slice(&[Val::TWO, Val::from_u8(4), Val::TWO]);
        registry[190..194].copy_from_slice(&native[2]);
        let root = fixed_root(&registry);
        registry.fill(Val::ZERO);
        if root != expected.root() {
            return Err(Error::Binding);
        }
        Ok(out)
    }
}
fn fixed_root(fields: &[Val]) -> [Val; 4] {
    assert!(matches!(fields.len(), 64 | 208));
    let mut state = [Val::ZERO; 12];
    let mut scratch = [Val::ZERO; crate::poseidon::WIDTH];
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        state = crate::poseidon::write(&mut scratch, state);
    }
    scratch.fill(Val::ZERO);
    let root = state[..4].try_into().unwrap();
    state.fill(Val::ZERO);
    root
}

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
/// Actual native SourceVersion and EMPTY208 verification, without freshness/admission.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::bootstrap::{Expected, VerifiedBootstrap};
/// fn forge(expected: Expected) -> VerifiedBootstrap { VerifiedBootstrap { expected } }
/// ```
/// ```compile_fail
/// use registry200_proof::registry_progress::word::bootstrap::VerifiedBootstrap;
/// fn duplicate(value: &VerifiedBootstrap) -> VerifiedBootstrap { value.clone() }
/// ```
pub struct VerifiedBootstrap {
    expected: Expected,
}
impl VerifiedBootstrap {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}

fn header(expected: &Expected, n: usize) -> Result<Vec<u8>> {
    if n == 0 || n > MAX_PROOF_BYTES {
        return Err(Error::Resource);
    }
    let mut out = Vec::with_capacity(HEADER_BYTES);
    out.extend(MAGIC);
    out.extend([1, 0, 0, 0, 0, 0, 0, 0]);
    out.extend(profile_digest());
    out.extend(expected.binding());
    out.extend((n as u32).to_le_bytes());
    out.extend([0; 4]);
    Ok(out)
}
fn payload<'a>(expected: &Expected, bytes: &'a [u8]) -> Result<&'a [u8]> {
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(Error::Resource);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(Error::Encoding);
    }
    let n = u32::from_le_bytes(bytes[112..116].try_into().unwrap()) as usize;
    if bytes[..HEADER_BYTES] != header(expected, n)? {
        return Err(Error::Binding);
    }
    if HEADER_BYTES.checked_add(n) != Some(bytes.len()) {
        return Err(Error::Encoding);
    }
    Ok(&bytes[HEADER_BYTES..])
}
/// Unverified native producer output. Both caller expectation and Source proof are mandatory.
pub fn prove(
    expected: &Expected,
    inputs: PrivateInputs,
    source_bytes: &[u8],
) -> Result<UnverifiedEvidence> {
    if inputs.expected.binding() != expected.binding() {
        return Err(Error::Binding);
    }
    source::version::verify(expected.source(), source_bytes).map_err(|_| Error::Prerequisite)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let backend = backend::Backend::new(expected)?;
        let trace = backend
            .air
            .trace(&inputs.plain, &inputs.controllers, &inputs.salts);
        let proof = backend.prove(trace)?;
        let child = codec::serialize(&proof, &backend.shape, MAX_PROOF_BYTES)?;
        let mut bytes = header(expected, child.len())?;
        bytes.extend(child);
        Ok(UnverifiedEvidence { bytes })
    }))
    .map_err(|_| Error::Verification)?
}
/// Complete bounded frame and actual independent native prerequisite/child receiving.
pub fn verify(expected: &Expected, source_bytes: &[u8], bytes: &[u8]) -> Result<VerifiedBootstrap> {
    let child = payload(expected, bytes)?;
    source::version::verify(expected.source(), source_bytes).map_err(|_| Error::Prerequisite)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let backend = backend::Backend::new(expected)?;
        let proof = codec::decode(child, &backend.shape, 16_384, 16 * 1024 * 1024)?;
        backend.verify(&proof)?;
        Ok(VerifiedBootstrap {
            expected: expected.clone(),
        })
    }))
    .map_err(|_| Error::Verification)?
}
