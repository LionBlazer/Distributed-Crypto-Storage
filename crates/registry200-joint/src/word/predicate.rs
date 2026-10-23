//! Self-contained, canonical UNVERIFIED public Predicate endpoints and evidence.
//! This codec grants no proof verdict, journal import, SQL result or lock.
pub mod transport;
use super::{Error, Result};
use bfv_ciphertext_formation::gold::{data, query as fused};
use bfv_query_core::gold::{self, PublicRequest};
use bfv_unrelinearized_product as product;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{
    Val,
    registry_progress::word as math,
    source::{self, version::SourceVersionExpected},
    two_lane_encoding::{self as encoding, data_formation as installed, statement::KeyBinding},
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"DCSWJP02";
const HEADER: usize = 416;
const BODY_RESERVE: usize = 4096;
/// Leave a fixed reserve for the actual signed journal body and its request.
/// The eventual journal author must still check its complete encoded body.
pub const MAX_PREDICATE_PACKET_BYTES: usize = version_journal::MAX_BODY_BYTES - BODY_RESERVE;
const CAPS: [usize; 8] = [
    gold::MAX_REQUEST_BYTES,
    gold::MAX_PRODUCT_OUTPUT_BYTES,
    source::version::MAX_CERTIFICATE_BYTES,
    encoding::hash::MAX_EVIDENCE_BYTES,
    data::hash::MAX_EVIDENCE_BYTES,
    math::hash::MAX_EVIDENCE_BYTES,
    fused::hash::MAX_EVIDENCE_BYTES,
    product::CERTIFICATE_BYTES,
];

/// Encoding identity only, with no accepting proof or joint-admission authority.
/// It deliberately does not depend on the enclosing journal contract identity.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/Word-Predicate-packet/v2/DCSWJP02/UNVERIFIED/no-admission");
    h.update(math::read::hash::profile_digest());
    h.update(gold::profile_digest());
    h.update(product::wire_profile_digest());
    h.update(b"independent-Source;DATA-nonce32/key29LE64/vector4LE64/Cw4LE64;original-GOPREQ/CT3/SHA-State/Role3/DATA/Word/Query/product;explicit-canonical-Cw/full-derived-DATA-binding;original-ordered-pair-and-nonce;fixed-header416/reserved-zero/exact-total-and-EOF/no-verdict/no-old-frame-fallback");
    for n in [HEADER, BODY_RESERVE, MAX_PREDICATE_PACKET_BYTES]
        .into_iter()
        .chain(CAPS)
    {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}

fn require_lengths(lengths: [usize; 8]) -> Result<usize> {
    let mut total = HEADER;
    for (length, cap) in lengths.into_iter().zip(CAPS) {
        if length == 0 || length > cap {
            return Err(Error::ResourceLimit);
        }
        total = total.checked_add(length).ok_or(Error::ResourceLimit)?;
    }
    if lengths[7] != product::CERTIFICATE_BYTES {
        return Err(Error::InvalidEncoding);
    }
    if total > MAX_PREDICATE_PACKET_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(total)
}

fn bytes<const N: usize>(words: &[u64]) -> Result<[u8; N]> {
    if words.len() * 4 != N {
        return Err(Error::InvalidEncoding);
    }
    let mut out = [0; N];
    for (chunk, &word) in out.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = u32::try_from(word)
            .map_err(|_| Error::InvalidEncoding)?
            .to_le_bytes();
    }
    Ok(out)
}

fn key_from_words(words: [u64; 29]) -> Result<KeyBinding> {
    if words[..25].iter().any(|&v| v > u64::from(u32::MAX))
        || words[25..].iter().any(|&v| v >= Val::ORDER_U64)
    {
        return Err(Error::InvalidEncoding);
    }
    let coefficients = core::array::from_fn(|i| Val::from_u64(words[25 + i]));
    let key = KeyBinding::new(
        bytes(&words[..4])?,
        bytes(&words[4..8])?,
        u32::try_from(words[8]).map_err(|_| Error::InvalidEncoding)?,
        bytes(&words[17..25])?,
        source::statement::encode_digest(coefficients),
    )
    .map_err(|_| Error::WrongDomain)?;
    // This checks the fixed parameter digest as well as every reconstructed word.
    if key
        .values()
        .into_iter()
        .map(|v| v.as_canonical_u64())
        .ne(words)
    {
        return Err(Error::WrongDomain);
    }
    Ok(key)
}

// Shared canonical full header, never a proof or a packet-extent assertion.
// Transport compaction keeps these exact original bytes and all eight lengths.
struct Header {
    nonce: [u8; 32],
    words: [u64; 37],
    lengths: [usize; 8],
    total: usize,
}
impl Header {
    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != HEADER || &raw[..8] != MAGIC || raw[408..] != [0; 8] {
            return Err(Error::InvalidEncoding);
        }
        if raw[8..40] != profile_digest() {
            return Err(Error::WrongDomain);
        }
        let nonce = raw[48..80].try_into().unwrap();
        if nonce == [0; 32] {
            return Err(Error::WrongDomain);
        }
        let words: [u64; 37] = core::array::from_fn(|i| {
            u64::from_le_bytes(raw[80 + 8 * i..88 + 8 * i].try_into().unwrap())
        });
        if words[..25].iter().any(|&v| v > u64::from(u32::MAX))
            || words[25..].iter().any(|&v| v >= Val::ORDER_U64)
        {
            return Err(Error::InvalidEncoding);
        }
        let lengths = core::array::from_fn(|i| {
            u32::from_le_bytes(raw[376 + 4 * i..380 + 4 * i].try_into().unwrap()) as usize
        });
        let total = require_lengths(lengths)?;
        if u64::from_le_bytes(raw[40..48].try_into().unwrap()) != total as u64 {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            nonce,
            words,
            lengths,
            total,
        })
    }
    fn data_expected(
        &self,
        source: &SourceVersionExpected,
        request: &PublicRequest,
    ) -> Result<installed::Expected> {
        let statement = encoding::statement::Statement {
            expected: encoding::statement::Expected::source_version(
                source,
                key_from_words(self.words[..29].try_into().unwrap())?,
            )
            .map_err(|_| Error::WrongDomain)?,
            encoded: core::array::from_fn(|i| Val::from_u64(self.words[33 + i])),
        };
        let request_data = data::Request::checked(self.nonce, request.data_ciphertext().to_vec())
            .map_err(|_| Error::InvalidEncoding)?;
        let data = installed::Expected::checked(&request_data, &statement)
            .map_err(|_| Error::WrongDomain)?;
        if data.core_expected().binding() != request.data_binding()
            || data.request().ciphertext() != request.data_ciphertext()
        {
            return Err(Error::WrongDomain);
        }
        Ok(data)
    }
}

/// Owned canonical packet bytes, still UNVERIFIED. No accepted flag is encoded.
pub struct PredicatePacket {
    bytes: Vec<u8>,
}
impl PredicatePacket {
    /// Export the exact original public endpoints and all six unverified frames.
    /// Metadata/codec consistency is checked; no native proof is verified here.
    pub fn from_read(
        expected: &math::read::Expected,
        request: &PublicRequest,
        evidence: math::read::Evidence<'_>,
    ) -> Result<Self> {
        let output = expected.product_expected().output_wire();
        let payload = [
            request.as_bytes(),
            output,
            evidence.state,
            evidence.child,
            evidence.data,
            evidence.word,
            evidence.query,
            evidence.product,
        ];
        let total = require_lengths(payload.map(<[u8]>::len))?;
        let data = expected.data_expected();
        let original = request
            .formation_request()
            .map_err(|_| Error::WrongDomain)?;
        if expected.word_expected().role() != math::Role::Predicate
            || request.data_binding() != data.core_expected().binding()
            || request.data_ciphertext() != data.request().ciphertext()
            || expected.product_expected().nonce() != original.nonce()
            || expected.product_expected().input_wires() != original.ciphertexts()
            || request.binding().context()
                != <[u8; 32]>::from(Sha256::digest(expected.word_expected().binding()))
        {
            return Err(Error::WrongDomain);
        }
        let key = data.source().expected.key_binding().values();
        if key.len() != 29 {
            return Err(Error::InvalidEncoding);
        }
        let vector = expected.query_expected().core_expected().roots()[0];
        let cw = data.source().encoded;
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(MAGIC);
        header[8..40].copy_from_slice(&profile_digest());
        header[40..48].copy_from_slice(&(total as u64).to_le_bytes());
        header[48..80].copy_from_slice(&data.request().nonce());
        for (chunk, value) in header[80..376]
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(key.into_iter().chain(vector).chain(cw))
        {
            *chunk = value.as_canonical_u64().to_le_bytes();
        }
        for (chunk, frame) in header[376..408]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(payload)
        {
            *chunk = u32::try_from(frame.len())
                .map_err(|_| Error::ResourceLimit)?
                .to_le_bytes();
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend(header);
        for frame in payload {
            bytes.extend_from_slice(frame);
        }
        let parsed = BorrowedPredicate::parse(expected.word_expected().source(), &bytes)?;
        let restored = parsed.expected(expected.word_expected())?;
        if restored.data_expected().core_expected().binding() != data.core_expected().binding()
            || restored.query_expected().binding() != expected.query_expected().binding()
            || restored.product_expected().request_wire()
                != expected.product_expected().request_wire()
            || restored.product_expected().output_wire() != output
        {
            return Err(Error::WrongDomain);
        }
        Ok(Self { bytes })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Bounded original public metadata and borrowed proof frames, with no verdict.
/// The Source pin belongs to the receiver; candidate bytes cannot replace it.
pub struct BorrowedPredicate<'a> {
    data: installed::Expected,
    request: PublicRequest,
    vector: [Val; 4],
    output: &'a [u8],
    frames: [&'a [u8]; 6],
}
impl<'a> BorrowedPredicate<'a> {
    pub fn parse(source: &SourceVersionExpected, raw: &'a [u8]) -> Result<Self> {
        if raw.len() > MAX_PREDICATE_PACKET_BYTES {
            return Err(Error::ResourceLimit);
        }
        if raw.len() < HEADER {
            return Err(Error::InvalidEncoding);
        }
        let header = Header::parse(&raw[..HEADER])?;
        if header.total != raw.len() {
            return Err(Error::InvalidEncoding);
        }
        let mut payload = [&[][..]; 8];
        let mut at = HEADER;
        for (out, length) in payload.iter_mut().zip(header.lengths) {
            let end = at.checked_add(length).ok_or(Error::ResourceLimit)?;
            *out = raw.get(at..end).ok_or(Error::InvalidEncoding)?;
            at = end;
        }
        // Header/range/extent validation above precedes all decoded allocation.
        // Each nested parser independently enforces its own canonical wire caps.
        let request = PublicRequest::decode(payload[0]).map_err(|_| Error::InvalidEncoding)?;
        // SHA Role3 binds a complete independently supplied Statement; its
        // frame exports no Cw. These canonical packet fields remain unverified
        // until the actual SHA Role3 argument is checked by the receiver.
        let data = header.data_expected(source, &request)?;
        let original = request
            .formation_request()
            .map_err(|_| Error::WrongDomain)?;
        // Parse all original Ct3 residues now; this executes no FHE operation and
        // verifies no product certificate or other proof.
        drop(
            product::Expected::checked(
                original.nonce(),
                original.ciphertexts().map(<[u8]>::to_vec),
                payload[1].to_vec(),
            )
            .map_err(|_| Error::InvalidEncoding)?,
        );
        Ok(Self {
            data,
            request,
            vector: core::array::from_fn(|i| Val::from_u64(header.words[29 + i])),
            output: payload[1],
            frames: payload[2..].try_into().unwrap(),
        })
    }
    /// Derive the complete expectation from an independently retained Word claim.
    /// No packet field can supply or replace that journal/owner expectation.
    pub fn expected(&self, word: &math::Expected) -> Result<math::read::Expected> {
        if self.request.binding().context() != <[u8; 32]>::from(Sha256::digest(word.binding())) {
            return Err(Error::WrongDomain);
        }
        math::read::Expected::checked(
            word,
            &self.data,
            &self
                .request
                .formation_request()
                .map_err(|_| Error::WrongDomain)?,
            self.vector,
            self.output.to_vec(),
        )
        .map_err(|_| Error::WrongDomain)
    }
    pub fn evidence(&self) -> math::read::Evidence<'a> {
        math::read::Evidence {
            state: self.frames[0],
            child: self.frames[1],
            data: self.frames[2],
            word: self.frames[3],
            query: self.frames[4],
            product: self.frames[5],
        }
    }
    pub fn public_request(&self) -> &PublicRequest {
        &self.request
    }
    pub fn data_expected(&self) -> &installed::Expected {
        &self.data
    }
}
