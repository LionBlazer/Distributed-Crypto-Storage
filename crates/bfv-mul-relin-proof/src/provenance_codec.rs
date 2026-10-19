//! Bounded public prover-job claims. No proof or independently trusted anchor is decoded.
use crate::{Error, Provenance, Result, profile_digest};
use bfv_query_core::{BfvKeyAnchor, PublicSetup};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    coefficient_encoding::statement::{BfvBinding, Expected, Statement},
    source::{self, Relation},
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"BFVMPV01";
const SOURCE_BYTES: usize = 32 + 2 * 112 + 60 + 2384 + 2 * 32;
const KEY_BYTES: usize = 16 + 16 + 32 + 4 + 2 * 32;
const HEADER: usize =
    8 + 64 + 32 + 64 + BfvKeyAnchor::CLAIM_BYTES + SOURCE_BYTES + KEY_BYTES + 32 + 4 * 32 + 2 * 4;

/// Maximum public metadata claim including both complete original ciphertexts.
/// Setup, proofs, output ciphertext, plaintext SQL/mask and private openings are absent.
/// This is an allocation/framing bound, not proof or transport admission.
pub const MAX_PROVENANCE_CLAIM_BYTES: usize =
    HEADER + 2 * bfv_ciphertext_wire::MAX_CIPHERTEXT_BYTES;

fn root(out: &mut Vec<u8>, values: [Val; 4]) {
    out.extend_from_slice(&source::statement::encode_digest(values));
}

impl Provenance {
    /// Encode the fixed original-input association, not a verification receipt.
    /// Every Source691 and both full encoding statements are reconstructed from
    /// these canonical public fields. No output claim or setup duplicate is sent.
    pub fn encode_claim(&self) -> Result<Vec<u8>> {
        let source = self.encodings()[0].expected.source_claim();
        let key = self.encodings()[0].expected.bfv().key();
        let predicate = &self.encodings()[1];
        let material = self
            .setup()
            .relinearization_material()
            .map_err(|_| Error::Statement)?;
        if key.expected.descriptor.public_setup_digest
            != <[u8; 32]>::from(Sha256::digest(material.parameters()))
        {
            return Err(Error::Statement);
        }
        let size = self.ciphertexts().iter().try_fold(HEADER, |size, bytes| {
            size.checked_add(bytes.len()).ok_or(Error::ResourceLimit)
        })?;
        if size > MAX_PROVENANCE_CLAIM_BYTES {
            return Err(Error::ResourceLimit);
        }
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&profile_digest());
        out.extend_from_slice(&self.anchor().full_setup_id());
        out.extend_from_slice(&self.original_setup_digest());
        out.extend_from_slice(&self.anchor().encode_claim().map_err(|_| Error::Statement)?);
        out.extend_from_slice(&source.request);
        for head in &source.heads {
            out.extend_from_slice(head);
        }
        for packet in &source.packets {
            out.extend_from_slice(packet);
        }
        root(&mut out, source.key_commitment);
        root(&mut out, source.open_commitment);
        out.extend_from_slice(&key.expected.descriptor.bytes());
        root(&mut out, key.expected.coefficients);
        root(&mut out, key.transformed);
        root(&mut out, self.encodings()[0].encoded);
        out.extend_from_slice(&predicate.expected.sql_identity());
        out.extend_from_slice(&predicate.expected.public_nonce());
        root(&mut out, predicate.expected.command());
        root(&mut out, predicate.encoded);
        for bytes in self.ciphertexts() {
            out.extend_from_slice(
                &u32::try_from(bytes.len())
                    .map_err(|_| Error::ResourceLimit)?
                    .to_le_bytes(),
            );
        }
        debug_assert_eq!(out.len(), HEADER);
        for bytes in self.ciphertexts() {
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }

    /// Rebuild mathematical claims for an already installed original setup.
    ///
    /// A peer may choose every label in this message, including its anchor claim.
    /// Decoding supplies no Owner, Key, Source, Formation, freshness or SQL
    /// authority. A client must retain its LOCAL independently pinned provenance
    /// when building Expected; it must never replace that pin with this result.
    /// The public prover must still call `verify_inputs` on all fifteen frames.
    pub fn decode_claim(setup: PublicSetup, bytes: &[u8]) -> Result<Self> {
        // The only variable lengths are two bounded complete ciphertexts. Check
        // their exact sum, canonical grammar and every Gold root before any
        // attacker-sized Vec or SDK evaluation-key/polynomial allocation.
        if bytes.len() < HEADER || bytes.len() > MAX_PROVENANCE_CLAIM_BYTES {
            return Err(Error::ResourceLimit);
        }
        if &bytes[..8] != MAGIC || bytes[8..72] != profile_digest() {
            return Err(Error::Statement);
        }
        let lengths: [usize; 2] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                bytes[HEADER - 8 + 4 * i..HEADER - 4 + 4 * i]
                    .try_into()
                    .unwrap(),
            ) as usize
        });
        let mut end = HEADER;
        for length in lengths {
            if length == 0 || length > bfv_ciphertext_wire::MAX_CIPHERTEXT_BYTES {
                return Err(Error::ResourceLimit);
            }
            end = end.checked_add(length).ok_or(Error::ResourceLimit)?;
        }
        if end != bytes.len() {
            return Err(Error::Statement);
        }
        let ciphertexts = [
            &bytes[HEADER..HEADER + lengths[0]],
            &bytes[HEADER + lengths[0]..],
        ];
        for ciphertext in ciphertexts {
            bfv_ciphertext_wire::parse(ciphertext).map_err(|error| match error {
                bfv_ciphertext_wire::WireError::ResourceLimit => Error::ResourceLimit,
                bfv_ciphertext_wire::WireError::InvalidEncoding => Error::Statement,
            })?;
        }
        let mut read = Reader {
            bytes: &bytes[..HEADER],
            at: 72,
        };
        let setup_id: [u8; 32] = read.array();
        let setup_digest: [u8; 64] = read.array();
        let anchor_bytes: [u8; BfvKeyAnchor::CLAIM_BYTES] = read.array();
        let request = read.array();
        let heads = [read.array(), read.array()];
        let packets = [read.array::<60>().to_vec(), read.array::<2384>().to_vec()];
        let key_commitment = read.root()?;
        let open_commitment = read.root()?;
        let descriptor = bfv_key_transform::SetupDescriptor {
            database: read.array(),
            key_domain: read.array(),
            public_setup_digest: read.array(),
            key_epoch: u32::from_le_bytes(read.array()),
        };
        let key = bfv_key_transform::Statement {
            expected: bfv_key_transform::Expected {
                descriptor,
                coefficients: read.root()?,
            },
            transformed: read.root()?,
        };
        let source_root = read.root()?;
        let sql_identity = read.array();
        let public_nonce = read.array();
        let command = read.root()?;
        let predicate_root = read.root()?;
        debug_assert_eq!(read.at, HEADER - 8);

        let anchor = setup
            .decode_key_anchor_claim(&anchor_bytes)
            .map_err(|_| Error::Statement)?;
        if anchor.full_setup_id() != setup_id {
            return Err(Error::Statement);
        }
        let source = CanonicalSource::checked_claim(&source::Statement {
            relation: Relation::CanonicalIndex,
            request,
            heads,
            packets,
            key_commitment,
            open_commitment,
        })
        .map_err(|_| Error::Statement)?;
        let binding = BfvBinding::new(setup_id, key);
        let encodings = [
            Statement {
                expected: Expected::source(&source, binding.clone())
                    .map_err(|_| Error::Statement)?,
                encoded: source_root,
            },
            Statement {
                expected: Expected::private_mask(
                    &source,
                    binding,
                    sql_identity,
                    public_nonce,
                    source::statement::encode_digest(command),
                )
                .map_err(|_| Error::Statement)?,
                encoded: predicate_root,
            },
        ];
        let provenance = Self::new(setup, anchor, encodings, ciphertexts.map(<[u8]>::to_vec))?;
        if provenance.original_setup_digest() != setup_digest || provenance.encode_claim()? != bytes
        {
            return Err(Error::Statement);
        }
        Ok(provenance)
    }
}

// All reads are compile-time sizes from the already checked fixed header. No
// submitted count controls indexing or allocation; root conversion rejects aliases.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let value = self.bytes[self.at..self.at + N].try_into().unwrap();
        self.at += N;
        value
    }
    fn root(&mut self) -> Result<[Val; 4]> {
        let values: [u64; 4] = core::array::from_fn(|_| u64::from_le_bytes(self.array()));
        if values.iter().any(|v| *v >= Val::ORDER_U64) {
            return Err(Error::Statement);
        }
        Ok(values.map(Val::from_u64))
    }
}

#[cfg(test)]
mod tests;
