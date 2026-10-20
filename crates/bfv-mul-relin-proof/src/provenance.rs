//! Public input provenance for the fixed two-operand MulRelin statement.
//!
//! These owned claims are not verification receipts. The anchor must come from
//! the caller's independently trusted owner/application. Neither its setup label
//! nor this composition proves that the public relinearization key uses the same
//! secret, supplies a fresh agreed head, or authorizes SQL admission.
use crate::Error;
use bfv_ciphertext_formation::{EncodedCommitment, Expected as FormationExpected};
use bfv_query_core::{BfvKeyAnchor, PublicSetup};
use p3_field::PrimeField64;
use registry200_proof::coefficient_encoding::{
    Role,
    statement::Statement as EncodingStatement,
    wire::{self, BorrowedFrame},
};
use sha2::{Digest, Sha256, Sha512};

const KEY_FRAME_BYTES: usize = bfv_key_transform::HEADER_BYTES + bfv_key_transform::MAX_PROOF_BYTES;
const BASIS_FRAME_BYTES: usize =
    bfv_basis_convolution::HEADER_BYTES + bfv_basis_convolution::MAX_PROOF_BYTES;
const FORMATION_FRAME_BYTES: usize =
    bfv_ciphertext_formation::HEADER_BYTES + bfv_ciphertext_formation::MAX_PROOF_BYTES;

/// Worst-case sum of the existing fifteen bounded wire frames: one Key, two
/// Source/Encoding pairs, ten Basis components and two Formation components.
/// Both copies of Source count toward this limit, even though they must be equal.
/// This is a collection limit, not a new aggregate transport or Journal format.
pub const MAX_INPUT_BYTES: usize =
    KEY_FRAME_BYTES + 2 * wire::MAX_FRAME + 10 * BASIS_FRAME_BYTES + 2 * FORMATION_FRAME_BYTES;

/// Number and order of individual input frames, never one aggregate proof blob.
pub const INPUT_FRAMES: usize = 15;

/// Existing proof codec byte cap for one fixed input role. This is not a
/// verification result, transport policy, or permission to allocate that size.
pub const fn input_frame_limit(ordinal: usize) -> Option<usize> {
    match ordinal {
        0 => Some(KEY_FRAME_BYTES),
        1..=2 => Some(wire::MAX_FRAME),
        3..=12 => Some(BASIS_FRAME_BYTES),
        13..=14 => Some(FORMATION_FRAME_BYTES),
        _ => None,
    }
}

/// Public proof bytes borrowed from their existing individual bounded frames.
///
/// Input0 is SourceAllOriginal and Input1 is PrivateMask; each inner Basis array
/// is ordered Q0..Q4. The two pairs must carry the exact same Source proof, giving
/// the fixed input16 proof roles across fifteen wire frames. No proof buffer is
/// copied or retained by verification.
pub struct InputEvidence<'a> {
    pub key: &'a [u8],
    pub encodings: [&'a [u8]; 2],
    pub bases: [[&'a [u8]; 5]; 2],
    pub formations: [&'a [u8]; 2],
}

impl<'a> InputEvidence<'a> {
    /// Borrow the exact fixed order: Key, Enc0, Enc1, Input0 Basis Q0..4,
    /// Input1 Basis Q0..4, Formation0, Formation1. No bytes are copied.
    pub fn frames(&self) -> [&'a [u8]; INPUT_FRAMES] {
        [
            self.key,
            self.encodings[0],
            self.encodings[1],
            self.bases[0][0],
            self.bases[0][1],
            self.bases[0][2],
            self.bases[0][3],
            self.bases[0][4],
            self.bases[1][0],
            self.bases[1][1],
            self.bases[1][2],
            self.bases[1][3],
            self.bases[1][4],
            self.formations[0],
            self.formations[1],
        ]
    }

    /// Check nonempty individual frames and their existing caps before borrowing
    /// the collection. Actual proof grammar, role and cryptography remain mandatory.
    pub fn from_frames(frames: [&'a [u8]; INPUT_FRAMES]) -> Result<Self, Error> {
        for (ordinal, bytes) in frames.iter().enumerate() {
            if bytes.is_empty() || bytes.len() > input_frame_limit(ordinal).unwrap() {
                return Err(Error::ResourceLimit);
            }
        }
        let evidence = Self {
            key: frames[0],
            encodings: [frames[1], frames[2]],
            bases: [
                frames[3..8].try_into().unwrap(),
                frames[8..13].try_into().unwrap(),
            ],
            formations: [frames[13], frames[14]],
        };
        let _ = evidence.byte_len()?;
        Ok(evidence)
    }

    /// Count the complete submitted bytes with checked arithmetic and every
    /// original per-frame byte cap. This does not parse or verify any proof.
    pub fn byte_len(&self) -> Result<usize, Error> {
        let mut total = 0usize;
        for (bytes, cap) in core::iter::once((self.key, KEY_FRAME_BYTES))
            .chain(self.encodings.iter().map(|bytes| (*bytes, wire::MAX_FRAME)))
            .chain(
                self.bases
                    .iter()
                    .flatten()
                    .map(|bytes| (*bytes, BASIS_FRAME_BYTES)),
            )
            .chain(
                self.formations
                    .iter()
                    .map(|bytes| (*bytes, FORMATION_FRAME_BYTES)),
            )
        {
            if bytes.len() > cap {
                return Err(Error::ResourceLimit);
            }
            total = total.checked_add(bytes.len()).ok_or(Error::ResourceLimit)?;
        }
        if total > MAX_INPUT_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(total)
    }
}

/// Immutable independently supplied public claims for both original inputs.
/// Construction checks their association and complete ciphertext grammar, not
/// their proofs. A decoded claim is not an independently trusted Owner anchor.
pub struct Provenance {
    setup: PublicSetup,
    anchor: BfvKeyAnchor,
    encodings: [EncodingStatement; 2],
    ciphertexts: [Vec<u8>; 2],
    original_setup_digest: [u8; 64],
    setup_wire_len: u64,
}

impl Provenance {
    pub fn new(
        setup: PublicSetup,
        anchor: BfvKeyAnchor,
        encodings: [EncodingStatement; 2],
        ciphertexts: [Vec<u8>; 2],
    ) -> Result<Self, Error> {
        // PublicSetup's existing profile check retains its fixed parameter and
        // version contract without decoding any public evaluation key.
        setup.profile().map_err(|_| Error::Statement)?;
        let (original_setup_digest, setup_wire_len) = {
            let bytes = setup.to_bytes().map_err(|_| Error::Statement)?;
            let full_id: [u8; 32] = Sha256::digest(&bytes).into();
            if full_id != anchor.full_setup_id() {
                return Err(Error::Statement);
            }
            (
                Sha512::digest(&bytes).into(),
                u64::try_from(bytes.len()).map_err(|_| Error::ResourceLimit)?,
            )
        }; // Do not retain a second complete public setup wire.

        let source = &encodings[0].expected;
        let predicate = &encodings[1].expected;
        let source_claim = source.source_claim();
        let predicate_claim = predicate.source_claim();
        if source.role() != Role::SourceAllOriginal
            || predicate.role() != Role::PrivateMask
            || source_claim.request != predicate_claim.request
            || source_claim.values() != predicate_claim.values()
            || source_claim.heads != predicate_claim.heads
            || source_claim.packets != predicate_claim.packets
            || source.bfv().full_setup() != anchor.full_setup_id()
            || predicate.bfv().full_setup() != anchor.full_setup_id()
            || source.bfv().key().public_values() != predicate.bfv().key().public_values()
        {
            return Err(Error::Statement);
        }
        let key = source.bfv().key();
        let scope = anchor.scope();
        if key.expected.descriptor.database != scope.database
            || key.expected.descriptor.key_domain != scope.bfv_key_domain
            || key.expected.descriptor.key_epoch != scope.epoch
            || key.expected.coefficients.map(|v| v.as_canonical_u64())
                != anchor.coefficient_commitment()
        {
            return Err(Error::Statement);
        }
        for bytes in &ciphertexts {
            // Ntt is wire metadata: stored polynomial rows remain PowerBasis.
            // Parsing retains the complete original seeded or unseeded wire;
            // it performs no SDK polynomial allocation or transform here.
            bfv_ciphertext_wire::parse(bytes).map_err(|error| match error {
                bfv_ciphertext_wire::WireError::ResourceLimit => Error::ResourceLimit,
                bfv_ciphertext_wire::WireError::InvalidEncoding => Error::Statement,
            })?;
        }
        Ok(Self {
            setup,
            anchor,
            encodings,
            ciphertexts,
            original_setup_digest,
            setup_wire_len,
        })
    }

    pub fn setup(&self) -> &PublicSetup {
        &self.setup
    }
    pub fn anchor(&self) -> &BfvKeyAnchor {
        &self.anchor
    }
    pub fn encodings(&self) -> &[EncodingStatement; 2] {
        &self.encodings
    }
    pub fn ciphertexts(&self) -> &[Vec<u8>; 2] {
        &self.ciphertexts
    }
    pub fn query(&self) -> [u8; 32] {
        self.encodings[0].expected.source_claim().request
    }
    /// SHA512 of the complete original setup wire, computed once at construction.
    pub fn original_setup_digest(&self) -> [u8; 64] {
        self.original_setup_digest
    }

    /// Feed the exact public graph identity, without retaining another setup copy.
    /// Its complete setup is bound by its original length and full SHA512 digest;
    /// both original ciphertext wires and all raw Source bytes enter directly.
    pub(crate) fn feed_identity(&self, h: &mut Sha512) {
        h.update(b"DCS/BFV-MUL-RELIN/INPUT-PROVENANCE/v1");
        h.update(self.setup_wire_len.to_le_bytes());
        h.update(self.original_setup_digest);
        h.update(self.anchor.full_setup_id());
        h.update(self.query());
        for (ordinal, (statement, ciphertext)) in
            self.encodings.iter().zip(&self.ciphertexts).enumerate()
        {
            h.update([ordinal as u8]);
            feed_bytes(h, ciphertext);
            let values = statement.values();
            h.update((values.len() as u64).to_le_bytes());
            for value in values {
                h.update(value.as_canonical_u64().to_le_bytes());
            }
            h.update(statement.producer_identity());
            let source = statement.expected.source_claim();
            h.update(source.request);
            for bytes in source
                .heads
                .iter()
                .map(|head| head.as_slice())
                .chain(source.packets.iter().map(Vec::as_slice))
            {
                feed_bytes(h, bytes);
            }
        }
    }

    /// Verify all sixteen original input proof roles. Decoded SDK proofs and
    /// verifier backends are owned and dropped inside each existing verifier.
    /// Only public statements survive between phases; no partial success escapes.
    /// This verifies mathematics against this instance's claims. A decoded peer
    /// anchor is still untrusted: the caller independently owns setup/anchor
    /// provenance, source authorization and freshness. No receipt is returned.
    pub fn verify_inputs(&self, evidence: &InputEvidence<'_>) -> Result<(), Error> {
        let _ = evidence.byte_len()?;
        {
            // Grammar and byte caps precede all expensive verification. A second
            // randomized Source proof of the same claim is outside input16.
            let source = BorrowedFrame::parse(&self.encodings[0].expected, evidence.encodings[0])
                .map_err(|_| Error::InputVerification)?;
            let predicate =
                BorrowedFrame::parse(&self.encodings[1].expected, evidence.encodings[1])
                    .map_err(|_| Error::InputVerification)?;
            if source.source() != predicate.source() {
                return Err(Error::InputVerification);
            }
        }

        // First actual cryptographic verification uses the independently pinned
        // owner-local anchor, never a key label recovered from submitted frames.
        let key = self
            .setup
            .verify_key_transform(&self.anchor, evidence.key)
            .map_err(|_| Error::InputVerification)?;
        let key_values = key.statement().public_values();
        for statement in &self.encodings {
            if statement.expected.bfv().key().public_values() != key_values {
                return Err(Error::InputVerification);
            }
        }

        // Both Source/Encoding pairs really verify, despite their identical
        // Source bytes. Full returned PVs (including Cw) and producer identities
        // must match the caller's complete statements, not only their Expected.
        let encodings = [
            self.verify_encoding(0, evidence.encodings[0])?,
            self.verify_encoding(1, evidence.encodings[1])?,
        ];
        let material = self
            .setup
            .relinearization_material()
            .map_err(|_| Error::InputVerification)?;
        for (operand, encoding) in encodings.iter().enumerate() {
            let bases = self.verify_bases(operand, material.parameters(), &key, evidence)?;
            let commitment = EncodedCommitment::new(
                encoding.producer_identity(),
                encoding
                    .expected
                    .encoding_context()
                    .map(|v| v.as_canonical_u64()),
                encoding.encoded.map(|v| v.as_canonical_u64()),
            )
            .map_err(|_| Error::InputVerification)?;
            let expected = FormationExpected::new(
                commitment,
                core::array::from_fn(|i| bases[i].statement().clone()),
            )
            .map_err(|_| Error::InputVerification)?;
            // These actual child results borrow THIS call's freshly verified
            // transform. Formation checks all five complete statements before
            // its real child verification; no external capability is accepted.
            let _ = bfv_ciphertext_formation::verify_scoped(
                self.anchor.full_setup_id(),
                &expected,
                bases.each_ref(),
                evidence.formations[operand],
            )
            .map_err(|_| Error::InputVerification)?;
        }
        Ok(())
    }

    fn verify_encoding(&self, operand: usize, bytes: &[u8]) -> Result<EncodingStatement, Error> {
        let expected = &self.encodings[operand];
        let checked =
            wire::verify(&expected.expected, bytes).map_err(|_| Error::InputVerification)?;
        let actual = checked.statement();
        actual
            .require_expected(&expected.expected)
            .map_err(|_| Error::InputVerification)?;
        if actual.values() != expected.values()
            || actual.producer_identity() != expected.producer_identity()
        {
            return Err(Error::InputVerification);
        }
        Ok(actual.clone())
    }

    fn verify_bases<'key>(
        &self,
        operand: usize,
        parameters: &[u8],
        key: &'key bfv_key_transform::VerifiedTransform,
        evidence: &InputEvidence<'_>,
    ) -> Result<[bfv_basis_convolution::ScopedBasis<'key>; 5], Error> {
        // This holds five PUBLIC statements and canonical ciphertext rows, not
        // decoded proofs, PCS data or a new aggregate evidence buffer. Each
        // verification finishes before the next Expected/backend is constructed.
        let mut statements = Vec::with_capacity(5);
        for (basis, bytes) in evidence.bases[operand].iter().enumerate() {
            let expected = bfv_basis_convolution::Expected::new(
                key.statement().clone(),
                parameters,
                &self.ciphertexts[operand],
                self.query(),
                basis,
            )
            .map_err(|_| Error::InputVerification)?;
            let checked = bfv_basis_convolution::verify_scoped(
                self.anchor.full_setup_id(),
                key,
                &expected,
                bytes,
            )
            .map_err(|_| Error::InputVerification)?;
            checked
                .statement()
                .require_expected(&expected)
                .map_err(|_| Error::InputVerification)?;
            statements.push(checked);
        }
        statements.try_into().map_err(|_| Error::InputVerification)
    }
}

fn feed_bytes(h: &mut Sha512, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

#[cfg(test)]
#[path = "input_prerequisites_tests.rs"]
mod input_prerequisites_tests;
