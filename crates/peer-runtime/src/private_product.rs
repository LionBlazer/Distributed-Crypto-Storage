//! Fixed bounded stream for real private-input BFV multiplication proofs.
//! Its terminal result is mathematical evidence, never SQL or lock authority.
use bfv_mul_relin_proof::{CheckedProduct, Provenance};
use bfv_query_core::{
    MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES, MAX_PRIVATE_COEFFICIENT_RESPONSE_BYTES,
};
use peer_transport::{read_frame, write_frame};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    time::Duration,
};

pub(crate) const IO_BUDGET: Duration = Duration::from_secs(180);
pub(crate) const SESSION_BUDGET: Duration = Duration::from_secs(1800);
const HEADER: usize = 96;
const MAGIC: &[u8; 8] = b"DCSPRP01";
pub(crate) const READY: u8 = 1;
pub(crate) const INPUT: u8 = 2;
pub(crate) const OUTPUT: u8 = 3;
pub(crate) const CLAIMS: u8 = 4;
pub(crate) const PROOF: u8 = 5;
pub(crate) const END: u8 = 6;
pub(crate) const FAILED: u8 = 7;
pub(crate) const NEXT: u8 = 8;

/// Public untrusted mathematical job. The owner authenticates the request;
/// neither this claim nor a transport acknowledgement authorizes a SQL result.
#[derive(Serialize, Deserialize)]
pub struct PrivateProductRequest {
    pub(crate) object: [u8; 32],
    pub(crate) setup: [u8; 32],
    #[serde(
        serialize_with = "crate::bytes::serialize",
        deserialize_with = "manifest"
    )]
    pub(crate) provenance: Vec<u8>,
    #[serde(
        serialize_with = "crate::bytes::serialize",
        deserialize_with = "request"
    )]
    pub(crate) ciphertext: Vec<u8>,
}
fn manifest<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::bytes::deserialize_frame(d, bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES)
}
fn request<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::bytes::deserialize_frame(d, MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES)
}
impl PrivateProductRequest {
    pub(crate) fn new(
        object: [u8; 32],
        provenance: &Provenance,
        ciphertext: &[u8],
    ) -> io::Result<Self> {
        if ciphertext.len() > MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES {
            return Err(rejected("private product byte limit"));
        }
        let out = Self {
            object,
            setup: provenance.anchor().full_setup_id(),
            provenance: provenance.encode_claim().map_err(rejected)?,
            ciphertext: ciphertext.to_vec(),
        };
        out.require_envelope(provenance)?;
        Ok(out)
    }
    pub(crate) fn require_envelope(&self, p: &Provenance) -> io::Result<()> {
        if self.ciphertext.len() > MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES
            || self.provenance.len() > bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES
        {
            return Err(rejected("private product byte limit"));
        }
        let view = p
            .setup()
            .private_coefficient_request(&self.ciphertext)
            .map_err(rejected)?;
        let source = p.encodings()[0].expected.source_claim();
        if self.setup != p.anchor().full_setup_id()
            || view.query() != p.query()
            || view.context().data_head() != source.heads[0]
            || view.context().index_head() != source.heads[1]
            || view.ciphertexts() != p.ciphertexts().each_ref().map(Vec::as_slice)
        {
            return Err(rejected("private product association"));
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/private-product-stream/v1/");
        h.update(bfv_mul_relin_proof::profile_digest());
        h.update(self.object);
        h.update(self.setup);
        for b in [&self.provenance, &self.ciphertext] {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
        h.finalize().into()
    }
}

/// All input and output proofs have been checked against the caller's own
/// provenance. Fresh agreed state, SQL semantics and lock grants remain separate.
pub struct CheckedPrivateProduct {
    pub(crate) product: CheckedProduct,
    pub(crate) response: Vec<u8>,
}
impl CheckedPrivateProduct {
    pub fn product(&self) -> &CheckedProduct {
        &self.product
    }
    pub fn encrypted_response(&self) -> &[u8] {
        &self.response
    }
}
/// Checked current mathematical stream plus an UNTRUSTED retained identity.
/// Fresh readers must actually verify its original evidence again; this is no
/// persisted application vote, agreed head, SQL answer or lock permission.
pub struct RecordedPrivateProduct {
    pub(crate) checked: CheckedPrivateProduct,
    pub(crate) catalog: bfv_product_evidence::CatalogId,
}
impl RecordedPrivateProduct {
    pub fn checked(&self) -> &CheckedPrivateProduct {
        &self.checked
    }
    pub fn catalog(&self) -> bfv_product_evidence::CatalogId {
        self.catalog
    }
    pub fn into_parts(self) -> (CheckedPrivateProduct, bfv_product_evidence::CatalogId) {
        (self.checked, self.catalog)
    }
}
pub(crate) fn rejected(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[derive(Clone, Copy)]
pub(crate) struct StreamBinding {
    pub id: u64,
    pub digest: [u8; 32],
    pub nonce: [u8; 32],
}
impl StreamBinding {
    pub fn send(
        &self,
        stream: &mut impl Write,
        kind: u8,
        ordinal: usize,
        payload: &[u8],
    ) -> io::Result<usize> {
        let mut bytes = vec![0; HEADER];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10] = kind;
        bytes[12..14].copy_from_slice(&u16::try_from(ordinal).map_err(rejected)?.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.id.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.digest);
        bytes[56..88].copy_from_slice(&self.nonce);
        bytes[88..92].copy_from_slice(
            &u32::try_from(payload.len())
                .map_err(rejected)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(payload);
        write_frame(stream, &bytes, peer_transport::MAX_FRAME_BYTES)?;
        Ok(bytes.len())
    }
    #[cfg(test)]
    pub fn receive(
        &self,
        stream: &mut impl Read,
        kind: u8,
        ordinal: usize,
        cap: usize,
    ) -> io::Result<Vec<u8>> {
        self.receive_observed(stream, kind, ordinal, cap, |_| {})
    }
    pub fn receive_observed(
        &self,
        stream: &mut impl Read,
        kind: u8,
        ordinal: usize,
        cap: usize,
        observed: impl FnOnce(usize),
    ) -> io::Result<Vec<u8>> {
        let bytes = read_frame(
            stream,
            HEADER
                .checked_add(cap)
                .ok_or_else(|| rejected("frame cap"))?,
        )?;
        observed(bytes.len());
        if bytes.len() < HEADER
            || bytes[..8] != *MAGIC
            || bytes[8..10] != 1u16.to_le_bytes()
            || bytes[11] != 0
            || bytes[14..16] != [0; 2]
            || bytes[92..96] != [0; 4]
            || bytes[16..24] != self.id.to_le_bytes()
            || bytes[24..56] != self.digest
            || bytes[56..88] != self.nonce
            || bytes[88..92] != ((bytes.len() - HEADER) as u32).to_le_bytes()
        {
            return Err(rejected("private product stream binding"));
        }
        if bytes[10] == FAILED && bytes.len() == HEADER + 1 {
            return Err(failure(bytes[HEADER]));
        }
        if bytes[10] != kind
            || usize::from(u16::from_le_bytes(bytes[12..14].try_into().unwrap())) != ordinal
        {
            return Err(rejected("private product stream order"));
        }
        Ok(bytes[HEADER..].to_vec())
    }
    #[cfg(test)]
    pub fn ready(stream: &mut impl Read, id: u64, digest: [u8; 32]) -> io::Result<Self> {
        Self::ready_observed(stream, id, digest, |_| {})
    }
    pub fn ready_observed(
        stream: &mut impl Read,
        id: u64,
        digest: [u8; 32],
        observed: impl FnOnce(usize),
    ) -> io::Result<Self> {
        let bytes = read_frame(stream, HEADER + 1)?;
        observed(bytes.len());
        if bytes.len() < HEADER {
            return Err(rejected("private product not ready"));
        }
        let binding = Self {
            id,
            digest,
            nonce: bytes[56..88].try_into().unwrap(),
        };
        if bytes[..8] != *MAGIC
            || bytes[8..10] != 1u16.to_le_bytes()
            || bytes[11..16] != [0; 5]
            || bytes[16..24] != id.to_le_bytes()
            || bytes[24..56] != digest
            || bytes[88..92] != ((bytes.len() - HEADER) as u32).to_le_bytes()
            || bytes[92..96] != [0; 4]
        {
            return Err(rejected("private product ready binding"));
        }
        if bytes[10] == FAILED && bytes.len() == HEADER + 1 {
            return Err(failure(bytes[HEADER]));
        }
        if bytes[10] != READY || bytes.len() != HEADER {
            return Err(rejected("private product ready stage"));
        }
        Ok(binding)
    }
}
fn failure(code: u8) -> io::Error {
    match code {
        2 => io::Error::other(crate::RemoteError::Busy),
        _ => rejected("peer rejected private product"),
    }
}
pub(crate) fn response_cap() -> usize {
    MAX_PRIVATE_COEFFICIENT_RESPONSE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> StreamBinding {
        StreamBinding {
            id: 42,
            digest: [0x51; 32],
            nonce: [0x72; 32],
        }
    }
    #[test]
    fn start_length_bombs_reject_at_the_field_cap_before_reading_the_body() {
        use crate::wire::{WireRequest, decode_request, encode};
        let bytes = encode(&WireRequest {
            version: 2,
            id: 42,
            request: crate::Request::PrivateProduct(PrivateProductRequest {
                object: [0; 32],
                setup: [0; 32],
                provenance: Vec::new(),
                ciphertext: Vec::new(),
            }),
        })
        .unwrap();
        for (offset, limit) in [
            (78, bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES),
            (86, MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES),
        ] {
            for count in [limit as u64 + 1, u64::MAX] {
                let mut bomb = bytes.clone();
                bomb[offset..offset + 8].copy_from_slice(&count.to_le_bytes());
                let error = decode_request(&bomb)
                    .err()
                    .expect("oversized field rejected");
                assert!(
                    error.to_string().contains("RPC frame exceeds limit"),
                    "{error}"
                );
            }
        }
    }
    #[test]
    fn rejected_complete_frames_are_observed_and_busy_remains_a_typed_retry() {
        let b = binding();
        let mut bytes = Vec::new();
        b.send(&mut bytes, FAILED, 0, &[2]).unwrap();
        let mut observed = 0;
        let error =
            StreamBinding::ready_observed(&mut bytes.as_slice(), b.id, b.digest, |n| observed = n)
                .err()
                .unwrap();
        assert_eq!(observed, 97);
        assert!(matches!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<crate::RemoteError>()),
            Some(crate::RemoteError::Busy)
        ));
        let mut bytes = Vec::new();
        b.send(&mut bytes, PROOF, 0, &[1; 17]).unwrap();
        let mut observed = 0;
        assert!(
            b.receive_observed(&mut bytes.as_slice(), PROOF, 1, 17, |n| observed = n)
                .is_err()
        );
        assert_eq!(
            observed, 113,
            "complete wire read precedes header rejection"
        );
    }
    #[test]
    fn stream_frames_bind_session_request_role_order_length_and_reserved_fields() {
        let b = binding();
        let mut bytes = Vec::new();
        b.send(&mut bytes, PROOF, 7, &[9; 17]).unwrap();
        assert_eq!(
            b.receive(&mut bytes.as_slice(), PROOF, 7, 17).unwrap(),
            vec![9; 17]
        );
        for at in [0, 8, 10, 11, 12, 14, 16, 24, 56, 88, 92] {
            let mut changed = bytes.clone();
            changed[16 + at] ^= 1;
            assert!(
                b.receive(&mut changed.as_slice(), PROOF, 7, 17).is_err(),
                "header byte {at}"
            );
        }
        assert!(b.receive(&mut bytes.as_slice(), PROOF, 6, 17).is_err());
        assert!(b.receive(&mut bytes.as_slice(), CLAIMS, 7, 17).is_err());
        assert!(b.receive(&mut bytes.as_slice(), PROOF, 7, 16).is_err());
        let foreign = StreamBinding {
            nonce: [0x73; 32],
            ..b
        };
        assert!(
            foreign
                .receive(&mut bytes.as_slice(), PROOF, 7, 17)
                .is_err()
        );
    }
    #[test]
    fn ready_failure_truncation_and_terminal_frames_never_supply_a_result() {
        let b = binding();
        let mut bytes = Vec::new();
        b.send(&mut bytes, READY, 0, &[]).unwrap();
        let ready = StreamBinding::ready(&mut bytes.as_slice(), b.id, b.digest).unwrap();
        assert_eq!(ready.nonce, b.nonce);
        assert!(StreamBinding::ready(&mut bytes.as_slice(), b.id + 1, b.digest).is_err());
        for length in [0, 15, bytes.len() - 1] {
            assert!(StreamBinding::ready(&mut &bytes[..length], b.id, b.digest).is_err());
        }
        let mut failed = Vec::new();
        b.send(&mut failed, FAILED, 0, &[1]).unwrap();
        assert!(StreamBinding::ready(&mut failed.as_slice(), b.id, b.digest).is_err());
        assert!(b.receive(&mut failed.as_slice(), OUTPUT, 0, 1024).is_err());
        let mut end = Vec::new();
        b.send(&mut end, END, 118, &[]).unwrap();
        assert!(b.receive(&mut end.as_slice(), PROOF, 117, 1024).is_err());
        assert!(
            b.receive(&mut end.as_slice(), END, 118, 0)
                .unwrap()
                .is_empty()
        );
    }
}
