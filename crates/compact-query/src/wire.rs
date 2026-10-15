use crate::{AgeRange, Error, MAX_WIRE_BYTES, Operation, Result, Stages};
use bincode::Options;
use serde::{Deserialize, Serialize};
use tfhe::{FheBool, FheUint8, FheUint10, FheUint16, FheUint24};

#[derive(Serialize, Deserialize)]
pub(crate) struct MaskedRow {
    pub ordinal: u64,
    pub age: FheUint8,
    pub amount: FheUint16,
}
/// Only the canonical comparison operator is public; each threshold is FHE encrypted.
#[derive(Serialize, Deserialize)]
pub(crate) enum EncryptedPredicate {
    Equal(FheUint8),
    AtLeast(FheUint8),
    AtMost(FheUint8),
    Range { lower: FheUint8, upper: FheUint8 },
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Request {
    pub domain: [u8; 16],
    pub id: [u8; 16],
    pub head: Vec<u8>,
    pub rows: Vec<MaskedRow>,
    pub predicate: EncryptedPredicate,
    pub delta: Option<FheUint16>,
}
/// Owner-local query context retains the expected addresses and plaintext intent.
/// Only encode_request() crosses to the evaluator.
pub struct PreparedQuery {
    pub(crate) request: Request,
    pub(crate) index_head: compact_store::Commitment,
    pub(crate) predicate: AgeRange,
    pub(crate) operation: Operation,
    pub(crate) stages: Stages,
}
impl PreparedQuery {
    pub fn selected_rows(&self) -> usize {
        self.request.rows.len()
    }
    pub fn stages(&self) -> &Stages {
        &self.stages
    }
    pub fn encode_request(&mut self) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let bytes = encode(&self.request)?;
        self.stages.request_serialize_ms = crate::ms(start);
        self.stages.request_bytes = bytes.len();
        Ok(bytes)
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) struct UpdatedRow {
    pub ordinal: u64,
    pub amount: FheUint16,
}
#[derive(Serialize, Deserialize)]
pub(crate) enum CountCipher {
    Single(FheBool),
    Multiple(FheUint10),
}
#[derive(Serialize, Deserialize)]
pub(crate) enum SumCipher {
    Single(FheUint16),
    Multiple(FheUint24),
}
/// Query output is unverified even after correct decoding/decryption and root checks.
#[derive(Serialize, Deserialize)]
pub struct UnverifiedOutput {
    pub(crate) domain: [u8; 16],
    pub(crate) id: [u8; 16],
    pub(crate) head: Vec<u8>,
    pub(crate) count: CountCipher,
    pub(crate) sum: SumCipher,
    pub(crate) rejected: Option<FheBool>,
    pub(crate) rows: Vec<UpdatedRow>,
    pub(crate) stages: Stages,
}
impl UnverifiedOutput {
    pub fn stages(&self) -> &Stages {
        &self.stages
    }
    pub fn encode(&mut self) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let bytes = encode(self)?;
        self.stages.output_serialize_ms = crate::ms(start);
        self.stages.output_bytes = bytes.len();
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes)
    }
}
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_WIRE_BYTES)
        .reject_trailing_bytes()
}
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let size = options()
        .serialized_size(value)
        .map_err(|e| Error::Codec(e.to_string()))?;
    if size > MAX_WIRE_BYTES {
        return Err(Error::WireLimit);
    }
    options()
        .serialize(value)
        .map_err(|e| Error::Codec(e.to_string()))
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() as u64 > MAX_WIRE_BYTES {
        return Err(Error::WireLimit);
    }
    options()
        .deserialize(bytes)
        .map_err(|e| Error::Codec(e.to_string()))
}
