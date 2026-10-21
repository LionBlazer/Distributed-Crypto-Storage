//! Bounded public-only N4096 SDK product RPC. No checked SQL/result capability.
use crate::RemoteError;
use bfv_query_core::gold::{self, PublicRequest, UnverifiedProduct};
use serde::{Deserialize, Deserializer, Serialize};
use std::io;

// version/id/result/response tags, followed by two bounded vector lengths.
pub const MAX_GOLD_PRODUCT_RESPONSE_BYTES: usize =
    34 + gold::MAX_PRODUCT_OUTPUT_BYTES + gold::PRODUCT_CERTIFICATE_BYTES;

#[derive(Serialize, Deserialize)]
pub struct GoldProductRequest {
    #[serde(
        serialize_with = "crate::bytes::serialize",
        deserialize_with = "request"
    )]
    bytes: Vec<u8>,
}
fn request<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::bytes::deserialize_frame(d, gold::MAX_REQUEST_BYTES)
}
impl GoldProductRequest {
    pub fn new(request: &PublicRequest) -> Self {
        Self {
            bytes: request.as_bytes().to_vec(),
        }
    }
}
/// Only bounded untrusted bytes. No constructor can mint a checked result.
#[derive(Serialize, Deserialize)]
pub struct GoldProductReply {
    #[serde(
        serialize_with = "crate::bytes::serialize",
        deserialize_with = "output"
    )]
    output: Vec<u8>,
    #[serde(
        serialize_with = "crate::bytes::serialize",
        deserialize_with = "certificate"
    )]
    certificate: Vec<u8>,
}
fn output<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::bytes::deserialize_frame(d, gold::MAX_PRODUCT_OUTPUT_BYTES)
}
fn certificate<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let bytes = crate::bytes::deserialize_frame(d, gold::PRODUCT_CERTIFICATE_BYTES)?;
    if bytes.len() != gold::PRODUCT_CERTIFICATE_BYTES {
        return Err(serde::de::Error::custom("Invalid Gold certificate length"));
    }
    Ok(bytes)
}
impl GoldProductReply {
    pub fn into_unverified(self) -> io::Result<UnverifiedProduct> {
        UnverifiedProduct::from_parts(self.output, self.certificate).map_err(io::Error::other)
    }
}
pub(crate) fn evaluate(request: GoldProductRequest) -> Result<GoldProductReply, RemoteError> {
    let rejected = |e| RemoteError::Cryptography(format!("Gold product: {e}"));
    let request = PublicRequest::decode(&request.bytes).map_err(rejected)?;
    let (output, certificate) = gold::Evaluator::new()
        .map_err(rejected)?
        .evaluate(&request)
        .map_err(rejected)?
        .into_parts();
    Ok(GoldProductReply {
        output,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{self, Request, Response, WireRequest, WireResponse};
    #[test]
    fn bounded_gold_tags_preserve_old_variants_and_reject_hostile_lengths() {
        let wire = wire::encode(&WireRequest {
            version: 2,
            id: 9,
            request: Request::GoldProduct(GoldProductRequest { bytes: vec![0; 1] }),
        })
        .unwrap();
        assert_eq!(&wire[10..14], &22u32.to_le_bytes());
        let mut oversized = wire[..14].to_vec();
        oversized.extend(u64::MAX.to_le_bytes());
        assert!(wire::decode_request(&oversized).is_err());
        assert!(wire::decode_request(&wire).is_ok());
        assert!(evaluate(GoldProductRequest { bytes: vec![0; 1] }).is_err());

        let reply = wire::encode(&WireResponse {
            version: 2,
            id: 9,
            result: Ok(Response::GoldProduct(GoldProductReply {
                output: vec![1],
                certificate: vec![0; gold::PRODUCT_CERTIFICATE_BYTES],
            })),
        })
        .unwrap();
        assert_eq!(&reply[14..18], &14u32.to_le_bytes());
        assert!(wire::decode_custody_response(&reply, MAX_GOLD_PRODUCT_RESPONSE_BYTES, 14).is_ok());
        let mut wrong = reply.clone();
        wrong[14..18].copy_from_slice(&6u32.to_le_bytes());
        wrong[18..26].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            wire::decode_custody_response(&wrong, MAX_GOLD_PRODUCT_RESPONSE_BYTES, 14).is_err()
        );
        let mut oversized = reply[..18].to_vec();
        oversized.extend(u64::MAX.to_le_bytes());
        assert!(
            wire::decode_custody_response(&oversized, MAX_GOLD_PRODUCT_RESPONSE_BYTES, 14).is_err()
        );
        let mut short = reply;
        short.pop();
        assert!(
            wire::decode_custody_response(&short, MAX_GOLD_PRODUCT_RESPONSE_BYTES, 14).is_err()
        );
    }
}
