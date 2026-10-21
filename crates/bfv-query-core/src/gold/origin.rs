//! Actual public evaluator and protected local input scope, without SQL authority.
use super::*;
use binding::BINDING_BYTES;
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_traits::DeserializeParametrized;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};
const HEADER: usize = 8 + 32 + BINDING_BYTES + 64 + 8;
pub const MAX_REQUEST_BYTES: usize = HEADER + 2 * MAX_CT;
/// Owner-private finite truth table; every packed bit denotes one age value.
pub struct Mask256(Zeroizing<[u8; 32]>);
impl Mask256 {
    pub fn new(bits: [u8; 32]) -> Self {
        Self(Zeroizing::new(bits))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub(super) fn raw_words(&self) -> Zeroizing<Vec<u64>> {
        let mut out = Zeroizing::new(vec![0; N]);
        for age in 0..256 {
            out[255 - age] = u64::from((self.0[age / 8] >> (age % 8)) & 1);
        }
        out
    }
    pub(super) fn scaled_words(&self) -> Zeroizing<Vec<u64>> {
        let mut out = self.raw_words();
        for v in out.iter_mut() {
            *v = *v * SCALE % T;
        }
        out
    }
}
/// Public UNVERIFIED request; decoding never mints an originating/private scope.
#[derive(Clone)]
pub struct PublicRequest {
    bytes: Vec<u8>,
    binding: InputBinding,
    data_binding: [u8; 64],
    split: usize,
}
impl PublicRequest {
    pub(super) fn checked(
        binding: InputBinding,
        data: &lower::data::Expected,
        query: Vec<u8>,
    ) -> Result<Self> {
        Self::parts(
            binding,
            data.binding(),
            [data.request().ciphertext().to_vec(), query],
        )
    }
    fn parts(binding: InputBinding, data_binding: [u8; 64], inputs: [Vec<u8>; 2]) -> Result<Self> {
        if data_binding == [0; 64] || inputs.iter().any(|ct| ct.is_empty() || ct.len() > MAX_CT) {
            return Err(Error::Resource);
        }
        let parse_nonce: [u8; 32] = Sha256::digest(digest64(
            b"DCS/Gold-owner/public-endpoint-preflight/v1",
            &[binding.as_bytes(), &data_binding],
        ))
        .into();
        for ct in &inputs {
            drop(lower::data::Request::checked(parse_nonce, ct.clone())?);
        }
        let mut bytes = Vec::with_capacity(HEADER + inputs[0].len() + inputs[1].len());
        bytes.extend(b"GOPREQ01");
        bytes.extend(profile_digest());
        bytes.extend(binding.as_bytes());
        bytes.extend(data_binding);
        for ct in &inputs {
            bytes.extend((ct.len() as u32).to_le_bytes());
        }
        let split = HEADER + inputs[0].len();
        for ct in inputs {
            bytes.extend(ct);
        }
        Ok(Self {
            bytes,
            binding,
            data_binding,
            split,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER || bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Resource);
        }
        let mut r = Reader::new(bytes);
        if r.take(8)? != b"GOPREQ01" || r.take(32)? != profile_digest() {
            return Err(Error::Binding);
        }
        let binding = InputBinding::decode(r.take(BINDING_BYTES)?)?;
        let data = r.array()?;
        let a = r.u32()?;
        let b = r.u32()?;
        if a == 0 || b == 0 || a > MAX_CT || b > MAX_CT {
            return Err(Error::Resource);
        }
        let inputs = [r.take(a)?.to_vec(), r.take(b)?.to_vec()];
        r.end()?;
        let request = Self::parts(binding, data, inputs)?;
        if request.as_bytes() != bytes {
            return Err(Error::Shape);
        }
        Ok(request)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn binding(&self) -> &InputBinding {
        &self.binding
    }
    pub fn data_binding(&self) -> [u8; 64] {
        self.data_binding
    }
    pub fn data_ciphertext(&self) -> &[u8] {
        &self.bytes[HEADER..self.split]
    }
    pub fn query_ciphertext(&self) -> &[u8] {
        &self.bytes[self.split..]
    }
    /// Fixed public endpoints for native Formation/Word composition; no proof or authority.
    pub fn formation_request(&self) -> Result<lower::Request> {
        lower::Request::checked(
            self.product_nonce(),
            [
                self.data_ciphertext().to_vec(),
                self.query_ciphertext().to_vec(),
            ],
        )
        .map_err(Error::from)
    }
    pub(super) fn product_nonce(&self) -> [u8; 32] {
        Sha256::digest(digest64(
            b"DCS/Gold-owner/complete-product-request/v1",
            &[self.as_bytes()],
        ))
        .into()
    }
    pub(super) fn product_expected(&self, output: Vec<u8>) -> Result<product::Expected> {
        product::Expected::checked(
            self.product_nonce(),
            [
                self.data_ciphertext().to_vec(),
                self.query_ciphertext().to_vec(),
            ],
            output,
        )
        .map_err(Error::from)
    }
}
/// Fresh actual SDK generation OR protected custody plus complete private equations.
/// Neither raw PublicRequest nor a checked-product object can construct this type.
/// ```compile_fail
/// fn expose(x:bfv_query_core::gold::OriginatingQuery){let _=x.mask;}
/// ```
/// ```compile_fail
/// fn duplicate(x:bfv_query_core::gold::OriginatingQuery){let _=x.clone();}
/// ```
pub struct OriginatingQuery {
    pub(super) request: PublicRequest,
    pub(super) mask: Mask256,
    pub(super) data: lower::data::Expected,
    pub(super) key_binding: [u8; 64],
}
impl OriginatingQuery {
    pub fn public_request(&self) -> &PublicRequest {
        &self.request
    }
}
/// Ciphertext/proof bytes remain UNVERIFIED until the owner's fixed receiving path.
pub struct UnverifiedProduct {
    output: Vec<u8>,
    certificate: Vec<u8>,
}
impl UnverifiedProduct {
    pub fn from_parts(output: Vec<u8>, certificate: Vec<u8>) -> Result<Self> {
        if output.is_empty()
            || output.len() > MAX_CT
            || certificate.len() != product::CERTIFICATE_BYTES
        {
            return Err(Error::Resource);
        }
        Ok(Self {
            output,
            certificate,
        })
    }
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}
/// Actual ciphertext-only SDK worker; receives no secret, mask or original rows.
pub struct Evaluator {
    parameters: Arc<BfvParameters>,
}
impl Evaluator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            parameters: owner::parameters()?,
        })
    }
    pub fn evaluate(&self, request: &PublicRequest) -> Result<UnverifiedProduct> {
        let left = Ciphertext::from_bytes(request.data_ciphertext(), &self.parameters)
            .map_err(|_| Error::Backend)?;
        let right = Ciphertext::from_bytes(request.query_ciphertext(), &self.parameters)
            .map_err(|_| Error::Backend)?;
        let output =
            catch_unwind(AssertUnwindSafe(|| &left * &right)).map_err(|_| Error::Backend)?;
        if output.len() != 3 {
            return Err(Error::Shape);
        }
        let output = owner::serialize(&output);
        let expected = request.product_expected(output.clone())?;
        let certificate = product::produce(&expected)?.into_bytes();
        UnverifiedProduct::from_parts(output, certificate)
    }
}
/// Conditional arithmetic-checked client plaintext; no SQL selection, lock or QC.
pub struct DecryptedProduct {
    pub(super) binding: InputBinding,
    pub(super) values: Zeroizing<Vec<u64>>,
}
impl DecryptedProduct {
    pub fn binding(&self) -> &InputBinding {
        &self.binding
    }
    pub fn coefficients(&self) -> &[u64] {
        &self.values
    }
}
