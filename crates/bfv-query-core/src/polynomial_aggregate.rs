//! Coefficient-packed COUNT/SUM through one full-residue public-polynomial product.
//! The caller owns complete authenticated selection and final proof acceptance.
use super::*;

const REQUEST_MAGIC: [u8; 8] = *b"BFVPAGQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVPAGR1";
const AGGREGATE_VERSION: u16 = 1;
const MAX_AGGREGATE_WIRE: usize = 2 * 1024 * 1024;
const LOW: usize = MAX_ROWS - 1;
const HIGH: usize = 2 * MAX_ROWS - 1;
const COUNT: usize = 3 * MAX_ROWS - 1;
const OUTPUT_COEFFICIENTS: usize = 4 * MAX_ROWS - 1;
const _: () = assert!(OUTPUT_COEFFICIENTS < DEGREE && 255 * (MAX_ROWS as u64) < PLAINTEXT);

#[derive(Serialize, Deserialize)]
struct Request {
    magic: [u8; 8],
    version: u16,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    original: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Response {
    magic: [u8; 8],
    version: u16,
    keyset_id: [u8; 32],
    context: QueryContext,
    geometry: Geometry,
    aggregated: Vec<u8>,
}
/// One-use owner state, containing no original values or locally computed sum.
pub struct PendingPolynomialAggregate {
    context: QueryContext,
    keyset_id: [u8; 32],
    active_rows: usize,
}
pub struct PreparedPolynomialAggregate {
    pub pending: PendingPolynomialAggregate,
    pub request: Vec<u8>,
}
/// Actual decrypted peer coefficients. Arithmetic evidence remains caller-owned.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedPolynomialAggregate {
    pub count: u32,
    pub sum: u32,
}

impl Owner {
    /// Encrypts original byte limbs and one presence coefficient per source row.
    /// No plaintext sum or count answer is prepared before peer convolution.
    pub fn prepare_polynomial_aggregate(
        &self,
        context: QueryContext,
        fields: &[SelectedField],
    ) -> Result<PreparedPolynomialAggregate> {
        if self.geometry != Geometry::Rows256
            || fields.len() > MAX_ROWS
            || fields.iter().any(|field| !field.active)
        {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        for (slot, field) in fields.iter().enumerate() {
            values[slot] = u64::from(field.amount & 255);
            values[MAX_ROWS + slot] = u64::from(field.amount >> 8);
            values[2 * MAX_ROWS + slot] = 1;
        }
        let plaintext = Zeroizing::new(
            Plaintext::try_encode(&*values, Encoding::poly(), &self.parameters).map_err(backend)?,
        );
        let ciphertext: Ciphertext = self
            .key
            .try_encrypt(&*plaintext, &mut rand::rng())
            .map_err(backend)?;
        let original = ciphertext.to_bytes();
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: AGGREGATE_VERSION,
            keyset_id: self.keyset_id,
            context: context.clone(),
            geometry: self.geometry,
            original,
        })?;
        Ok(PreparedPolynomialAggregate {
            pending: PendingPolynomialAggregate {
                context,
                keyset_id: self.keyset_id,
                active_rows: fields.len(),
            },
            request,
        })
    }
    /// Final decryption only. A consumer must first verify the exact product proof.
    pub fn decrypt_polynomial_aggregate_unverified(
        &self,
        pending: PendingPolynomialAggregate,
        output: &[u8],
    ) -> Result<UnverifiedPolynomialAggregate> {
        let response: Response = bounded_decode(output)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != AGGREGATE_VERSION
            || response.keyset_id != self.keyset_id
            || pending.keyset_id != self.keyset_id
            || response.context != pending.context
            || response.geometry != Geometry::Rows256
            || self.geometry != Geometry::Rows256
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.aggregated, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let values =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::poly()).map_err(backend)?);
        if values.len() != DEGREE
            || values[..OUTPUT_COEFFICIENTS]
                .iter()
                .any(|value| *value > 255 * MAX_ROWS as u64)
            || values[OUTPUT_COEFFICIENTS..]
                .iter()
                .any(|value| *value != 0)
        {
            return Err(Error::AggregateBounds);
        }
        let count = values[COUNT];
        let low = values[LOW];
        let high = values[HIGH];
        if count != pending.active_rows as u64 || low > 255 * count || high > 255 * count {
            return Err(Error::AggregateBounds);
        }
        let sum = high
            .checked_mul(256)
            .and_then(|high| high.checked_add(low))
            .ok_or(Error::AggregateBounds)?;
        Ok(UnverifiedPolynomialAggregate {
            count: count as u32,
            sum: u32::try_from(sum).map_err(|_| Error::AggregateBounds)?,
        })
    }
}
fn bounded_decode<T: serde::de::DeserializeOwned>(wire: &[u8]) -> Result<T> {
    if wire.len() > MAX_AGGREGATE_WIRE {
        return Err(Error::WireLimit);
    }
    decode(wire)
}
fn checked(parameters: &Arc<BfvParameters>, keyset: [u8; 32], wire: &[u8]) -> Result<Request> {
    let request: Request = bounded_decode(wire)?;
    if request.magic != REQUEST_MAGIC
        || request.version != AGGREGATE_VERSION
        || request.keyset_id != keyset
        || request.geometry != Geometry::Rows256
        || !request.context.valid()
    {
        return Err(Error::BindingMismatch);
    }
    checked_ciphertext(&request.original, parameters)?;
    Ok(request)
}
fn kernel(parameters: &Arc<BfvParameters>) -> Result<Plaintext> {
    let mut coefficients = vec![0u64; DEGREE];
    coefficients[..MAX_ROWS].fill(1);
    Plaintext::try_encode(&coefficients, Encoding::poly(), parameters).map_err(backend)
}
pub(super) fn request_context(
    parameters: &Arc<BfvParameters>,
    keyset: [u8; 32],
    wire: &[u8],
) -> Result<QueryContext> {
    Ok(checked(parameters, keyset, wire)?.context)
}
pub(super) fn circuit_request(
    parameters: &Arc<BfvParameters>,
    keyset: [u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let request = checked(parameters, keyset, wire)?;
    let original = checked_ciphertext(&request.original, parameters)?;
    let kernel = kernel(parameters)?;
    canonical::public_product_request(parameters, wire, &original, &kernel)
}
pub(super) fn restore(
    parameters: &Arc<BfvParameters>,
    keyset: [u8; 32],
    wire: &[u8],
    output: &[u8],
) -> Result<Vec<u8>> {
    let request = checked(parameters, keyset, wire)?;
    let (binding, coefficients) = bfv_product_circuit::decode_output(output).map_err(backend)?;
    if binding != <[u8; 32]>::from(Sha256::digest(wire)) {
        return Err(Error::BindingMismatch);
    }
    encode(&Response {
        magic: RESPONSE_MAGIC,
        version: AGGREGATE_VERSION,
        keyset_id: keyset,
        context: request.context,
        geometry: request.geometry,
        aggregated: canonical::ciphertext(parameters, &coefficients)?.to_bytes(),
    })
}
#[cfg(test)]
mod tests;
