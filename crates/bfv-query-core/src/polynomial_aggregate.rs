//! Coefficient-packed COUNT/SUM through one full-residue public-polynomial product.
//! The caller owns complete authenticated selection and final proof acceptance.
use super::*;

const REQUEST_MAGIC: [u8; 8] = *b"BFVPAGQ2";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVPAGR2";
const AGGREGATE_VERSION: u16 = 2;
const MAX_AGGREGATE_WIRE: usize = 2 * 1024 * 1024;
const WINDOW: usize = 256;
const BANDS: usize = 10;
/// Complete source capacity for the Q2 coefficient layout; row operations remain Rows256.
pub const POLYNOMIAL_AGGREGATE_CAPACITY: usize = BANDS * WINDOW;
/// Public operation semantics bound by the network application anchor, not a cryptographic profile.
pub const POLYNOMIAL_AGGREGATE_SEMANTICS_ID: &[u8] =
    b"bfv-query-core/polynomial-aggregate/Q2-R2/contiguous-low-high-presence/C2560-W256-B10";
const OUTPUT_COEFFICIENTS: usize = 3 * POLYNOMIAL_AGGREGATE_CAPACITY + WINDOW - 1;
const _: () = assert!(
    WINDOW == MAX_ROWS
        && OUTPUT_COEFFICIENTS < DEGREE
        && 255 * (WINDOW as u64) < PLAINTEXT
        && (POLYNOMIAL_AGGREGATE_CAPACITY as u64) * (u16::MAX as u64) <= u32::MAX as u64
);

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
            || fields.len() > POLYNOMIAL_AGGREGATE_CAPACITY
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
            values[POLYNOMIAL_AGGREGATE_CAPACITY + slot] = u64::from(field.amount >> 8);
            values[2 * POLYNOMIAL_AGGREGATE_CAPACITY + slot] = 1;
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
            || pending.active_rows > POLYNOMIAL_AGGREGATE_CAPACITY
            || values[OUTPUT_COEFFICIENTS..]
                .iter()
                .any(|value| *value != 0)
        {
            return Err(Error::AggregateBounds);
        }
        // Only source cardinality/geometry is known here. Unknown low/high byte
        // values are bounded, never recomputed. This also checks pure presence
        // coefficients, unused gaps and the complete descending count triangle.
        for (coefficient, value) in values[..OUTPUT_COEFFICIENTS].iter().enumerate() {
            let low = active_window(pending.active_rows, coefficient, 0);
            let high = active_window(
                pending.active_rows,
                coefficient,
                POLYNOMIAL_AGGREGATE_CAPACITY,
            );
            let presence = active_window(
                pending.active_rows,
                coefficient,
                2 * POLYNOMIAL_AGGREGATE_CAPACITY,
            );
            if *value < presence || *value > 255 * (low + high) + presence {
                return Err(Error::AggregateBounds);
            }
        }
        let mut count = 0_u64;
        let mut sum = 0_u64;
        for band in 0..BANDS {
            let endpoint = (band + 1) * WINDOW - 1;
            let actual_count = values[2 * POLYNOMIAL_AGGREGATE_CAPACITY + endpoint];
            let low = values[endpoint];
            let high = values[POLYNOMIAL_AGGREGATE_CAPACITY + endpoint];
            let expected_count = pending
                .active_rows
                .saturating_sub(band * WINDOW)
                .min(WINDOW) as u64;
            if actual_count != expected_count
                || low > 255 * actual_count
                || high > 255 * actual_count
            {
                return Err(Error::AggregateBounds);
            }
            let partial_sum = high
                .checked_mul(256)
                .and_then(|high| high.checked_add(low))
                .ok_or(Error::AggregateBounds)?;
            count = count
                .checked_add(actual_count)
                .ok_or(Error::AggregateBounds)?;
            sum = sum.checked_add(partial_sum).ok_or(Error::AggregateBounds)?;
        }
        if count != pending.active_rows as u64 {
            return Err(Error::AggregateBounds);
        }
        Ok(UnverifiedPolynomialAggregate {
            count: u32::try_from(count).map_err(|_| Error::AggregateBounds)?,
            sum: u32::try_from(sum).map_err(|_| Error::AggregateBounds)?,
        })
    }
}
/// Number of occupied source coefficients in the public kernel's window.
/// This depends on authenticated selection cardinality, never on amount values.
fn active_window(rows: usize, coefficient: usize, field_start: usize) -> u64 {
    let Some(position) = coefficient.checked_sub(field_start) else {
        return 0;
    };
    let end = position + 1;
    rows.min(end).saturating_sub(end.saturating_sub(WINDOW)) as u64
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
    coefficients[..WINDOW].fill(1);
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
