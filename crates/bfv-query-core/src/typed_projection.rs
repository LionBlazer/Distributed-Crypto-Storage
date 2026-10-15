//! Schema-neutral encrypted byte projection, composed with authenticated selection by its caller.
//! A chunk can split a row, text value or binary object. No SQL type or fixed table is assumed.
use super::*;

const REQUEST_MAGIC: [u8; 8] = *b"BFVBYSQ1";
const RESPONSE_MAGIC: [u8; 8] = *b"BFVBYSR1";
const BYTE_VERSION: u16 = 1;

/// One slot remains a mandatory zero guard, so even SELECT * has a nonidentity
/// projection polynomial. Larger data is streamed as independently bound chunks.
pub const BYTE_SELECT_CAPACITY: usize = DEGREE - 1;

#[derive(Serialize, Deserialize)]
struct Request {
    magic: [u8; 8],
    version: u16,
    keyset_id: [u8; 32],
    context: QueryContext,
    binding: [u8; 32],
    projection: Vec<bool>,
    original: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Response {
    magic: [u8; 8],
    version: u16,
    keyset_id: [u8; 32],
    context: QueryContext,
    binding: [u8; 32],
    projection: Vec<bool>,
    projected: Vec<u8>,
}

/// Single-use completion state: shape and public identities, never original row values.
pub struct PendingByteSelect {
    keyset_id: [u8; 32],
    context: QueryContext,
    binding: [u8; 32],
    projection: Vec<bool>,
}
impl PendingByteSelect {
    pub fn context(&self) -> &QueryContext {
        &self.context
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

pub struct PreparedByteSelect {
    pub pending: PendingByteSelect,
    pub request: Vec<u8>,
}
impl PreparedByteSelect {
    /// Only fresh original ciphertext; excludes public context, schema/query binding and mask.
    pub fn ciphertext_payload_bytes(&self) -> Result<Vec<u8>> {
        Ok(decode::<Request>(&self.request)?.original)
    }
}

/// Bounds/context checks alone do not establish arithmetic correctness or complete selection.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedByteSelection {
    pub bytes: Vec<u8>,
    pub proof: ProofStatus,
}

impl Owner {
    /// Encrypts ORIGINAL bytes before projection. The public mask must derive only from
    /// schema and requested columns, not from plaintext row predicates or an answer.
    /// `binding` must commit schema, table, query, chunk position/count and catalog version.
    /// Caller must authenticate and completely select source rows independently.
    pub fn prepare_byte_select(
        &self,
        context: QueryContext,
        binding: [u8; 32],
        original: &[u8],
        project: &[bool],
    ) -> Result<PreparedByteSelect> {
        if original.len() > BYTE_SELECT_CAPACITY || original.len() != project.len() {
            return Err(Error::GeometryLimit);
        }
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        for (slot, value) in original.iter().enumerate() {
            values[slot] = u64::from(*value);
        }
        let request = encode(&Request {
            magic: REQUEST_MAGIC,
            version: BYTE_VERSION,
            keyset_id: self.keyset_id,
            context: context.clone(),
            binding,
            projection: project.to_vec(),
            original: self.encrypted(&values)?,
        })?;
        Ok(PreparedByteSelect {
            request,
            pending: PendingByteSelect {
                keyset_id: self.keyset_id,
                context,
                binding,
                projection: project.to_vec(),
            },
        })
    }

    /// Final decryption of the actual peer response. This deliberately returns an
    /// unverified type; a proof-composing consumer must check evidence before calling it.
    pub fn decrypt_byte_select_unverified(
        &self,
        pending: PendingByteSelect,
        output: &[u8],
    ) -> Result<UnverifiedByteSelection> {
        let response: Response = decode(output)?;
        if response.magic != RESPONSE_MAGIC
            || response.version != BYTE_VERSION
            || response.keyset_id != self.keyset_id
            || pending.keyset_id != self.keyset_id
            || response.context != pending.context
            || response.binding != pending.binding
            || response.projection != pending.projection
            || response.projection.len() > BYTE_SELECT_CAPACITY
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = checked_ciphertext(&response.projected, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let decoded =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).map_err(backend)?);
        if decoded.len() != DEGREE {
            return Err(Error::InvalidShape);
        }
        for (slot, value) in decoded.iter().copied().enumerate() {
            let selected = pending.projection.get(slot).copied().unwrap_or(false);
            if value > if selected { 255 } else { 0 } {
                return Err(Error::SelectBounds);
            }
        }
        Ok(UnverifiedByteSelection {
            bytes: decoded[..pending.projection.len()]
                .iter()
                .map(|value| *value as u8)
                .collect(),
            proof: ProofStatus::Unavailable,
        })
    }
}

fn checked_request(
    parameters: &Arc<BfvParameters>,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<Request> {
    let request: Request = decode(wire)?;
    if request.magic != REQUEST_MAGIC
        || request.version != BYTE_VERSION
        || request.keyset_id != keyset_id
        || !request.context.valid()
        || request.projection.len() > BYTE_SELECT_CAPACITY
    {
        return Err(Error::BindingMismatch);
    }
    checked_ciphertext(&request.original, parameters)?;
    Ok(request)
}

fn public_projection(parameters: &Arc<BfvParameters>, projection: &[bool]) -> Result<Plaintext> {
    let mut mask = vec![0; DEGREE];
    for (slot, selected) in projection.iter().enumerate() {
        mask[slot] = u64::from(*selected);
    }
    Plaintext::try_encode(&mask, Encoding::simd(), parameters).map_err(backend)
}

pub(super) fn request_context(
    parameters: &Arc<BfvParameters>,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<QueryContext> {
    Ok(checked_request(parameters, keyset_id, wire)?.context)
}

pub(super) fn evaluate_public(
    parameters: &Arc<BfvParameters>,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_request(parameters, keyset_id, wire)?;
    let original = checked_ciphertext(&request.original, parameters)?;
    let mask = public_projection(parameters, &request.projection)?;
    response(request, (&original * &mask).to_bytes())
}

pub(super) fn circuit_request(
    parameters: &Arc<BfvParameters>,
    keyset_id: [u8; 32],
    wire: &[u8],
) -> Result<Vec<u8>> {
    use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
    let request = checked_request(parameters, keyset_id, wire)?;
    let original = checked_ciphertext(&request.original, parameters)?;
    let mask = public_projection(parameters, &request.projection)?;
    let mut polynomial = Poly::try_convert_from(
        &mask,
        parameters.context_at_level(0).map_err(backend)?,
        true,
        Representation::PowerBasis,
    )
    .map_err(backend)?;
    polynomial.change_representation(Representation::Ntt);
    let values = Vec::<u64>::from(&polynomial);
    let repeated: Vec<_> = values.iter().chain(&values).copied().collect();
    bfv_product_circuit::encode_request(
        Sha256::digest(wire).into(),
        &canonical::coefficients(&original),
        &repeated,
    )
    .map_err(backend)
}

pub(super) fn restore_circuit_output(
    parameters: &Arc<BfvParameters>,
    keyset_id: [u8; 32],
    wire: &[u8],
    output: &[u8],
) -> Result<Vec<u8>> {
    let request = checked_request(parameters, keyset_id, wire)?;
    let (binding, coefficients) = bfv_product_circuit::decode_output(output).map_err(backend)?;
    if binding != <[u8; 32]>::from(Sha256::digest(wire)) {
        return Err(Error::BindingMismatch);
    }
    response(
        request,
        canonical::ciphertext(parameters, &coefficients)?.to_bytes(),
    )
}

fn response(request: Request, projected: Vec<u8>) -> Result<Vec<u8>> {
    encode(&Response {
        magic: RESPONSE_MAGIC,
        version: BYTE_VERSION,
        keyset_id: request.keyset_id,
        context: request.context,
        binding: request.binding,
        projection: request.projection,
        projected,
    })
}

#[cfg(test)]
mod tests;
