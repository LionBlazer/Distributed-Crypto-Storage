//! Private fixed-N4 coefficient predicate: actual FHE only, without proof or SQL admission.
use super::*;

pub const COEFFICIENT_PREDICATE_ROWS: usize = 4;
/// Mathematical operation identity, not an admitted SQL or proof profile.
pub const COEFFICIENT_PREDICATE_SEMANTICS_ID: &[u8] =
    b"bfv-query-core/private-coefficient-predicate/v1/N4-L12-S512-poly-encrypted-mask";
const LANES_PER_ROW: usize = 3;
const STRIDE: usize = 512;
const AGES: usize = 256;
const LANES: usize = COEFFICIENT_PREDICATE_ROWS * LANES_PER_ROW;
const LAST_PRODUCT: usize = (LANES - 1) * STRIDE + 2 * (AGES - 1);
const COMMON_HEADER: usize = 320;
const REQUEST_HEADER: usize = COMMON_HEADER + 8;
const RESPONSE_HEADER: usize = COMMON_HEADER + 40;
const MAX_CT: usize = bfv_ciphertext_wire::MAX_CIPHERTEXT_BYTES;
const MAX_REQUEST: usize = REQUEST_HEADER + 2 * MAX_CT;
const MAX_RESPONSE: usize = RESPONSE_HEADER + MAX_CT;
const REQUEST_MAGIC: &[u8; 8] = b"BFVCPDQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"BFVCPDR1";
const PRIVATE_VERSION: u16 = 1;
const _: () = assert!(DEGREE == 8192 && PLAINTEXT == 114689 && LAST_PRODUCT == 6142);

/// Caller-owned original data. There is deliberately no predicate, active flag or window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoefficientRow {
    pub age: u8,
    pub amount: u16,
}
impl Zeroize for CoefficientRow {
    fn zeroize(&mut self) {
        self.age.zeroize();
        self.amount.zeroize();
    }
}
/// One-use public binding only. No plaintext rows, predicate mask or answer is retained.
pub struct PendingPrivateCoefficientPredicate {
    keyset_id: [u8; 32],
    context: QueryContext,
    query: [u8; 32],
    request_digest: [u8; 32],
}
pub struct PreparedPrivateCoefficientPredicate {
    pub pending: PendingPrivateCoefficientPredicate,
    pub request: Vec<u8>,
}
impl PreparedPrivateCoefficientPredicate {
    /// Borrow the exact complete original and predicate ciphertexts in that order.
    /// This checks the prepared envelope against its private pending binding, not
    /// encryption origin, computation, completeness or SQL authority. No SDK math runs.
    pub fn operand_ciphertexts(&self) -> Result<[&[u8]; 2]> {
        let view = request_view(&self.request)?;
        if !view.labels.context.valid()
            || view.labels.keyset_id != self.pending.keyset_id
            || view.labels.context != self.pending.context
            || view.labels.query != self.pending.query
            || <[u8; 32]>::from(Sha256::digest(&self.request)) != self.pending.request_digest
        {
            return Err(Error::BindingMismatch);
        }
        Ok([view.original, view.predicate])
    }
}
/// Encrypted actual SDK output. It has no computation/completeness proof.
pub struct EvaluatedPrivateCoefficientPredicate {
    pub output: Vec<u8>,
    pub ct_ct_multiplications: usize,
}
/// Values decoded from the actual completed ciphertext at an original row's target coefficients.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedCoefficientRow {
    pub ordinal: u8,
    pub present: bool,
    pub age: u8,
    pub amount: u16,
}
/// No proof, source completeness, authorization or freshness has been established.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedPrivateCoefficientPredicate {
    pub rows: [UnverifiedCoefficientRow; COEFFICIENT_PREDICATE_ROWS],
}

struct Labels {
    geometry: Geometry,
    keyset_id: [u8; 32],
    query: [u8; 32],
    context: QueryContext,
}
struct RequestView<'a> {
    labels: Labels,
    original: &'a [u8],
    predicate: &'a [u8],
}
struct ResponseView<'a> {
    labels: Labels,
    request_digest: [u8; 32],
    product: &'a [u8],
}
fn geometry_byte(geometry: Geometry) -> u8 {
    match geometry {
        Geometry::Rows16 => 1,
        Geometry::Rows256 => 2,
    }
}
fn fixed_parameters(parameters: &Arc<BfvParameters>) -> Result<()> {
    if parameters.degree() != DEGREE
        || parameters.plaintext() != PLAINTEXT
        || parameters.moduli() != MODULI
    {
        return Err(Error::ParameterProfile);
    }
    Ok(())
}
fn common_header(magic: &[u8; 8], labels: &Labels) -> Result<Vec<u8>> {
    if !labels.context.valid() {
        return Err(Error::BindingMismatch);
    }
    let mut bytes = Vec::with_capacity(COMMON_HEADER);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&PRIVATE_VERSION.to_le_bytes());
    bytes.push(geometry_byte(labels.geometry));
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(&labels.keyset_id);
    bytes.extend_from_slice(&labels.query);
    bytes.extend_from_slice(&labels.context.query_id());
    bytes.extend_from_slice(labels.context.data_head());
    bytes.extend_from_slice(labels.context.index_head());
    debug_assert_eq!(bytes.len(), COMMON_HEADER);
    Ok(bytes)
}
fn labels(bytes: &[u8], magic: &[u8; 8], maximum: usize) -> Result<Labels> {
    if bytes.len() > maximum {
        return Err(Error::WireLimit);
    }
    if bytes.len() < COMMON_HEADER
        || &bytes[..8] != magic
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != PRIVATE_VERSION
        || bytes[11..16] != [0; 5]
    {
        return Err(Error::InvalidShape);
    }
    let geometry = match bytes[10] {
        1 => Geometry::Rows16,
        2 => Geometry::Rows256,
        _ => return Err(Error::InvalidShape),
    };
    Ok(Labels {
        geometry,
        keyset_id: bytes[16..48].try_into().unwrap(),
        query: bytes[48..80].try_into().unwrap(),
        context: QueryContext::new(
            bytes[80..96].try_into().unwrap(),
            bytes[96..208].try_into().unwrap(),
            bytes[208..320].try_into().unwrap(),
        ),
    })
}
fn length(bytes: &[u8], at: usize) -> Result<usize> {
    let value = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    if value == 0 || value > MAX_CT {
        return Err(Error::WireLimit);
    }
    Ok(value)
}
fn request_view(bytes: &[u8]) -> Result<RequestView<'_>> {
    let labels = labels(bytes, REQUEST_MAGIC, MAX_REQUEST)?;
    if bytes.len() < REQUEST_HEADER {
        return Err(Error::InvalidShape);
    }
    let original = length(bytes, COMMON_HEADER)?;
    let predicate = length(bytes, COMMON_HEADER + 4)?;
    let middle = REQUEST_HEADER
        .checked_add(original)
        .ok_or(Error::WireLimit)?;
    let end = middle.checked_add(predicate).ok_or(Error::WireLimit)?;
    if end != bytes.len() {
        return Err(Error::InvalidShape);
    }
    Ok(RequestView {
        labels,
        original: &bytes[REQUEST_HEADER..middle],
        predicate: &bytes[middle..end],
    })
}
fn response_view(bytes: &[u8]) -> Result<ResponseView<'_>> {
    let labels = labels(bytes, RESPONSE_MAGIC, MAX_RESPONSE)?;
    if bytes.len() < RESPONSE_HEADER || bytes[356..360] != [0; 4] {
        return Err(Error::InvalidShape);
    }
    let size = length(bytes, 352)?;
    if RESPONSE_HEADER.checked_add(size) != Some(bytes.len()) {
        return Err(Error::InvalidShape);
    }
    Ok(ResponseView {
        labels,
        request_digest: bytes[320..352].try_into().unwrap(),
        product: &bytes[RESPONSE_HEADER..],
    })
}
fn require_labels(labels: &Labels, geometry: Geometry, keyset_id: [u8; 32]) -> Result<()> {
    if !labels.context.valid() || labels.geometry != geometry || labels.keyset_id != keyset_id {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}
fn canonical_ciphertext(bytes: &[u8], parameters: &Arc<BfvParameters>) -> Result<Ciphertext> {
    // The shared borrowed parser bounds both polynomials/residues before SDK math.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let value = checked_ciphertext(bytes, parameters)?;
        if value.to_bytes() != bytes {
            return Err(Error::InvalidShape);
        }
        Ok(value)
    }))
    .map_err(|_| Error::InvalidShape)?
}
fn encrypt_poly(owner: &Owner, values: &[u64]) -> Result<Vec<u8>> {
    fixed_parameters(&owner.parameters)?;
    if values.len() != DEGREE || values.iter().any(|v| *v >= PLAINTEXT) {
        return Err(Error::InvalidShape);
    }
    let plaintext = Zeroizing::new(
        Plaintext::try_encode(values, Encoding::poly(), &owner.parameters).map_err(backend)?,
    );
    let ciphertext: Ciphertext = owner
        .key
        .try_encrypt(&*plaintext, &mut rand::rng())
        .map_err(backend)?;
    let bytes = ciphertext.to_bytes();
    bfv_ciphertext_wire::validate(&bytes).map_err(|_| Error::InvalidShape)?;
    Ok(bytes)
}
impl Owner {
    /// Encrypt ALL four original rows independently of every query.
    ///
    /// This provides no Source proof. The caller owns the plaintext input and its erasure.
    /// Same-owner encryption origin is not authenticated by raw ciphertext bytes.
    pub fn encrypt_original_coefficient_rows_for_experiment(
        &self,
        rows: &[CoefficientRow; COEFFICIENT_PREDICATE_ROWS],
    ) -> Result<Vec<u8>> {
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        for (i, row) in rows.iter().enumerate() {
            for (field, weight) in [1, u64::from(row.age), u64::from(row.amount)]
                .into_iter()
                .enumerate()
            {
                values[(LANES_PER_ROW * i + field) * STRIDE + usize::from(row.age)] = weight;
            }
        }
        encrypt_poly(self, &values)
    }
    /// Encrypt a private 256-age truth table as a second ciphertext.
    ///
    /// `query` is an independently supplied opaque application label, NOT an exposed
    /// hash of low-entropy SQL/constants. No predicate/SQL hash is generated here.
    /// All predicate shapes have the same two-ciphertext envelope. No rows are filtered.
    pub fn prepare_private_coefficient_predicate_for_experiment(
        &self,
        context: QueryContext,
        query: [u8; 32],
        original: &[u8],
        private_mask: &[u8; 32],
    ) -> Result<PreparedPrivateCoefficientPredicate> {
        fixed_parameters(&self.parameters)?;
        if !context.valid() {
            return Err(Error::BindingMismatch);
        }
        // Reject malformed public input before constructing a private plaintext/performing encryption.
        let _ = canonical_ciphertext(original, &self.parameters)?;
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        for age in 0..AGES {
            values[AGES - 1 - age] = u64::from((private_mask[age / 8] >> (age % 8)) & 1);
        }
        let predicate = encrypt_poly(self, &values)?;
        let labels = Labels {
            geometry: self.geometry,
            keyset_id: self.keyset_id,
            query,
            context,
        };
        let mut request = common_header(REQUEST_MAGIC, &labels)?;
        request.extend_from_slice(
            &u32::try_from(original.len())
                .map_err(|_| Error::WireLimit)?
                .to_le_bytes(),
        );
        request.extend_from_slice(
            &u32::try_from(predicate.len())
                .map_err(|_| Error::WireLimit)?
                .to_le_bytes(),
        );
        request.extend_from_slice(original);
        request.extend_from_slice(&predicate);
        let _ = request_view(&request)?;
        Ok(PreparedPrivateCoefficientPredicate {
            pending: PendingPrivateCoefficientPredicate {
                keyset_id: self.keyset_id,
                context: labels.context,
                query,
                request_digest: Sha256::digest(&request).into(),
            },
            request,
        })
    }
    /// Owner completion ONLY. A valid decryption is not computation/completeness evidence.
    pub fn decrypt_private_coefficient_predicate_unverified_for_experiment(
        &self,
        pending: PendingPrivateCoefficientPredicate,
        output: &[u8],
    ) -> Result<UnverifiedPrivateCoefficientPredicate> {
        let response = response_view(output)?;
        require_labels(&response.labels, self.geometry, self.keyset_id)?;
        if pending.keyset_id != self.keyset_id
            || response.labels.context != pending.context
            || response.labels.query != pending.query
            || response.request_digest != pending.request_digest
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext = canonical_ciphertext(response.product, &self.parameters)?;
        let plaintext = Zeroizing::new(self.key.try_decrypt(&ciphertext).map_err(backend)?);
        let values =
            Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::poly()).map_err(backend)?);
        decode_coefficients(&values)
    }
}
impl PeerEvaluator {
    /// One actual SDK ciphertext product and original relinearization key; no query plaintext.
    /// This output is deliberately unavailable to the production proof/SQL dispatchers.
    pub fn evaluate_private_coefficient_predicate_for_experiment(
        &self,
        wire: &[u8],
    ) -> Result<EvaluatedPrivateCoefficientPredicate> {
        let request = request_view(wire)?;
        require_labels(&request.labels, self.geometry, self.keyset_id)?;
        fixed_parameters(self.kernel.parameters())?;
        let original = canonical_ciphertext(request.original, self.kernel.parameters())?;
        let predicate = canonical_ciphertext(request.predicate, self.kernel.parameters())?;
        let (product, ct_ct_multiplications) =
            self.kernel.coefficient_product(&original, &predicate)?;
        let product = product.to_bytes();
        let _ = canonical_ciphertext(&product, self.kernel.parameters())?;
        let mut output = common_header(RESPONSE_MAGIC, &request.labels)?;
        output.extend_from_slice(&Sha256::digest(wire));
        output.extend_from_slice(
            &u32::try_from(product.len())
                .map_err(|_| Error::WireLimit)?
                .to_le_bytes(),
        );
        output.extend_from_slice(&[0; 4]);
        output.extend_from_slice(&product);
        let _ = response_view(&output)?;
        Ok(EvaluatedPrivateCoefficientPredicate {
            output,
            ct_ct_multiplications,
        })
    }
}
fn decode_coefficients(values: &[u64]) -> Result<UnverifiedPrivateCoefficientPredicate> {
    if values.len() != DEGREE {
        return Err(Error::InvalidShape);
    }
    // Bounds and public layout only; never recompute a predicate or consult original rows.
    for (coefficient, value) in values.iter().enumerate() {
        let lane = coefficient / STRIDE;
        let maximum = if lane < LANES && coefficient % STRIDE <= 2 * (AGES - 1) {
            [1, u64::from(u8::MAX), u64::from(u16::MAX)][lane % LANES_PER_ROW]
        } else {
            0
        };
        if *value > maximum {
            return Err(Error::SelectBounds);
        }
    }
    let mut rows = Vec::with_capacity(COEFFICIENT_PREDICATE_ROWS);
    for i in 0..COEFFICIENT_PREDICATE_ROWS {
        let at = LANES_PER_ROW * i * STRIDE + AGES - 1;
        let presence = values[at];
        let age = values[at + STRIDE];
        let amount = values[at + 2 * STRIDE];
        if presence > 1 || (presence == 0 && (age != 0 || amount != 0)) {
            return Err(Error::SelectBounds);
        }
        rows.push(UnverifiedCoefficientRow {
            ordinal: i as u8,
            present: presence == 1,
            age: u8::try_from(age).map_err(|_| Error::SelectBounds)?,
            amount: u16::try_from(amount).map_err(|_| Error::SelectBounds)?,
        });
    }
    Ok(UnverifiedPrivateCoefficientPredicate {
        rows: rows.try_into().map_err(|_| Error::InvalidShape)?,
    })
}
#[cfg(test)]
mod tests;
