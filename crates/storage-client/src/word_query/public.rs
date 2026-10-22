//! Original compiled SQL's transferable unverified Word and fused Query evidence.
use super::*;
use bfv_ciphertext_formation::gold::query as fused;

impl PendingQuery {
    /// Produce both native arguments from the same original private statement.
    /// Wrong Word/DATA endpoints preserve the witness; every later attempt
    /// consumes it, including entropy, owner, preparation and proving failures.
    pub fn prove_public<'q>(
        &'q mut self,
        owner: &Owner,
        producer: &word::Prover,
        expected: &word::Expected,
        data: &installed::Expected,
    ) -> Result<ProvedPublicQuery<'q>> {
        self.prove_public_with_entropy(owner, producer, expected, data, &mut |bytes| {
            getrandom::getrandom(bytes).map_err(|_| Error::Entropy)
        })
    }

    pub(super) fn prove_public_with_entropy<'q>(
        &'q mut self,
        owner: &Owner,
        producer: &word::Prover,
        expected: &word::Expected,
        data: &installed::Expected,
        fill: &mut impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<ProvedPublicQuery<'q>> {
        let request = self.original.public_request();
        if expected.binding() != self.expected
            || request.data_binding() != data.core_expected().binding()
            || request.data_ciphertext() != data.request().ciphertext()
        {
            return Err(Error::Binding);
        }
        let words = self.words.take().ok_or(Error::Consumed)?;
        let inputs = self.inputs.take().ok_or(Error::Consumed)?;
        let salt = fresh_salt(fill)?;
        let request = request.formation_request().map_err(Error::Input)?;
        let context = word::read::query::encoding_context(
            &request,
            data.core_expected(),
            expected.claims().statement,
        )
        .map_err(Error::Query)?;
        let vector = owner
            .query_commitment(&self.original, context.map(|v| v.as_canonical_u64()), &salt)
            .map_err(Error::Input)?
            .map(Val::from_u64);
        let query_expected = word::read::query::expected(
            &request,
            data.core_expected(),
            expected.claims().statement,
            vector,
        )
        .map_err(Error::Query)?;
        let query_inputs = owner
            .prepare_query(&self.original, &query_expected, words, salt)
            .map_err(Error::Input)?;
        let word = producer
            .produce(expected, inputs)
            .map_err(Error::Word)?
            .into_bytes();
        let query = fused::prove(&query_expected, query_inputs)
            .map_err(Error::Formation)?
            .into_bytes();
        Ok(ProvedPublicQuery {
            original: &self.original,
            word_binding: self.expected,
            query_expected,
            word,
            query,
        })
    }
}

fn fresh_salt(fill: &mut impl FnMut(&mut [u8]) -> Result<()>) -> Result<Zeroizing<[u64; 4]>> {
    let mut salt = Zeroizing::new([0; 4]);
    for out in salt.iter_mut() {
        let mut accepted = false;
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0; 8]);
            fill(&mut *bytes)?;
            let value = u64::from_le_bytes(*bytes);
            if value < Val::ORDER_U64 {
                *out = value;
                accepted = true;
                break;
            }
        }
        if !accepted {
            return Err(Error::Entropy);
        }
    }
    if *salt == [0; 4] {
        return Err(Error::Entropy);
    }
    Ok(salt)
}

/// Genuine producer bytes and original public endpoints, not checked evidence.
/// The key, mask, full statement and salt have no public getters.
/// ```compile_fail
/// fn duplicate<'a>(q: &storage_client::word_query::ProvedPublicQuery<'a>)
///     -> storage_client::word_query::ProvedPublicQuery<'a> { q.clone() }
/// ```
/// Owner-private receiving cannot substitute for complete public receiving:
/// ```compile_fail
/// use storage_client::word_query::ProvedPublicQuery;
/// use bfv_query_core::gold::Owner;
/// use registry200_proof::registry_progress::word::read::owner::OwnerCheckedRead;
/// fn complete(q: &ProvedPublicQuery<'_>, o: &Owner, p: &OwnerCheckedRead<'_, '_>) {
///     let _ = q.complete(o, p);
/// }
/// ```
pub struct ProvedPublicQuery<'q> {
    original: &'q gold::OriginatingQuery,
    word_binding: [u8; 64],
    query_expected: fused::Expected,
    word: Vec<u8>,
    query: Vec<u8>,
}
impl ProvedPublicQuery<'_> {
    pub fn public_request(&self) -> &gold::PublicRequest {
        self.original.public_request()
    }
    pub fn word(&self) -> &[u8] {
        &self.word
    }
    pub fn query(&self) -> &[u8] {
        &self.query
    }
    pub fn query_expected(&self) -> &fused::Expected {
        &self.query_expected
    }
    /// Complete only after actual public DATA/Word/Query/product verification.
    /// This conditional arithmetic plaintext grants no SQL, fresh head or lock.
    pub fn complete(
        &self,
        owner: &Owner,
        checked: &word::read::ArithmeticCheckedRead<'_>,
    ) -> Result<gold::DecryptedProduct> {
        let expected = checked.expected();
        if expected.word_expected().binding() != self.word_binding
            || expected.query_expected().binding() != self.query_expected.binding()
            || expected.data_expected().core_expected().binding()
                != self.public_request().data_binding()
        {
            return Err(Error::Binding);
        }
        owner
            .complete_checked_product(self.original, checked.product())
            .map_err(Error::Input)
    }
}
