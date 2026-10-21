//! Original owner DATA and native private-input preparation. No Source or SQL admission.
use super::*;
/// Move-only original DATA ciphertext and its private owner plaintext.
/// ```compile_fail
/// fn expose(v:bfv_query_core::gold::OriginatingData) { let _=v.words; }
/// ```
/// ```compile_fail
/// fn duplicate(v:bfv_query_core::gold::OriginatingData) { let _=v.clone(); }
/// ```
pub struct OriginatingData {
    ciphertext: Vec<u8>,
    words: Zeroizing<Vec<u64>>,
    key_binding: [u8; 64],
}
fn scaled(words: &[u64]) -> Zeroizing<Vec<u64>> {
    Zeroizing::new(words.iter().map(|v| v * SCALE % T).collect())
}
fn commitment(context: [u64; 8], salt: &[u64; 4], words: &[u64]) -> Result<[u64; 4]> {
    if context.iter().any(|v| *v >= Val::ORDER_U64) {
        return Err(Error::Shape);
    }
    Ok(owner::commit_words(context.map(Val::from_u64), salt, words)?.map(|v| v.as_canonical_u64()))
}
impl OriginatingData {
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    /// Salted metadata only, without Source encoding or current-state authority.
    pub fn commitment(&self, context: [u64; 8], salt: &[u64; 4]) -> Result<[u64; 4]> {
        commitment(context, salt, &scaled(&self.words))
    }
}
impl Owner {
    /// Encrypt exactly4096 canonical unscaled owner words; no externally supplied Ct.
    pub fn originate_data(&self, words: Zeroizing<Vec<u64>>) -> Result<OriginatingData> {
        if words.len() != N || words.iter().any(|v| *v >= T) {
            return Err(Error::Shape);
        }
        let ciphertext = self.encrypt_original(&words, encryption::Purpose::Data)?;
        Ok(OriginatingData {
            ciphertext,
            words,
            key_binding: self.expected.binding(),
        })
    }
    /// Guard the original private DATA opening against independently selected endpoints.
    /// Native prove_dense/verify_dense are still mandatory; this is only preparation.
    pub fn prepare_data(
        &self,
        original: &OriginatingData,
        expected: &lower::data::Expected,
        salt: Zeroizing<[u64; 4]>,
    ) -> Result<lower::data::Prepared> {
        self.require_data(expected)?;
        if original.key_binding != self.expected.binding()
            || expected.request().ciphertext() != original.ciphertext()
        {
            return Err(Error::Binding);
        }
        let opening = lower::ScaledOpening::checked(
            expected.contexts()[0],
            expected.roots()[0],
            scaled(&original.words),
            salt,
        )?;
        lower::data::Prepared::new(expected, opening, self.secret_opening()?).map_err(Error::from)
    }
    /// Public Cw metadata from this SAME private query mask; no Word/Source grant.
    pub fn query_commitment(
        &self,
        original: &OriginatingQuery,
        context: [u64; 8],
        salt: &[u64; 4],
    ) -> Result<[u64; 4]> {
        self.require_query(original)?;
        commitment(context, salt, &original.mask.scaled_words())
    }
    /// Keep the key and mask private while preparing the sole original fused Query proof.
    pub fn prepare_query(
        &self,
        original: &OriginatingQuery,
        expected: &lower::query::Expected,
        statement: Zeroizing<[u64; 96]>,
        salt: Zeroizing<[u64; 4]>,
    ) -> Result<lower::query::Prepared> {
        self.require_query(original)?;
        let core = expected.core_expected();
        self.require_data(core)?;
        if core.request().ciphertext() != original.request.query_ciphertext()
            || core.request().nonce() != original.request.product_nonce()
            || statement.iter().any(|v| *v >= Val::ORDER_U64)
        {
            return Err(Error::Binding);
        }
        let mut bits = Zeroizing::new([0u8; 32]);
        for (i, word) in statement[78..86].iter().enumerate() {
            let word = u32::try_from(*word).map_err(|_| Error::Shape)?;
            bits[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        if bits.as_slice() != original.mask.as_bytes() {
            return Err(Error::Binding);
        }
        let opening = lower::ScaledOpening::checked(
            core.contexts()[0],
            core.roots()[0],
            original.mask.scaled_words(),
            salt,
        )?;
        let input = lower::data::Prepared::new(core, opening, self.secret_opening()?)?;
        lower::query::Prepared::new(
            expected,
            input,
            core::array::from_fn(|i| Val::from_u64(statement[i])),
        )
        .map_err(Error::from)
    }
}
