//! Owner-private input premise; never a transferable proof or a peer admission token.
use super::*;

/// Borrowed original input whose complete private equations and Stmt96 binding
/// have actually been checked by its originating owner. No public proof is implied.
/// ```compile_fail
/// fn forge<'a>(q: &'a bfv_query_core::gold::OriginatingQuery) {
///     let _ = bfv_query_core::gold::OriginatingStatement { original: q };
/// }
/// ```
/// ```compile_fail
/// fn copy<'a>(s: &bfv_query_core::gold::OriginatingStatement<'a>)
///     -> bfv_query_core::gold::OriginatingStatement<'a> { s.clone() }
/// ```
pub struct OriginatingStatement<'q> {
    original: &'q OriginatingQuery,
    root: [u64; 4],
    header: [u64; 13],
}
impl OriginatingStatement<'_> {
    pub fn public_request(&self) -> &PublicRequest {
        self.original.public_request()
    }
    pub fn data_expected(&self) -> &lower::data::Expected {
        &self.original.data
    }
    pub fn root(&self) -> [u64; 4] {
        self.root
    }
    pub fn header(&self) -> [u64; 13] {
        self.header
    }
    /// Requires the genuine sealed arithmetic result for this same original pair.
    pub fn complete_checked_product(
        &self,
        owner: &Owner,
        checked: &product::ArithmeticCheckedProduct,
    ) -> Result<DecryptedProduct> {
        owner.complete_checked_product(self.original, checked)
    }
}
impl Owner {
    /// Check the known private input, without proving it to the same owner in ZK.
    /// This does not establish Word semantics, DATA admission, a head or SQL rights.
    pub fn bind_statement<'q>(
        &self,
        original: &'q OriginatingQuery,
        statement: Zeroizing<[u64; 96]>,
    ) -> Result<OriginatingStatement<'q>> {
        self.require_query(original)?;
        if statement.iter().any(|v| *v >= Val::ORDER_U64) || statement[95] != 0 {
            return Err(Error::Shape);
        }
        let mut mask = Zeroizing::new([0; 32]);
        for (i, &word) in statement[78..86].iter().enumerate() {
            let word = u32::try_from(word).map_err(|_| Error::Shape)?;
            mask[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        if mask.as_slice() != original.mask.as_bytes() {
            return Err(Error::Binding);
        }
        let root = statement_root(&statement);
        let mut encoded = [0; 32];
        for (bytes, word) in encoded.as_chunks_mut::<8>().0.iter_mut().zip(root) {
            *bytes = word.to_le_bytes();
        }
        if encoded != original.request.binding().statement() {
            return Err(Error::Binding);
        }
        // These are the actual Q0/Q1 equations, same SDK S/Cs, shared bounded E,
        // exact K and all4096 original mask coefficients. No result is evaluated.
        self.check_original_input(&original.request, &original.mask, &original.data)?;
        Ok(OriginatingStatement {
            original,
            root,
            header: core::array::from_fn(|i| statement[i]),
        })
    }
}
struct Fields<const N: usize>([Val; N]);
impl<const N: usize> Drop for Fields<N> {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO);
    }
}
fn statement_root(words: &[u64; 96]) -> [u64; 4] {
    let mut state = Fields([Val::ZERO; 12]);
    let mut scratch = Fields([Val::ZERO; bfv_hiding_stark::poseidon::WIDTH]);
    for block in words.as_chunks::<8>().0 {
        state.0[..8].copy_from_slice(&block.map(Val::from_u64));
        state.0 = bfv_hiding_stark::poseidon::write(&mut scratch.0, state.0);
    }
    core::array::from_fn(|i| state.0[i].as_canonical_u64())
}
