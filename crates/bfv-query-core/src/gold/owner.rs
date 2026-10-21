//! Actual SDK secret ownership; no old N8192 Owner conversion or raw origin import.
use super::*;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, SecretKey};
use fhe_traits::{DeserializeParametrized, FheDecoder, FheDecrypter};
use rand::RngCore;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};
/// Import-only N4096 protected owner. No secret getter, Clone, Debug or key generation.
/// ```compile_fail
/// fn secret(x:bfv_query_core::gold::Owner){let _=x.key;}
/// ```
pub struct Owner {
    pub(super) expected: KeyExpected,
    parameters: Arc<BfvParameters>,
    key: SecretKey,
    sdk: Zeroizing<Vec<u8>>,
    salt: Zeroizing<[u64; 4]>,
}
pub(super) fn parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(N)
        .set_plaintext_modulus(T)
        .set_moduli(&Q)
        .set_variance(10)
        .build_arc()
        .map_err(|_| Error::Backend)
}
impl Owner {
    pub fn from_sdk(
        expected: KeyExpected,
        sdk: Zeroizing<Vec<u8>>,
        salt: Zeroizing<[u64; 4]>,
    ) -> Result<Self> {
        if sdk.len() != N + 3 {
            return Err(Error::Shape);
        }
        // This bounds and opens ALL4096 canonical SDK coefficients before its decoder.
        drop(lower::SecretOpening::checked(
            expected.context(),
            expected.root(),
            sdk.clone(),
            salt.clone(),
        )?);
        let parameters = parameters()?;
        let key = catch_unwind(AssertUnwindSafe(|| {
            SecretKey::from_bytes(&sdk, &parameters)
        }))
        .map_err(|_| Error::Backend)?
        .map_err(|_| Error::Backend)?;
        Ok(Self {
            expected,
            parameters,
            key,
            sdk,
            salt,
        })
    }
    pub fn key_expected(&self) -> &KeyExpected {
        &self.expected
    }
    pub(super) fn require_data(&self, data: &lower::data::Expected) -> Result<()> {
        if data.contexts()[1] != self.expected.context() || data.roots()[1] != self.expected.root()
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub fn originate(
        &self,
        mask: Mask256,
        binding: InputBinding,
        data: &lower::data::Expected,
    ) -> Result<OriginatingQuery> {
        self.require_data(data)?;
        let ciphertext: Ciphertext = catch_unwind(AssertUnwindSafe(|| {
            super::encryption::encrypt(&self.key, &self.parameters, &mask.raw_words())
        }))
        .map_err(|_| Error::Backend)??;
        let request = PublicRequest::checked(binding, data, serialize(&ciphertext))?;
        Ok(OriginatingQuery {
            request,
            mask,
            data: data.clone(),
            key_binding: self.expected.binding(),
        })
    }
    pub(super) fn require_query(&self, query: &OriginatingQuery) -> Result<()> {
        self.require_data(&query.data)?;
        if query.key_binding != self.expected.binding()
            || query.request.data_binding() != query.data.binding()
            || query.request.data_ciphertext() != query.data.request().ciphertext()
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    /// Actual conditional public arithmetic first; only then decrypt all4096.
    /// Invalid evidence leaves the borrowed originating scope available for retry.
    pub fn complete(
        &self,
        query: &OriginatingQuery,
        response: &UnverifiedProduct,
    ) -> Result<DecryptedProduct> {
        self.require_query(query)?;
        let expected = query.request.product_expected(response.output().to_vec())?;
        let checked = product::check_arithmetic(&expected, response.certificate())?;
        let ciphertext = Ciphertext::from_bytes(checked.expected().output_wire(), &self.parameters)
            .map_err(|_| Error::Backend)?;
        let plain = Zeroizing::new(
            catch_unwind(AssertUnwindSafe(|| self.key.try_decrypt(&ciphertext)))
                .map_err(|_| Error::Backend)?
                .map_err(|_| Error::Backend)?,
        );
        let values = Zeroizing::new(
            Vec::<u64>::try_decode(&*plain, Encoding::poly()).map_err(|_| Error::Backend)?,
        );
        if values.len() != N || values.iter().any(|&v| v >= T) {
            return Err(Error::Shape);
        }
        Ok(DecryptedProduct {
            binding: query.request.binding().clone(),
            values,
        })
    }
    pub(super) fn check_original_input(
        &self,
        request: &PublicRequest,
        mask: &Mask256,
        data: &lower::data::Expected,
    ) -> Result<()> {
        self.require_data(data)?;
        if request.data_binding() != data.binding()
            || request.data_ciphertext() != data.request().ciphertext()
        {
            return Err(Error::Binding);
        }
        let nonce = request.product_nonce();
        let input = lower::data::Request::checked(nonce, request.query_ciphertext().to_vec())?;
        let digest = Sha256::digest(digest64(
            b"DCS/Gold-owner/private-query-Cw-context/v1",
            &[request.as_bytes(), &self.expected.binding()],
        ));
        let context = core::array::from_fn(|i| {
            Val::from_u32(u32::from_le_bytes(
                digest[4 * i..4 * i + 4].try_into().expect("digest word"),
            ))
        });
        let words = mask.scaled_words();
        // This transient private root is never published, serialized or a Source grant.
        let salt = Zeroizing::new([0u64; 4]);
        let root = commit_words(context, &salt, &words)?;
        let local = lower::data::Expected::checked(
            input,
            digest64(
                b"DCS/Gold-owner/private-input-consistency/v1",
                &[
                    request.as_bytes(),
                    &data.binding(),
                    &self.expected.binding(),
                ],
            ),
            [context, self.expected.context()],
            [root, self.expected.root()],
        )?;
        let opening = lower::ScaledOpening::checked(context, root, words, salt)?;
        let key = lower::SecretOpening::checked(
            self.expected.context(),
            self.expected.root(),
            self.sdk.clone(),
            self.salt.clone(),
        )?;
        lower::data::Prepared::new(&local, opening, key)?
            .check_private_consistency(&local)
            .map_err(Error::from)
    }
}
pub(super) fn serialize(ct: &Ciphertext) -> Vec<u8> {
    use fhe_traits::Serialize;
    ct.to_bytes()
}
struct PrivateFields<const L: usize>([Val; L]);
impl<const L: usize> Drop for PrivateFields<L> {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO);
    }
}
/// Fixed Gold overwrite-rate8/capacity4 W/Cs sponge; no generic public factory.
pub(super) fn commit_words(context: [Val; 8], salt: &[u64; 4], words: &[u64]) -> Result<[Val; 4]> {
    if !matches!(words.len(), N | 512) || salt.iter().chain(words).any(|&v| v >= Val::ORDER_U64) {
        return Err(Error::Shape);
    }
    let mut state = PrivateFields([Val::ZERO; 12]);
    let mut scratch = PrivateFields([Val::ZERO; bfv_hiding_stark::poseidon::WIDTH]);
    for row in 0..2 + words.len() / 8 {
        let mut input = PrivateFields([Val::ZERO; 12]);
        input.0[8..].copy_from_slice(&state.0[8..]);
        if row == 0 {
            input.0[..8].copy_from_slice(&context);
        } else if row == 1 {
            for (i, &v) in salt.iter().enumerate() {
                input.0[i] = Val::from_u64(v);
            }
        } else {
            for i in 0..8 {
                input.0[i] = Val::from_u64(words[8 * (row - 2) + i]);
            }
        }
        state.0 = bfv_hiding_stark::poseidon::write(&mut scratch.0, input.0);
    }
    Ok(core::array::from_fn(|i| state.0[i]))
}
pub(super) fn fresh_nonce() -> [u8; 24] {
    let mut n = [0; 24];
    rand::rng().fill_bytes(&mut n);
    n
}
