//! Fixed honest owner key generation; public metadata is not enrollment authority.
use super::*;
use fhe::bfv::SecretKey;
use fhe_traits::Serialize;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform},
};
use rand_chacha::ChaCha20Rng;

pub(super) struct Generated {
    pub(super) expected: KeyExpected,
    pub(super) sdk: Zeroizing<Vec<u8>>,
    pub(super) salt: Zeroizing<[u64; 4]>,
}
pub(super) fn generate(scope: [u8; 32], context: [u64; 8]) -> Result<Generated> {
    generate_with_entropy(scope, context, || {
        ChaCha20Rng::try_from_os_rng().map_err(|_| Error::Backend)
    })
}
fn generate_with_entropy(
    scope: [u8; 32],
    context: [u64; 8],
    fresh: impl FnOnce() -> Result<ChaCha20Rng>,
) -> Result<Generated> {
    if scope == [0; 32] || context.iter().any(|v| *v >= Val::ORDER_U64) {
        return Err(Error::Binding);
    }
    let mut key_coins = fresh()?;
    key_coins.set_stream(2);
    key_coins.set_word_pos(0);
    let mut salt_coins = key_coins.clone();
    salt_coins.set_stream(3);
    salt_coins.set_word_pos(0);
    let parameters = origin::parameters()?;
    let key = SecretKey::random(&parameters, &mut key_coins);
    let sdk = Zeroizing::new(key.to_bytes());
    let coefficients = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
    if coefficients.len() != N || coefficients.iter().any(|v| !(-20..=20).contains(v)) {
        return Err(Error::Arithmetic);
    }
    let packed = Zeroizing::new(
        coefficients
            .as_chunks::<8>()
            .0
            .iter()
            .map(|row| {
                row.iter().enumerate().fold(0u64, |word, (i, value)| {
                    word | (((*value + 20) as u64) << (6 * i))
                })
            })
            .collect::<Vec<_>>(),
    );
    let uniform = Uniform::new(0, Val::ORDER_U64).map_err(|_| Error::Backend)?;
    let salt = Zeroizing::new(core::array::from_fn(|_| uniform.sample(&mut salt_coins)));
    let root = owner::commit_words(context.map(Val::from_u64), &salt, &packed)?;
    let expected = KeyExpected::checked(
        scope,
        Parameters::fixed(),
        context,
        root.map(|v| v.as_canonical_u64()),
    )?;
    Ok(Generated {
        expected,
        sdk,
        salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_failure_creates_no_key_or_commitment_and_invalid_context_rejects() {
        assert!(matches!(
            generate_with_entropy([1; 32], [1; 8], || Err(Error::Backend)),
            Err(Error::Backend)
        ));
        assert!(matches!(generate([0; 32], [1; 8]), Err(Error::Binding)));
        assert!(matches!(
            generate([1; 32], [Val::ORDER_U64; 8]),
            Err(Error::Binding)
        ));
        let generated = generate([1; 32], [1; 8]).unwrap();
        super::super::lower::SecretOpening::checked(
            generated.expected.context(),
            generated.expected.root(),
            generated.sdk,
            generated.salt,
        )
        .unwrap();
    }
}
