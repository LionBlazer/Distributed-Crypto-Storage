//! Owner-only independent ChaCha20 streams; preserve the exact SDK phase/noise.
use super::{Error, N, Result};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{FheEncoder, FheEncrypter};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub(super) fn encrypt(
    key: &SecretKey,
    parameters: &Arc<BfvParameters>,
    words: &[u64],
) -> Result<Ciphertext> {
    encrypt_with_entropy(key, parameters, words, || {
        ChaCha20Rng::try_from_os_rng().map_err(|_| Error::Backend)
    })
}

fn query_coins(fresh: impl FnOnce() -> Result<ChaCha20Rng>) -> Result<(ChaCha20Rng, ChaCha20Rng)> {
    let mut error = fresh()?;
    error.set_stream(0);
    error.set_word_pos(0);
    let mut uniform = error.clone();
    uniform.set_stream(1);
    uniform.set_word_pos(0);
    Ok((error, uniform))
}

// Private entropy injection is solely for owning tests, never a caller API.
fn encrypt_with_entropy(
    key: &SecretKey,
    parameters: &Arc<BfvParameters>,
    words: &[u64],
    fresh: impl FnOnce() -> Result<ChaCha20Rng>,
) -> Result<Ciphertext> {
    if words.len() != N || parameters.degree() != N {
        return Err(Error::Shape);
    }
    let (mut error_coins, mut uniform_coins) = query_coins(fresh)?;
    let plain = Zeroizing::new(
        Plaintext::try_encode(words, Encoding::poly(), parameters).map_err(|_| Error::Backend)?,
    );
    let mut original: Ciphertext = key
        .try_encrypt(&*plain, &mut error_coins)
        .map_err(|_| Error::Backend)?;
    let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(key).coeffs);
    let result = remask(&original, &secret, parameters, &mut uniform_coins);
    // The intermediate SDK ciphertext is never exported or used as the request.
    for polynomial in original.iter_mut() {
        polynomial.zeroize();
    }
    result
}

fn remask(
    original: &Ciphertext,
    secret: &[i64],
    parameters: &Arc<BfvParameters>,
    coins: &mut ChaCha20Rng,
) -> Result<Ciphertext> {
    let context = parameters.context_at_level(0).map_err(|_| Error::Backend)?;
    if original.len() != 2
        || secret.len() != N
        || secret.iter().any(|v| !(-20..=20).contains(v))
        || original.iter().any(|p| p.ctx() != context)
    {
        return Err(Error::Shape);
    }
    let mut s = Zeroizing::new(
        Poly::try_convert_from(secret, context, false, Representation::PowerBasis)
            .map_err(|_| Error::Backend)?,
    );
    s.change_representation(Representation::Ntt);
    let mut rho = Zeroizing::new(Poly::random(context, Representation::Ntt, coins));
    rho.disallow_variable_time_computations();
    let correction = Zeroizing::new(&*rho * &*s);
    let mut b = original[0].clone();
    let mut a = original[1].clone();
    // SDK operations OR their variable-time flags. Reset both public operands
    // BEFORE combining them with the owner-private secret/randomness.
    b.disallow_variable_time_computations();
    a.disallow_variable_time_computations();
    b -= &*correction;
    a += &*rho;
    // (b-rho*s)+(a+rho)*s=b+a*s exactly in every RNS/NTT coordinate.
    // No new error is added, and Ciphertext::new exports both unseeded operands.
    Ciphertext::new(vec![b, a], parameters).map_err(|_| Error::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_traits::{FheDecoder, FheDecrypter, Serialize};
    use rand::RngCore;

    #[test]
    fn one_seed_uses_disjoint_error_and_uniform_streams_from_counter_zero() {
        // Explicit PUBLIC test seed, never exposed by the owner API.
        let (mut error, mut uniform) = query_coins(|| Ok(ChaCha20Rng::from_seed([0; 32]))).unwrap();

        assert_eq!(error.get_stream(), 0);
        assert_eq!(uniform.get_stream(), 1);
        assert_eq!(error.get_word_pos(), 0);
        assert_eq!(uniform.get_word_pos(), 0);
        let mut error_block = [0; 64];
        let mut uniform_block = [0; 64];
        error.fill_bytes(&mut error_block);
        uniform.fill_bytes(&mut uniform_block);
        // ChaCha20 zero-key/counter/nonce block prefix; also pins the20-round variant.
        assert_eq!(
            &error_block[..8],
            &[0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90]
        );
        assert_ne!(error_block, uniform_block);
    }

    fn fixture() -> (Arc<BfvParameters>, SecretKey, Zeroizing<Vec<u64>>) {
        let parameters = super::super::owner::parameters().unwrap();
        let key = SecretKey::random(&parameters, &mut rand::rng());
        let mut words = Zeroizing::new(vec![0; N]);
        for (i, value) in words.iter_mut().take(256).enumerate() {
            *value = u64::from(i % 3 == 0);
        }
        (parameters, key, words)
    }

    fn phase(ciphertext: &Ciphertext, secret: &[i64]) -> Zeroizing<Poly> {
        let mut s = Zeroizing::new(
            Poly::try_convert_from(
                secret,
                ciphertext[0].ctx(),
                false,
                Representation::PowerBasis,
            )
            .unwrap(),
        );
        s.change_representation(Representation::Ntt);
        let mut a = Zeroizing::new(ciphertext[1].clone());
        a.disallow_variable_time_computations();
        let mut out = Zeroizing::new(&*a * &*s);
        let mut b = Zeroizing::new(ciphertext[0].clone());
        b.disallow_variable_time_computations();
        *out += &*b;
        out
    }

    #[test]
    fn independent_uniform_masks_change_public_inputs_but_preserve_every_phase_coefficient() {
        let (parameters, key, words) = fixture();
        let plain = Zeroizing::new(
            Plaintext::try_encode(words.as_slice(), Encoding::poly(), &parameters).unwrap(),
        );
        let original = key.try_encrypt(&*plain, &mut rand::rng()).unwrap();
        let secret = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&key).coeffs);
        // Explicit PUBLIC test seeds. Neither seed nor RNG is a production input.
        let mut first_coins = ChaCha20Rng::from_seed([1; 32]);
        let mut second_coins = ChaCha20Rng::from_seed([2; 32]);

        let first = remask(&original, &secret, &parameters, &mut first_coins).unwrap();
        let second = remask(&original, &secret, &parameters, &mut second_coins).unwrap();

        let expected = phase(&original, &secret);
        for remasked in [&first, &second] {
            assert!(remasked[0].coefficients() != original[0].coefficients());
            assert!(remasked[1].coefficients() != original[1].coefficients());
            assert!(phase(remasked, &secret).coefficients() == expected.coefficients());
            let bytes = remasked.to_bytes();
            super::super::lower::data::Request::checked([1; 32], bytes).unwrap();
        }
        assert!(first[1].coefficients() != second[1].coefficients());
    }

    #[test]
    fn failed_entropy_returns_no_ciphertext_and_a_fresh_attempt_decrypts_the_original_mask() {
        let (parameters, key, words) = fixture();

        let failed = encrypt_with_entropy(&key, &parameters, &words, || Err(Error::Backend));

        assert!(matches!(failed, Err(Error::Backend)));
        let encrypted = encrypt(&key, &parameters, &words).unwrap();
        let plain = Zeroizing::new(key.try_decrypt(&encrypted).unwrap());
        let actual = Zeroizing::new(Vec::<u64>::try_decode(&*plain, Encoding::poly()).unwrap());
        assert_eq!(actual.as_slice(), words.as_slice());
    }
}
