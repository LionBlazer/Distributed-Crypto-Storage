//! Genuine upstream encryption plus a separate native formation equation.
//! All seeds/source records here are explicitly PUBLIC NONSECRET test fixtures.
use crate::{
    CBD_U64_DRAWS, DEGREE, MODULI, PLAINTEXT, Result, VARIANCE,
    ntt::{ReferenceNtt, mul, pow},
    packing::Packed,
};
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use fhe_util::sample_vec_cbd;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use zeroize::Zeroizing;

fn parameters() -> Result<Arc<BfvParameters>> {
    BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT)
        .set_moduli(&MODULI)
        .set_variance(VARIANCE)
        .build_arc()
        .map_err(|e| e.to_string())
}
fn encoding(packed: &Packed) -> Encoding {
    if packed.layout.simd() {
        Encoding::simd()
    } else {
        Encoding::poly()
    }
}
pub(crate) fn check_support(values: &[i64]) -> Result<()> {
    if values.len() != DEGREE || values.iter().any(|v| !(-20..=20).contains(v)) {
        return Err("CBD(20) signed-support mismatch".into());
    }
    Ok(())
}

/// The actual SIMD matrix map, followed by a separate canonical inverse NTT.
pub(crate) fn plaintext_coefficients(packed: &Packed) -> Result<Zeroizing<Vec<u64>>> {
    if packed.values.len() != DEGREE || packed.values.iter().any(|v| *v >= PLAINTEXT) {
        return Err("invalid original plaintext slots".into());
    }
    if !packed.layout.simd() {
        return Ok(Zeroizing::new(packed.values.to_vec()));
    }
    let mut coefficients = Zeroizing::new(vec![0; DEGREE]);
    let mut position = 1_usize;
    for i in 0..DEGREE / 2 {
        let first = (position - 1) / 2;
        let second = (2 * DEGREE - position - 1) / 2;
        let first = first.reverse_bits() >> (usize::BITS - crate::LOG_DEGREE);
        let second = second.reverse_bits() >> (usize::BITS - crate::LOG_DEGREE);
        coefficients[first] = packed.values[i];
        coefficients[second] = packed.values[DEGREE / 2 + i];
        position = (position * 3) & (2 * DEGREE - 1);
    }
    ReferenceNtt::new(PLAINTEXT)?.backward(&mut coefficients)?;
    Ok(coefficients)
}

pub(crate) struct Fixture {
    parameters: Arc<BfvParameters>,
    ciphertext: Ciphertext,
    secret: Zeroizing<Vec<i64>>,
    error: Zeroizing<Vec<i64>>,
}
impl Fixture {
    pub(crate) fn encrypt(packed: &Packed) -> Result<Self> {
        let parameters = parameters()?;
        let mut key_rng = ChaCha8Rng::from_seed([0x53; 32]);
        let mut key_replay = key_rng.clone();
        let key = SecretKey::random(&parameters, &mut key_rng);
        let secret = Zeroizing::new(
            sample_vec_cbd(DEGREE, VARIANCE, &mut key_replay).map_err(str::to_owned)?,
        );
        check_replay(&key_rng, &key_replay)?;
        check_support(&secret)?;

        let plaintext = Zeroizing::new(
            Plaintext::try_encode(packed.values.as_slice(), encoding(packed), &parameters)
                .map_err(|e| e.to_string())?,
        );
        // Public conversion exposes the caller-created fixture's unscaled M,
        // never an Owner/SecretKey exporter or private upstream field.
        let plaintext_reference: &Plaintext = &plaintext;
        let actual = Zeroizing::new(
            Poly::try_convert_from(
                plaintext_reference,
                parameters.context_at_level(0).map_err(|e| e.to_string())?,
                false,
                Representation::PowerBasis,
            )
            .map_err(|e| e.to_string())?,
        );
        let reference = plaintext_coefficients(packed)?;
        if actual
            .coefficients()
            .row(0)
            .iter()
            .copied()
            .ne(reference.iter().copied())
        {
            return Err("independent SIMD/coefficient formation disagrees with upstream".into());
        }

        let mut noise_rng = ChaCha8Rng::from_seed([0x45; 32]);
        let mut noise_replay = noise_rng.clone();
        let ciphertext = <SecretKey as FheEncrypter<Plaintext, Ciphertext>>::try_encrypt(
            &key,
            plaintext_reference,
            &mut noise_rng,
        )
        .map_err(|e| e.to_string())?;
        let error = Zeroizing::new(
            sample_vec_cbd(DEGREE, VARIANCE, &mut noise_replay).map_err(str::to_owned)?,
        );
        check_replay(&noise_rng, &noise_replay)?;
        check_support(&error)?;
        // Actual upstream decryption is only an additional local positive control.
        let decrypted = Zeroizing::new(key.try_decrypt(&ciphertext).map_err(|e| e.to_string())?);
        let decrypted_reference: &Plaintext = &decrypted;
        let decoded: Vec<u64> =
            <Vec<u64> as FheDecoder<Plaintext>>::try_decode(decrypted_reference, encoding(packed))
                .map_err(|e| e.to_string())?;
        let decoded = Zeroizing::new(decoded);
        if *decoded != *packed.values {
            return Err("actual upstream encryption/decryption control disagrees".into());
        }
        Ok(Self {
            parameters,
            ciphertext,
            secret,
            error,
        })
    }

    pub(crate) fn check(&self, packed: &Packed) -> Result<()> {
        check_support(&self.secret)?;
        check_support(&self.error)?;
        if self.ciphertext.len() != 2
            || self.ciphertext[0].representation() != &Representation::Ntt
            || self.ciphertext[1].representation() != &Representation::Ntt
            || self.parameters.moduli() != MODULI
        {
            return Err("ciphertext profile/representation mismatch".into());
        }
        let mut scaled = plaintext_coefficients(packed)?;
        let q_mod_t = MODULI
            .iter()
            .fold(1, |value, q| mul(value, q % PLAINTEXT, PLAINTEXT));
        for value in scaled.iter_mut() {
            *value = mul(*value, q_mod_t, PLAINTEXT);
        }
        let a = self.ciphertext[1].coefficients();
        let b = self.ciphertext[0].coefficients();
        if a.dim() != (MODULI.len(), DEGREE) || b.dim() != a.dim() {
            return Err("incomplete public ciphertext residues".into());
        }
        for (basis, q) in MODULI.into_iter().enumerate() {
            let ntt = ReferenceNtt::new(q)?;
            let delta = pow(q - PLAINTEXT, q - 2, q);
            let mut secret = Zeroizing::new(
                self.secret
                    .iter()
                    .map(|v| signed(*v, q))
                    .collect::<Vec<_>>(),
            );
            let mut error =
                Zeroizing::new(self.error.iter().map(|v| signed(*v, q)).collect::<Vec<_>>());
            let mut plaintext =
                Zeroizing::new(scaled.iter().map(|v| mul(*v, delta, q)).collect::<Vec<_>>());
            ntt.forward(&mut secret)?;
            ntt.forward(&mut error)?;
            ntt.forward(&mut plaintext)?;
            for index in 0..DEGREE {
                let (a, b) = (a[(basis, index)], b[(basis, index)]);
                if a >= q || b >= q {
                    return Err("noncanonical public BFV residue".into());
                }
                let product = mul(a, secret[index], q);
                let expected = (error[index] + plaintext[index] + q - product) % q;
                if expected != b {
                    return Err(format!(
                        "formation mismatch at public basis{basis}/coefficient{index}"
                    ));
                }
            }
        }
        Ok(())
    }
}
fn signed(value: i64, modulus: u64) -> u64 {
    if value < 0 {
        modulus - value.unsigned_abs()
    } else {
        value as u64
    }
}
fn check_replay(actual: &ChaCha8Rng, replay: &ChaCha8Rng) -> Result<()> {
    let expected_words = 2 * CBD_U64_DRAWS as u128;
    if actual.get_word_pos() != expected_words || replay.get_word_pos() != expected_words {
        return Err("upstream caller RNG consumed a different CBD vector".into());
    }
    Ok(())
}
