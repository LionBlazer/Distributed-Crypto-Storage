//! Independently derived PUBLIC endpoints. Never accepts a root/spectrum from a peer.
use super::*;
use bfv_hiding_stark::poseidon;

/// Fixed capacity IV. Separate acyclic transcript, not profile(IV(profile(...))).
/// Four consecutive LE64 words of SHA512 reduced modulo Gold; no randomness claim.
pub(super) fn iv() -> [Val; 4] {
    let mut h = Sha512::new();
    h.update(b"DCS/CoreGold/public-coeff-capacity-IV/v1");
    h.update(
        b"A_freq_Q0,A_freq_Q1,c0_Q0,c0_Q1;4096-each;additive-rate8;full12carry;no-prefix;no-salt",
    );
    for v in [
        N as u64,
        crate::gold::geometry::Q[0],
        crate::gold::geometry::Q[1],
        crate::gold::geometry::T,
        COEFFICIENT_WORDS as u64,
        fft::PSI,
    ] {
        h.update(v.to_le_bytes());
    }
    let digest = h.finalize();
    core::array::from_fn(|i| {
        Val::from_u64(u64::from_le_bytes(
            digest[8 * i..8 * i + 8]
                .try_into()
                .expect("fixed SHA512 word"),
        ))
    })
}
pub(super) fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(BUS.as_bytes());
    h.update(
        b"fixed-order[Data,PublicCoeffHash];global-terminal-sum;PV48+4;actual-native-defaultpack",
    );
    h.update(b"S/E+-20;K+-524287;W<=65536;range4096;Cw514/Cs66-original-salted-format");
    h.update(b"coefficient-stream=A_freq_Q0,A_freq_Q1,c0_Q0,c0_Q1;all4096each;additive-rate8/full12carry/capacity-IV/no-prefix/no-salt");
    h.update(data::profile_digest()); // Mathematical lineage, NOT an old-profile cast.
    for v in [
        H,
        W,
        PP,
        PV,
        HASH_W,
        HASH_PP,
        HASH_PV,
        PORTS,
        HASH_PORTS,
        GATES,
        COEFFICIENT_WORDS,
        FREQ_TAG,
        C0_TAG,
    ] {
        h.update((v as u64).to_le_bytes());
    }
    for v in iv() {
        h.update(v.as_canonical_u64().to_le_bytes());
    }
    h.finalize().into()
}

/// Metadata only; no source/key/current-head/SQL or successful proof is represented.
pub(super) struct PublicExpected {
    pub(super) coefficients: Vec<Val>,
    pub(super) data_values: [Val; PV],
    pub(super) hash_values: [Val; HASH_PV],
    pub(super) binding: [u8; 64],
    literal_request: Vec<u8>,
}
impl PublicExpected {
    pub(super) fn checked(expected: &data::Expected) -> Result<Self> {
        // Actual canonical SDK wire parse/EOF/bounds, even when callers hold typed metadata.
        let request = data::Request::decode(expected.request().bytes())?;
        if request.bytes() != expected.request().bytes() {
            return Err(Error::Binding);
        }
        let fast = fft::Plan::new()?;
        let mut coefficients = Vec::with_capacity(COEFFICIENT_WORDS);
        for basis in 0..2 {
            coefficients.extend(
                fast.public_frequency(&request.input(1)[basis], crate::gold::geometry::Q[basis])?
                    .into_iter()
                    .map(Val::from_u64),
            );
        }
        for basis in 0..2 {
            coefficients.extend(request.input(0)[basis].iter().copied().map(Val::from_u64));
        }
        if coefficients.len() != COEFFICIENT_WORDS {
            return Err(Error::Shape);
        }
        let hash_values = coefficient_root(&coefficients)?;
        let mut h = Sha512::new();
        h.update(DOMAIN);
        h.update(b"/complete-independent-Expected/v1");
        h.update(profile());
        h.update((request.bytes().len() as u64).to_le_bytes());
        h.update(request.bytes());
        h.update(expected.binding()); // Includes the entire retained association, contexts and roots.
        for v in hash_values {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        let binding: [u8; 64] = h.finalize().into();
        let mut data_values = [Val::ZERO; PV];
        for (i, word) in profile().as_chunks::<4>().0.iter().enumerate() {
            data_values[i] = Val::from_u32(u32::from_le_bytes(*word));
        }
        for (i, word) in binding.as_chunks::<4>().0.iter().enumerate() {
            data_values[8 + i] = Val::from_u32(u32::from_le_bytes(*word));
        }
        // Cs then Cw roots, followed by Cw then Cs contexts. All are ordinary PV.
        data_values[24..28].copy_from_slice(&expected.roots()[1]);
        data_values[28..32].copy_from_slice(&expected.roots()[0]);
        data_values[32..40].copy_from_slice(&expected.contexts()[0]);
        data_values[40..48].copy_from_slice(&expected.contexts()[1]);
        Ok(Self {
            coefficients,
            data_values,
            hash_values,
            binding,
            literal_request: request.bytes().to_vec(),
        })
    }
    pub(super) fn request_bytes(&self) -> &[u8] {
        &self.literal_request
    }
}

/// Exactly2048 full Poseidon2 absorbs of literal public coefficients. No private data,
/// FHE evaluation, NTT of a secret, or Source proof is performed by this helper.
pub(super) fn coefficient_root(values: &[Val]) -> Result<[Val; 4]> {
    if values.len() != COEFFICIENT_WORDS {
        return Err(Error::Shape);
    }
    let mut state = [Val::ZERO; 12];
    state[8..].copy_from_slice(&iv());
    for block in values.as_chunks::<8>().0 {
        let mut input = state;
        for i in 0..8 {
            input[i] += block[i];
        }
        let mut row = [Val::ZERO; poseidon::WIDTH];
        state = poseidon::write(&mut row, input);
    }
    Ok(state[..4].try_into().expect("four root coordinates"))
}
