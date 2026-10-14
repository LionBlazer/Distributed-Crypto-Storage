//! Experimental seed recovery for one exact pinned Spiral profile.
//! The owner image is secret trusted state; the original public setup is retained separately.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use spiral_rs::{
    client::{Client, PublicParameters},
    params::Params,
};
use zeroize::Zeroizing;

pub const SDK_REVISION: &str = "fdb7206517c249603b0c91b65f1f29f95272107c";
pub const OWNER_STATE_BYTES: usize = 336;
pub const PUBLIC_SETUP_BYTES: usize = 6_029_344;
pub const RECORD_BYTES: usize = 8192;
pub const RECORD_SLOTS: usize = 512;
const MAGIC: &[u8; 8] = b"SPROWNR1";
const SDK_BYTES: [u8; 20] = [
    0xfd, 0xb7, 0x20, 0x65, 0x17, 0xc2, 0x49, 0x60, 0x3b, 0x0c, 0x91, 0xb6, 0x5f, 0x1f, 0x29, 0xf9,
    0x52, 0x72, 0x10, 0x7c,
];
const CONTRACT: &[u8] = b"Spiral-owner-v1;rand=0.8.5;rand_chacha=0.3.1;ChaCha20Rng;SliceRandom;ternary+256-256;fresh-query-entropy;LE64;Gaussian-width6.4";
const PROFILE_OFFSET: usize = 96;
const PUBLIC_OFFSET: usize = 240;
const SEED_OFFSET: usize = 272;
const CHECKSUM_OFFSET: usize = 304;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    UnsupportedPlatform,
    ProfileMismatch,
    OsRandomness,
    OwnerImageLength,
    OwnerImageHeader,
    OwnerImageCorrupt,
    DomainMismatch,
    PublicSetupLength,
    PublicSetupMismatch,
}
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Spiral owner recovery: {self:?}")
    }
}
impl std::error::Error for RecoveryError {}

/// Opaque owner-only image. Never send this to a peer or print it.
/// Its checksum detects corruption; the caller supplies trusted confidential storage.
pub struct OwnerState {
    image: Zeroizing<[u8; OWNER_STATE_BYTES]>,
}

pub struct KeySetup<'a> {
    pub owner: OwnerState,
    pub client: Client<'a>,
    pub public_wire: Vec<u8>,
}

pub struct Restored<'a> {
    pub owner: OwnerState,
    pub client: Client<'a>,
    pub public: PublicParameters<'a>,
}

/// Same parameters as CFG_20_256 with nu_1=7 and nu_2=2 in the private-BFV pipeline.
/// SDK JSON parsing ignores s_e and fixes the actual Gaussian width to 6.4.
pub fn profile_params() -> Params {
    Params::init(
        2048,
        &[268_369_921, 249_561_089],
        6.4,
        2,
        256,
        20,
        4,
        8,
        56,
        8,
        true,
        7,
        2,
        1,
        RECORD_BYTES,
        0,
    )
}

fn profile_descriptor(params: &Params) -> [u8; 144] {
    let words = [
        params.poly_len as u64,
        params.crt_count as u64,
        params.moduli[0],
        params.moduli[1],
        params.noise_width.to_bits(),
        params.n as u64,
        params.pt_modulus,
        params.q2_bits,
        params.t_conv as u64,
        params.t_exp_left as u64,
        params.t_exp_right as u64,
        params.t_gsw as u64,
        u64::from(params.expand_queries),
        params.db_dim_1 as u64,
        params.db_dim_2 as u64,
        params.instances as u64,
        params.db_item_size as u64,
        params.version as u64,
    ];
    let mut out = [0u8; 144];
    for (dst, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn validate_profile(params: &Params) -> Result<(), RecoveryError> {
    if !cfg!(all(target_endian = "little", target_pointer_width = "64")) {
        return Err(RecoveryError::UnsupportedPlatform);
    }
    // Also reject caller-mutated derived NTT, Barrett or scratch parameters.
    if *params != profile_params() {
        return Err(RecoveryError::ProfileMismatch);
    }
    Ok(())
}

fn header(image: &mut [u8; OWNER_STATE_BYTES], params: &Params, domain: [u8; 32]) {
    image[..8].copy_from_slice(MAGIC);
    image[8..10].copy_from_slice(&1u16.to_le_bytes());
    image[10] = 1; // native SDK public wire: little endian
    image[11] = 8; // 64-bit usize/platform contract
    image[12..32].copy_from_slice(&SDK_BYTES);
    image[32..64].copy_from_slice(&Sha256::digest(CONTRACT));
    image[64..96].copy_from_slice(&domain);
    image[PROFILE_OFFSET..PUBLIC_OFFSET].copy_from_slice(&profile_descriptor(params));
}

impl OwnerState {
    pub fn generate<'a>(
        params: &'a Params,
        domain: [u8; 32],
    ) -> Result<KeySetup<'a>, RecoveryError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| RecoveryError::OsRandomness)?;
        Self::create_with_seed_for_experiment(params, domain, seed)
    }

    /// Caller-supplied seed entry point for explicitly public non-secret test fixtures.
    /// Normal callers use generate(); never reuse one seed across unrelated owners.
    pub fn create_with_seed_for_experiment<'a>(
        params: &'a Params,
        domain: [u8; 32],
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<KeySetup<'a>, RecoveryError> {
        validate_profile(params)?;
        let mut client = Client::init(params);
        let public = client.generate_keys_from_seed(*seed);
        let public_wire = public.serialize();
        if public_wire.len() != PUBLIC_SETUP_BYTES {
            return Err(RecoveryError::PublicSetupLength);
        }
        let mut image = Zeroizing::new([0u8; OWNER_STATE_BYTES]);
        header(&mut image, params, domain);
        image[PUBLIC_OFFSET..SEED_OFFSET].copy_from_slice(&Sha256::digest(&public_wire));
        image[SEED_OFFSET..CHECKSUM_OFFSET].copy_from_slice(seed.as_ref());
        let checksum = Sha256::digest(&image[..CHECKSUM_OFFSET]);
        image[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        Ok(KeySetup {
            owner: Self { image },
            client,
            public_wire,
        })
    }

    /// The returned buffer is secret owner-only state, not a peer message.
    pub fn encode_secret_for_experiment(&self) -> Zeroizing<[u8; OWNER_STATE_BYTES]> {
        Zeroizing::new(*self.image)
    }

    /// Restore both secret keys using the supported SDK seed API and retain the
    /// original public setup. No public keys are regenerated during restoration.
    pub fn restore<'a>(
        params: &'a Params,
        expected_domain: [u8; 32],
        owner_image: &[u8],
        original_public_wire: &[u8],
    ) -> Result<Restored<'a>, RecoveryError> {
        validate_profile(params)?;
        if owner_image.len() != OWNER_STATE_BYTES {
            return Err(RecoveryError::OwnerImageLength);
        }
        let expected_checksum = Sha256::digest(&owner_image[..CHECKSUM_OFFSET]);
        if owner_image[CHECKSUM_OFFSET..] != expected_checksum[..] {
            return Err(RecoveryError::OwnerImageCorrupt);
        }
        let mut expected = Zeroizing::new([0u8; OWNER_STATE_BYTES]);
        header(&mut expected, params, expected_domain);
        if owner_image[..64] != expected[..64] {
            return Err(RecoveryError::OwnerImageHeader);
        }
        if owner_image[64..96] != expected_domain {
            return Err(RecoveryError::DomainMismatch);
        }
        if owner_image[PROFILE_OFFSET..PUBLIC_OFFSET] != expected[PROFILE_OFFSET..PUBLIC_OFFSET] {
            return Err(RecoveryError::ProfileMismatch);
        }
        if original_public_wire.len() != PUBLIC_SETUP_BYTES {
            return Err(RecoveryError::PublicSetupLength);
        }
        if owner_image[PUBLIC_OFFSET..SEED_OFFSET] != Sha256::digest(original_public_wire)[..] {
            return Err(RecoveryError::PublicSetupMismatch);
        }
        // Only trusted and fully bound inputs reach the SDK's asserting decoder.
        let public = PublicParameters::deserialize(params, original_public_wire);
        let mut client = Client::init(params);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&owner_image[SEED_OFFSET..CHECKSUM_OFFSET]);
        client.generate_secret_keys_from_seed(*seed);
        expected.copy_from_slice(owner_image);
        Ok(Restored {
            owner: Self { image: expected },
            client,
            public,
        })
    }
}
