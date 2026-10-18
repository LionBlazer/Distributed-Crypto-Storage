//! Independent complete public bindings. A commitment is mathematical input, not SQL authority.
use crate::{NOISE_DOMAIN, PUBLIC_VALUES, circuit, profile_digest};
use bfv_basis_convolution::Statement as BasisStatement;
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedCommitment {
    producer_identity: [u8; 32],
    context: [u64; 8],
    root: [u64; 4],
}
impl EncodedCommitment {
    pub fn new(
        producer_identity: [u8; 32],
        context: [u64; 8],
        root: [u64; 4],
    ) -> Result<Self, Error> {
        if context.iter().chain(&root).any(|x| *x >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        Ok(Self {
            producer_identity,
            context,
            root,
        })
    }
    pub fn producer_identity(&self) -> [u8; 32] {
        self.producer_identity
    }
    pub fn context(&self) -> [u64; 8] {
        self.context
    }
    pub fn root(&self) -> [u64; 4] {
        self.root
    }
}
#[derive(Clone)]
pub struct Expected {
    pub(crate) encoding: EncodedCommitment,
    pub(crate) bases: [BasisStatement; 5],
}
impl Expected {
    pub fn new(encoding: EncodedCommitment, bases: [BasisStatement; 5]) -> Result<Self, Error> {
        let value = Self { encoding, bases };
        value.validate()?;
        Ok(value)
    }
    pub fn encoding(&self) -> &EncodedCommitment {
        &self.encoding
    }
    pub fn bases(&self) -> &[BasisStatement; 5] {
        &self.bases
    }
    pub fn key(&self) -> &bfv_key_transform::Statement {
        self.bases[0].expected.key()
    }
    pub fn request(&self) -> [u8; 32] {
        self.bases[0].expected.request()
    }
    pub fn ciphertext(&self) -> &bfv_basis_convolution::CanonicalCiphertext {
        self.bases[0].expected.ciphertext()
    }
    pub fn validate(&self) -> Result<(), Error> {
        let first = &self.bases[0].expected;
        for (i, s) in self.bases.iter().enumerate() {
            let e = &s.expected;
            if e.ciphertext().basis() != i
                || e.key().public_values() != first.key().public_values()
                || e.request() != first.request()
                || e.ciphertext().bytes() != first.ciphertext().bytes()
                || e.ciphertext().parameter_bytes() != first.ciphertext().parameter_bytes()
            {
                return Err(Error::Shape);
            }
        }
        Ok(())
    }
    pub fn binding(&self, full_setup_id: [u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/BFV-CIPHERTEXT-FORMATION-EXPECTED/v1");
        h.update(profile_digest());
        h.update(full_setup_id);
        h.update(self.encoding.producer_identity);
        for v in self.encoding.context.into_iter().chain(self.encoding.root) {
            h.update(v.to_le_bytes());
        }
        for s in &self.bases {
            for v in s.public_values() {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        for b in [
            self.ciphertext().parameter_bytes(),
            self.ciphertext().bytes(),
        ] {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        }
        h.finalize().into()
    }
    pub fn context(&self, full_setup_id: [u8; 32]) -> [Val; 8] {
        bfv_basis_convolution::words(&self.binding(full_setup_id))
    }
}
#[derive(Clone)]
pub struct Statement {
    pub expected: Expected,
    pub full_setup_id: [u8; 32],
    pub noise: [Val; 4],
}
impl Statement {
    pub fn contexts(&self) -> [[Val; 8]; 7] {
        core::array::from_fn(|i| match i {
            0..=4 => self.expected.bases[i].contexts()[1],
            5 => self.expected.encoding.context.map(Val::from_u64),
            _ => {
                let mut h = Sha256::new();
                h.update(NOISE_DOMAIN);
                for v in self.expected.context(self.full_setup_id) {
                    h.update(v.as_canonical_u64().to_le_bytes());
                }
                bfv_basis_convolution::words(&h.finalize().into())
            }
        })
    }
    pub fn public_values(&self) -> Vec<Val> {
        bfv_basis_convolution::words(&profile_digest())
            .into_iter()
            .chain(self.expected.context(self.full_setup_id))
            .chain(self.expected.encoding.root.map(Val::from_u64))
            .chain(self.expected.bases.iter().flat_map(|s| s.result))
            .chain(self.noise)
            .collect()
    }
    pub fn air(&self) -> Result<circuit::FormationAir, Error> {
        let s = circuit::CircuitStatement::new(
            self.public_values().try_into().map_err(|_| Error::Shape)?,
            self.contexts(),
            core::array::from_fn(|i| {
                self.expected.bases[i]
                    .expected
                    .ciphertext()
                    .b_coefficients()
                    .to_vec()
            }),
        )?;
        Ok(circuit::FormationAir::new(s))
    }
}
const _: () = assert!(PUBLIC_VALUES == 44);
