//! Canonical public metadata only. Decoding never establishes Owner provenance.
use super::{BfvKeyAnchor, Error, KeyScope, PublicSetup, Result, keyset_id};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"BFVKAC01";

impl BfvKeyAnchor {
    /// Fixed public claim length. Contains no secret coefficient, opening or proof.
    pub const CLAIM_BYTES: usize = 140;

    /// Encode public association labels; this does not authenticate their origin.
    pub fn encode_claim(&self) -> Result<Vec<u8>> {
        if self
            .coefficients
            .iter()
            .any(|v| *v >= bfv_hiding_stark::Val::ORDER_U64)
        {
            return Err(Error::InvalidShape);
        }
        let mut out = Vec::with_capacity(Self::CLAIM_BYTES);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.scope.database);
        out.extend_from_slice(&self.scope.bfv_key_domain);
        out.extend_from_slice(&self.scope.epoch.to_le_bytes());
        out.extend_from_slice(&self.full_setup_id);
        out.extend_from_slice(&self.parameter_digest);
        for value in self.coefficients {
            out.extend_from_slice(&value.to_le_bytes());
        }
        Ok(out)
    }
}

impl PublicSetup {
    /// Decode untrusted public anchor labels for this exact installed setup.
    ///
    /// This verifies canonical grammar and setup/parameter association only. It
    /// proves neither Owner origin, secret possession, KeyTransform nor same-secret
    /// evaluation keys. Clients must retain their independently pinned anchor;
    /// an anchor decoded from a peer must never replace it.
    pub fn decode_key_anchor_claim(&self, bytes: &[u8]) -> Result<BfvKeyAnchor> {
        if bytes.len() != BfvKeyAnchor::CLAIM_BYTES || &bytes[..8] != MAGIC {
            return Err(Error::InvalidShape);
        }
        let coefficients = core::array::from_fn(|i| {
            u64::from_le_bytes(bytes[108 + 8 * i..116 + 8 * i].try_into().unwrap())
        });
        if coefficients
            .iter()
            .any(|v| *v >= bfv_hiding_stark::Val::ORDER_U64)
        {
            return Err(Error::InvalidShape);
        }
        self.checked_parameters()?;
        let full_setup_id = bytes[44..76].try_into().unwrap();
        let parameter_digest = bytes[76..108].try_into().unwrap();
        if keyset_id(self)? != full_setup_id
            || <[u8; 32]>::from(Sha256::digest(&self.parameters)) != parameter_digest
        {
            return Err(Error::BindingMismatch);
        }
        Ok(BfvKeyAnchor {
            scope: KeyScope {
                database: bytes[8..24].try_into().unwrap(),
                bfv_key_domain: bytes[24..40].try_into().unwrap(),
                epoch: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
            },
            full_setup_id,
            parameter_digest,
            coefficients,
        })
    }
}
