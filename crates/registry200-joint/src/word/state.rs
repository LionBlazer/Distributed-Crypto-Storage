//! Distinct control-head family. A decoded head supplies no proof or freshness.
use super::{Descriptor, Error, Result};
use registry200_proof::{
    Val,
    source::statement::{decode_digest, encode_digest},
};
use version_journal::HeadPair;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Pending,
    Active {
        enrollment: [Val; 4],
        registry: [Val; 4],
    },
}
impl Control {
    pub fn heads(self, d: &Descriptor) -> HeadPair {
        let (phase, registry, enrollment) = match self {
            Self::Pending => (0, [0; 32], [0; 32]),
            Self::Active {
                enrollment,
                registry,
            } => (1, encode_digest(registry), encode_digest(enrollment)),
        };
        let make = |component, root: [u8; 32]| {
            let mut b = [0; 112];
            b[..8].copy_from_slice(b"DCSWCH01");
            b[8..24].copy_from_slice(&d.database());
            b[24] = component;
            b[25] = phase;
            b[32..64].copy_from_slice(&d.id());
            b[64..96].copy_from_slice(&root);
            b
        };
        HeadPair {
            data: make(1, registry),
            index: make(2, enrollment),
        }
    }
    pub fn decode(d: &Descriptor, heads: HeadPair) -> Result<Self> {
        let state = match heads.data[25] {
            0 => Self::Pending,
            1 => Self::Active {
                enrollment: decode_digest(heads.index[64..96].try_into().unwrap())
                    .map_err(|_| Error::InvalidEncoding)?,
                registry: decode_digest(heads.data[64..96].try_into().unwrap())
                    .map_err(|_| Error::InvalidEncoding)?,
            },
            _ => return Err(Error::InvalidEncoding),
        };
        if state.heads(d) != heads {
            return Err(Error::InvalidEncoding);
        }
        Ok(state)
    }
}
