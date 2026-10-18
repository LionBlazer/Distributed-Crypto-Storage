//! One bounded public component, never an aggregate or a serialized checked token.
use crate::{Error, HEADER_BYTES, MAX_COMPONENT_BYTES, Result, state::Stage};
const MAGIC: &[u8; 8] = b"BFVCRL01";
pub struct Component {
    bytes: Vec<u8>,
}
impl Component {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub(crate) fn encode(
        identity: [u8; 64],
        stage: Stage,
        output: &[u8],
        proof: &[u8],
    ) -> Result<Self> {
        check_lengths(stage, output.len(), proof.len())?;
        let mut bytes = vec![0; HEADER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..72].copy_from_slice(&crate::profile_digest());
        bytes[72..136].copy_from_slice(&identity);
        bytes[136..140].copy_from_slice(&stage.metadata());
        bytes[140..144].copy_from_slice(&(output.len() as u32).to_le_bytes());
        bytes[144..148].copy_from_slice(&(proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(output);
        bytes.extend_from_slice(proof);
        Ok(Self { bytes })
    }
}
fn check_lengths(stage: Stage, output: usize, proof: usize) -> Result<()> {
    let proof_cap = if stage.kind == 1 || stage.kind == 3 {
        bfv_ntt_witness_proof::MAX_PROOF_BYTES
    } else {
        bfv_relinearization_multilinear_proof::MAX_PROOF_BYTES
    };
    if output != stage.output_bytes()
        || proof == 0
        || proof > proof_cap
        || HEADER_BYTES
            .checked_add(output)
            .and_then(|n| n.checked_add(proof))
            .is_none_or(|n| n > MAX_COMPONENT_BYTES)
    {
        return Err(Error::Component);
    }
    Ok(())
}
/// Validate exact role/ordinal/profile/identity/lengths BEFORE typed-output allocation
/// or primitive backend analysis. Borrowed views do not reserve network lengths.
pub(crate) fn decode(identity: [u8; 64], stage: Stage, bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > MAX_COMPONENT_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..72] != crate::profile_digest()
        || bytes[72..136] != identity
        || bytes[136..140] != stage.metadata()
        || bytes[148..HEADER_BYTES] != [0; HEADER_BYTES - 148]
    {
        return Err(Error::Component);
    }
    let output = u32::from_le_bytes(bytes[140..144].try_into().unwrap()) as usize;
    let proof = u32::from_le_bytes(bytes[144..148].try_into().unwrap()) as usize;
    check_lengths(stage, output, proof)?;
    if HEADER_BYTES
        .checked_add(output)
        .and_then(|n| n.checked_add(proof))
        != Some(bytes.len())
    {
        return Err(Error::Component);
    }
    Ok((
        &bytes[HEADER_BYTES..HEADER_BYTES + output],
        &bytes[HEADER_BYTES + output..],
    ))
}
