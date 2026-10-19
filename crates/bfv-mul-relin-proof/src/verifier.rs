//! Sequential actual proof admission; no prefix result or query re-execution.
use crate::graph::NodeRequest;
use crate::{
    Error, Expected, GraphClaims, InputEvidence, MAX_ATTEMPTS, MAX_PROOF_BYTES, MAX_SESSION_BYTES,
    NODES, NodeOutput, PROOF_RECORDS, PreparedGraph, RECORD_HEADER, Result,
};
use bfv_relinearization_key_source::PreparedKey;
pub(crate) fn packet_node(ordinal: usize) -> Option<usize> {
    if ordinal == 0 {
        return Some(NODES);
    }
    (0..NODES)
        .filter(|n| !matches!(n,20..=23|44..=53|84..=86))
        .nth(ordinal - 1)
}
pub(crate) fn encode_record(
    identity: [u8; 64],
    ordinal: usize,
    node: usize,
    proof: &[u8],
) -> Result<Vec<u8>> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES || packet_node(ordinal) != Some(node) {
        return Err(Error::ResourceLimit);
    }
    let mut b = vec![0; RECORD_HEADER];
    b[..8].copy_from_slice(b"BFVMRP01");
    b[8..72].copy_from_slice(&crate::profile_digest());
    b[72..136].copy_from_slice(&identity);
    b[136..138].copy_from_slice(&(ordinal as u16).to_le_bytes());
    b[138..140].copy_from_slice(&(node as u16).to_le_bytes());
    b[140..144].copy_from_slice(&(proof.len() as u32).to_le_bytes());
    b.extend(proof);
    Ok(b)
}
fn decode_record(identity: [u8; 64], ordinal: usize, bytes: &[u8]) -> Result<&[u8]> {
    let node = packet_node(ordinal).ok_or(Error::Stage)?;
    if bytes.len() <= RECORD_HEADER || bytes.len() > RECORD_HEADER + MAX_PROOF_BYTES {
        return Err(Error::ResourceLimit);
    }
    if bytes[..8] != *b"BFVMRP01"
        || bytes[8..72] != crate::profile_digest()
        || bytes[72..136] != identity
        || bytes[136..138] != (ordinal as u16).to_le_bytes()
        || bytes[138..140] != (node as u16).to_le_bytes()
        || bytes[144..RECORD_HEADER] != [0; 16]
        || u32::from_le_bytes(bytes[140..144].try_into().unwrap()) as usize
            != bytes.len() - RECORD_HEADER
    {
        return Err(Error::Statement);
    }
    Ok(&bytes[RECORD_HEADER..])
}
pub struct Verifier<'a> {
    expected: &'a Expected,
    key: &'a PreparedKey,
    graph: Option<PreparedGraph>,
    inputs: bool,
    next: usize,
    attempts: usize,
    bytes: usize,
    error_probability: f64,
    cancelled: bool,
}
impl<'a> Verifier<'a> {
    pub fn new(expected: &'a Expected, key: &'a PreparedKey) -> Self {
        Self {
            expected,
            key,
            graph: None,
            inputs: false,
            next: 0,
            attempts: 0,
            bytes: 0,
            error_probability: 0.,
            cancelled: false,
        }
    }
    fn charge(&mut self, bytes: usize) -> Result<()> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        self.attempts = self.attempts.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.attempts > MAX_ATTEMPTS || self.bytes > MAX_SESSION_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
    pub fn accept_claims(&mut self, bytes: &[u8]) -> Result<()> {
        self.charge(bytes.len())?;
        if self.graph.is_some() {
            return Err(Error::Stage);
        }
        let claims = GraphClaims::decode(crate::profile_digest(), bytes)?;
        let prepared = PreparedGraph::prepare(self.expected, self.key, claims)?;
        self.graph = Some(prepared);
        Ok(())
    }
    pub fn verify_inputs(&mut self, evidence: &InputEvidence<'_>) -> Result<()> {
        self.charge(evidence.byte_len().unwrap_or(usize::MAX))?;
        if self.inputs || self.graph.is_none() {
            return Err(Error::Stage);
        }
        self.expected.provenance.verify_inputs(evidence)?;
        self.inputs = true;
        Ok(())
    }
    pub fn progress(&self) -> usize {
        self.next
    }
    pub fn attempted_bytes(&self) -> usize {
        self.bytes
    }
    pub fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        self.charge(bytes.len())?;
        if !self.inputs {
            return Err(Error::Incomplete);
        }
        let graph = self.graph.as_ref().ok_or(Error::Incomplete)?;
        let proof = decode_record(graph.identity, self.next, bytes)?;
        let node = packet_node(self.next).ok_or(Error::Stage)?;
        let (bits, unassessed) = if node == NODES {
            let checked = bfv_arithmetic_batch_proof::verify(&graph.arithmetic, proof)
                .map_err(|_| Error::Proof)?;
            if !checked.matches(&graph.arithmetic) {
                return Err(Error::Statement);
            }
            let r = checked.security_report();
            (r.whole_security_bits, !r.unassessed_components.is_empty())
        } else {
            match (&graph.requests[node], &graph.claims.nodes()[node]) {
                (NodeRequest::Ntt(r), NodeOutput::Ntt(o)) => {
                    let c = bfv_ntt_witness_proof::verify(r, o, proof).map_err(|_| Error::Proof)?;
                    if !c.matches(r, o) {
                        return Err(Error::Statement);
                    }
                    let r = c.security_report();
                    (r.whole_security_bits, !r.unassessed_components.is_empty())
                }
                (NodeRequest::Relin(r), NodeOutput::Relin(o)) => {
                    let c = bfv_relinearization_multilinear_proof::verify(r, o, proof)
                        .map_err(|_| Error::Proof)?;
                    if !c.matches(r, o) {
                        return Err(Error::Statement);
                    }
                    let r = c.security_report();
                    (r.whole_security_bits, !r.unassessed_components.is_empty())
                }
                _ => return Err(Error::Stage),
            }
        };
        if !bits.is_finite() || bits < 144. || unassessed {
            return Err(Error::Security);
        }
        let probability = self.error_probability + (-bits).exp2();
        if !probability.is_finite() || probability <= 0. {
            return Err(Error::Security);
        }
        self.error_probability = probability;
        self.next += 1;
        Ok(())
    }
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.graph = None;
        self.inputs = false;
    }
    pub fn finish(self) -> Result<CheckedProduct> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if self.attempts > MAX_ATTEMPTS || self.bytes > MAX_SESSION_BYTES {
            return Err(Error::ResourceLimit);
        }
        if !self.inputs || self.next != PROOF_RECORDS {
            return Err(Error::Incomplete);
        }
        let graph = self.graph.ok_or(Error::Incomplete)?;
        let output_bits = -self.error_probability.log2();
        if !output_bits.is_finite() || output_bits < 144. {
            return Err(Error::Security);
        }
        Ok(CheckedProduct {
            identity: graph.identity,
            output: self.expected.output.clone(),
            output_bits,
        })
    }
}
/// Complete mathematical FHE product, not SQL/freshness/authorization authority.
/// output_bits covers output SDK proofs only. Input proofs retain their original
/// individual128 policies; this object makes no whole128 or whole144 claim.
pub struct CheckedProduct {
    identity: [u8; 64],
    output: Vec<u8>,
    output_bits: f64,
}
impl CheckedProduct {
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn output_ciphertext(&self) -> &[u8] {
        &self.output
    }
    pub fn output_sdk_security_bits(&self) -> f64 {
        self.output_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_envelope_binds_identity_order_node_length_and_reserved_fields() {
        // Deliberately unproved inner bytes: this test grants no result.
        let identity = [0x51; 64];
        let frame = encode_record(identity, 1, 0, &[7; 17]).unwrap();
        assert_eq!(decode_record(identity, 1, &frame).unwrap(), &[7; 17]);
        for offset in [0, 8, 72, 136, 138, 140, 144, 159] {
            let mut changed = frame.clone();
            changed[offset] ^= 1;
            assert!(decode_record(identity, 1, &changed).is_err());
        }
        assert!(decode_record([0x52; 64], 1, &frame).is_err());
        assert!(decode_record(identity, 2, &frame).is_err());
        assert!(decode_record(identity, 1, &frame[..frame.len() - 1]).is_err());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_record(identity, 1, &trailing).is_err());
        assert!(decode_record(identity, PROOF_RECORDS, &frame).is_err());
        assert!(decode_record(identity, 1, &[0; RECORD_HEADER]).is_err());
        assert!(encode_record(identity, 1, 0, &[]).is_err());
    }
}
