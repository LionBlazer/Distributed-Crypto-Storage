//! Actual primitive verification and exact endpoint routing, never query re-execution.
use crate::{
    Error, Input, MAX_ATTEMPTS, MAX_STREAM_BYTES, PreparedKey, Result, component,
    state::{Request, State},
};

pub struct Verifier<'a> {
    key: &'a PreparedKey,
    input: &'a Input,
    identity: [u8; 64],
    state: State,
    attempted: usize,
    attempted_bytes: usize,
}
impl<'a> Verifier<'a> {
    pub fn new(key: &'a PreparedKey, input: &'a Input) -> Self {
        Self {
            key,
            input,
            identity: crate::profile::identity(key, input),
            state: State::new(),
            attempted: 0,
            attempted_bytes: 0,
        }
    }
    pub fn progress(&self) -> usize {
        self.state.progress()
    }
    /// Rejected candidates consume the same lifetime attempt/byte budget, but
    /// never change verified arithmetic state or advance the component ordinal.
    pub fn accept(&mut self, bytes: &[u8]) -> Result<()> {
        let stage = self.state.next()?.ok_or(Error::Stage)?;
        self.attempted = self.attempted.checked_add(1).ok_or(Error::ResourceLimit)?;
        self.attempted_bytes = self
            .attempted_bytes
            .checked_add(bytes.len())
            .ok_or(Error::ResourceLimit)?;
        if self.attempted > MAX_ATTEMPTS || self.attempted_bytes > MAX_STREAM_BYTES {
            return Err(Error::ResourceLimit);
        }
        let (output, proof) = component::decode(self.identity, stage, bytes)?;
        let request = self.state.request(self.key, self.input, self.identity)?;
        let values = match request {
            Request::Ntt(request) => {
                let output = bfv_ntt_circuit::decode_output(output)?;
                let checked = bfv_ntt_witness_proof::verify(&request, &output, proof)?;
                if !checked.matches(&request, &output) {
                    return Err(Error::Identity);
                }
                output.coefficients().to_vec()
            }
            Request::Relin(request) => {
                let output = bfv_relinearization_circuit::decode_output(output)?;
                let checked =
                    bfv_relinearization_multilinear_proof::verify(&request, &output, proof)?;
                if !checked.matches(&request, &output) {
                    return Err(Error::Identity);
                }
                output.coefficients().to_vec()
            }
        }; // No decoded proof/backend survives this component admission.
        self.state.apply(stage, &values)
    }
    pub fn cancel(&mut self) {
        self.state.cancel();
    }
    pub fn finish(self) -> Result<CheckedRelinearization> {
        Ok(CheckedRelinearization {
            identity: self.identity,
            output: self.state.finish()?,
        })
    }
}
/// Only the complete32 verifier can construct this public mathematical result.
/// It grants no SQL, same-secret-key, freshness, writer or production authority.
pub struct CheckedRelinearization {
    identity: [u8; 64],
    output: [Vec<u64>; 2],
}
impl CheckedRelinearization {
    pub fn matches(&self, key: &PreparedKey, input: &Input) -> bool {
        self.identity == crate::profile::identity(key, input)
    }
    /// Complete nativeNTT component-major Q5 rows; NOT SDK PB protobuf bytes.
    pub fn output(&self) -> &[Vec<u64>; 2] {
        &self.output
    }
    pub fn into_output(self) -> [Vec<u64>; 2] {
        self.output
    }
}
