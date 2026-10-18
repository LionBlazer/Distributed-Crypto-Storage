//! One synchronous proof at a time. A prover prefix never yields CheckedRelinearization.
use crate::{
    Component, Input, PreparedKey, Result,
    state::{Request, State},
};
pub struct Prover<'a> {
    key: &'a PreparedKey,
    input: &'a Input,
    identity: [u8; 64],
    state: State,
}
impl<'a> Prover<'a> {
    pub fn new(key: &'a PreparedKey, input: &'a Input) -> Self {
        Self {
            key,
            input,
            identity: crate::profile::identity(key, input),
            state: State::new(),
        }
    }
    pub fn progress(&self) -> usize {
        self.state.progress()
    }
    pub fn prove_next(&mut self) -> Result<Option<Component>> {
        let Some(stage) = self.state.next()? else {
            return Ok(None);
        };
        let request = self.state.request(self.key, self.input, self.identity)?;
        let (component, values) = match request {
            Request::Ntt(request) => {
                let generated = bfv_ntt_witness_proof::prove(&request)?;
                let component = Component::encode(
                    self.identity,
                    stage,
                    &generated.output.encode(),
                    &generated.proof,
                )?;
                (component, generated.output.coefficients().to_vec())
            }
            Request::Relin(request) => {
                let generated = bfv_relinearization_multilinear_proof::prove(&request)?;
                let component = Component::encode(
                    self.identity,
                    stage,
                    &generated.output.encode(),
                    &generated.proof,
                )?;
                (component, generated.output.coefficients().to_vec())
            }
        }; // The primitive generated object/backend drops before the next call.
        self.state.apply(stage, &values)?;
        Ok(Some(component))
    }
    /// Cancellation is only BETWEEN synchronous component calls.
    pub fn cancel(&mut self) {
        self.state.cancel();
    }
}
