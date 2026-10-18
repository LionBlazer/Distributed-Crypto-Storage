use crate::Error;
use bfv_ntt_circuit::{Basis, Direction, Output, Request, multistark::validate_batch};
use sha2::{Digest, Sha512};
/// Independent opaque labels. Neither is setup/key authority or freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub query: [u8; 32],
    pub setup: [u8; 32],
}
pub fn instance_binding(
    context: Context,
    index: usize,
    direction: Direction,
    basis: Basis,
) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"DCS/NTT-BATCH/v2/instance-binding/");
    h.update(context.query);
    h.update(context.setup);
    h.update((index as u64).to_le_bytes());
    h.update([direction as u8, basis.index()]);
    h.finalize()[..32].try_into().unwrap()
}
/// Complete verifier-owned statement; no proof-selected input, table list or output.
#[derive(Clone)]
pub struct Expected {
    context: Context,
    requests: Vec<Request>,
    outputs: Vec<Output>,
}
pub(crate) fn validate_requests(context: Context, requests: &[Request]) -> Result<(), Error> {
    if !matches!(requests.len(), 2 | 4 | 8)
        || context.query == [0; 32]
        || context.setup == [0; 32]
        || requests
            .iter()
            .enumerate()
            .any(|(i, r)| r.binding() != instance_binding(context, i, r.direction(), r.basis()))
    {
        return Err(Error::Statement);
    }
    Ok(())
}
impl Expected {
    pub fn new(
        context: Context,
        requests: Vec<Request>,
        outputs: Vec<Output>,
    ) -> Result<Self, Error> {
        validate_requests(context, &requests)?;
        validate_batch(&requests, &outputs).map_err(|_| Error::Statement)?;
        Ok(Self {
            context,
            requests,
            outputs,
        })
    }
    pub fn context(&self) -> Context {
        self.context
    }
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }
    pub(crate) fn component_count(&self) -> usize {
        self.requests.len() / 2
    }
    pub(crate) fn component_range(&self, ordinal: usize) -> Result<core::ops::Range<usize>, Error> {
        if ordinal >= self.component_count() {
            return Err(Error::Statement);
        }
        let start = ordinal.checked_mul(2).ok_or(Error::ResourceLimit)?;
        Ok(start..start + 2)
    }
    pub(crate) fn request_wire(&self) -> Vec<u8> {
        let mut bytes = b"DCS/NTT-BATCH/v2/complete-ordered-requests/".to_vec();
        bytes.extend(self.context.query);
        bytes.extend(self.context.setup);
        bytes.extend((self.requests.len() as u64).to_le_bytes());
        for (i, r) in self.requests.iter().enumerate() {
            let wire = r.encode();
            bytes.extend((i as u64).to_le_bytes());
            bytes.extend((wire.len() as u64).to_le_bytes());
            bytes.extend(wire);
        }
        bytes
    }
    pub(crate) fn output_wire(&self) -> Vec<u8> {
        let mut bytes = b"DCS/NTT-BATCH/v2/complete-ordered-outputs/".to_vec();
        bytes.extend((self.outputs.len() as u64).to_le_bytes());
        for (i, o) in self.outputs.iter().enumerate() {
            let wire = o.encode();
            bytes.extend((i as u64).to_le_bytes());
            bytes.extend((wire.len() as u64).to_le_bytes());
            bytes.extend(wire);
        }
        bytes
    }
}
