//! Immutable full public statement. Context labels do not prove setup authority.
use crate::{Error, RELATIONS, backend};
use bfv_scale_circuit as scale;
use bfv_tensor_circuit as tensor;
use sha2::{Digest, Sha256};
const HEADER: usize = 144;
/// Independently supplied complete query/setup identity, never inferred from a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub query: [u8; 32],
    pub setup: [u8; 32],
}
#[derive(Clone)]
pub enum RelationRequest {
    Scale(scale::Request),
    Tensor(tensor::Request),
}
impl RelationRequest {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Scale(r) => r.encode(),
            Self::Tensor(r) => r.encode(),
        }
    }
    pub fn binding(&self) -> [u8; 32] {
        match self {
            Self::Scale(r) => r.binding(),
            Self::Tensor(r) => r.binding(),
        }
    }
}
#[derive(Clone)]
pub enum RelationOutput {
    Scale(scale::Output),
    Tensor(tensor::Output),
}
impl RelationOutput {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Scale(o) => o.encode(),
            Self::Tensor(o) => o.encode(),
        }
    }
}
pub(crate) fn role(index: usize) -> Option<(u8, u8)> {
    match index {
        0..=3 => Some((1, 255)),
        4..=13 => Some((2, (index - 4) as u8)),
        14..=16 => Some((3, 255)),
        _ => None,
    }
}
fn sizes(index: usize) -> (usize, usize) {
    match role(index).unwrap().0 {
        1 => (
            scale::Role::Extend5To10.request_bytes(),
            scale::Role::Extend5To10.output_bytes(),
        ),
        2 => {
            let b = tensor::Basis::new((index - 4) as u8).unwrap();
            (b.request_bytes(), b.output_bytes())
        }
        _ => (
            scale::Role::Scale10To5.request_bytes(),
            scale::Role::Scale10To5.output_bytes(),
        ),
    }
}
pub(crate) fn namespace(context: Context, ordinal: usize) -> limb_range_air::Namespace {
    let mut h = Sha256::new();
    h.update(b"DCS/ARITHMETIC-BATCH/v2/phase-range-namespace/");
    h.update(context.query);
    h.update(context.setup);
    h.update((ordinal as u64).to_le_bytes());
    limb_range_air::Namespace::new(h.finalize().into())
}
pub(crate) fn component_range(ordinal: usize) -> Result<core::ops::Range<usize>, Error> {
    match ordinal {
        0 => Ok(0..4),
        1 => Ok(4..14),
        2 => Ok(14..17),
        _ => Err(Error::Statement),
    }
}
/// Every position has a distinct fixed role/basis binding, including repeated scalers.
pub fn instance_binding(context: Context, index: usize) -> Result<[u8; 32], Error> {
    let (tag, basis) = role(index).ok_or(Error::Statement)?;
    let mut h = Sha256::new();
    h.update(b"DCS/ARITHMETIC-BATCH/v1/instance/");
    h.update(context.query);
    h.update(context.setup);
    h.update((index as u32).to_le_bytes());
    h.update([tag, basis]);
    Ok(h.finalize().into())
}
pub(crate) fn validate_requests(
    context: Context,
    requests: &[RelationRequest],
) -> Result<(), Error> {
    if context.query == [0; 32] || context.setup == [0; 32] || requests.len() != RELATIONS {
        return Err(Error::Statement);
    }
    for (i, r) in requests.iter().enumerate() {
        let valid = match (role(i).unwrap(), r) {
            ((1, _), RelationRequest::Scale(r)) => r.role() == scale::Role::Extend5To10,
            ((2, b), RelationRequest::Tensor(r)) => r.basis().index() == b,
            ((3, _), RelationRequest::Scale(r)) => r.role() == scale::Role::Scale10To5,
            _ => false,
        };
        if !valid || r.binding() != instance_binding(context, i)? {
            return Err(Error::Statement);
        }
    }
    Ok(())
}
#[derive(Clone)]
pub struct Expected {
    context: Context,
    requests: Vec<RelationRequest>,
    outputs: Vec<RelationOutput>,
}
impl Expected {
    /// Checks full canonical statement identity only, never arithmetic or an Aux.
    pub fn new(
        context: Context,
        requests: Vec<RelationRequest>,
        outputs: Vec<RelationOutput>,
    ) -> Result<Self, Error> {
        validate_requests(context, &requests)?;
        if outputs.len() != RELATIONS {
            return Err(Error::Statement);
        }
        for (r, o) in requests.iter().zip(&outputs) {
            let same = match (r, o) {
                (RelationRequest::Scale(r), RelationOutput::Scale(o)) => {
                    r.role() == o.role()
                        && r.binding() == o.binding()
                        && (r.role() != scale::Role::Extend5To10
                            || &o.coefficients()[..5 * scale::DEGREE] == r.input())
                }
                (RelationRequest::Tensor(r), RelationOutput::Tensor(o)) => {
                    r.basis() == o.basis() && r.binding() == o.binding()
                }
                _ => false,
            };
            if !same || o.encode()[80..112] != Sha256::digest(r.encode())[..] {
                return Err(Error::Statement);
            }
        }
        Ok(Self {
            context,
            requests,
            outputs,
        })
    }
    pub fn context(&self) -> Context {
        self.context
    }
    pub fn requests(&self) -> &[RelationRequest] {
        &self.requests
    }
    pub fn outputs(&self) -> &[RelationOutput] {
        &self.outputs
    }
    pub fn request_wire(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(b"BFVABRQ2");
        b.extend(backend::profile(self.context));
        b.extend(self.context.query);
        b.extend(self.context.setup);
        b.extend((RELATIONS as u32).to_le_bytes());
        b.extend([0; 4]);
        for (i, r) in self.requests.iter().enumerate() {
            append(&mut b, i, &r.encode());
        }
        b
    }
    pub fn output_wire(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(b"BFVABRO2");
        b.extend(backend::profile(self.context));
        b.extend(backend::digest(&self.request_wire()));
        b.extend((RELATIONS as u32).to_le_bytes());
        b.extend([0; 4]);
        for (i, o) in self.outputs.iter().enumerate() {
            append(&mut b, i, &o.encode());
        }
        b
    }
    /// Exact fixed envelopes, lengths and tags are checked before child allocations.
    pub fn from_wires(request: &[u8], output: &[u8]) -> Result<Self, Error> {
        let request_size = HEADER + (0..RELATIONS).map(|i| 8 + sizes(i).0).sum::<usize>();
        let output_size = HEADER + (0..RELATIONS).map(|i| 8 + sizes(i).1).sum::<usize>();
        if request.len() != request_size
            || output.len() != output_size
            || &request[..8] != b"BFVABRQ2"
            || &output[..8] != b"BFVABRO2"
        {
            return Err(Error::Statement);
        }
        let context = Context {
            query: request[72..104].try_into().unwrap(),
            setup: request[104..136].try_into().unwrap(),
        };
        if context.query == [0; 32]
            || context.setup == [0; 32]
            || request[8..72] != backend::profile(context)
            || output[8..72] != backend::profile(context)
            || output[72..136] != backend::digest(request)
            || request[136..144] != suffix()
            || output[136..144] != suffix()
        {
            return Err(Error::Statement);
        }
        let mut r_at = HEADER;
        let mut o_at = HEADER;
        let mut requests = Vec::with_capacity(RELATIONS);
        let mut outputs = Vec::with_capacity(RELATIONS);
        for i in 0..RELATIONS {
            let (rs, os) = sizes(i);
            let rb = take(request, &mut r_at, i, rs)?;
            let ob = take(output, &mut o_at, i, os)?;
            if role(i).unwrap().0 == 2 {
                requests.push(RelationRequest::Tensor(
                    tensor::decode_request(rb).map_err(|_| Error::Statement)?,
                ));
                outputs.push(RelationOutput::Tensor(
                    tensor::decode_output(ob).map_err(|_| Error::Statement)?,
                ));
            } else {
                requests.push(RelationRequest::Scale(
                    scale::decode_request(rb).map_err(|_| Error::Statement)?,
                ));
                outputs.push(RelationOutput::Scale(
                    scale::decode_output(ob).map_err(|_| Error::Statement)?,
                ));
            }
        }
        let expected = Self::new(context, requests, outputs)?;
        if expected.request_wire() != request || expected.output_wire() != output {
            return Err(Error::Statement);
        }
        Ok(expected)
    }
}
fn suffix() -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&(RELATIONS as u32).to_le_bytes());
    b
}
fn prefix(index: usize, length: usize) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&(length as u32).to_le_bytes());
    let (tag, basis) = role(index).unwrap();
    b[4] = tag;
    b[5] = basis;
    b
}
fn append(out: &mut Vec<u8>, index: usize, wire: &[u8]) {
    out.extend(prefix(index, wire.len()));
    out.extend(wire);
}
fn take<'a>(bytes: &'a [u8], at: &mut usize, index: usize, size: usize) -> Result<&'a [u8], Error> {
    if bytes[*at..*at + 8] != prefix(index, size) {
        return Err(Error::Statement);
    }
    *at += 8;
    let result = &bytes[*at..*at + size];
    *at += size;
    Ok(result)
}
