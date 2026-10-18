//! Fixed full-vector predecessor assembly. This module runs no arithmetic evaluator.
use crate::{DEGREE, Error, NODES, NodeMetadata, NodeOutput, Result, node_metadata};
use bfv_ntt_circuit as ntt;
use bfv_relinearization_circuit as relin;
use bfv_relinearization_key_source::PreparedKey;
use bfv_scale_circuit as scale;
use bfv_tensor_circuit as tensor;
use sha2::{Digest, Sha256};

/// One ordinary primitive mathematical request, with no proof/verification grant.
pub enum NodeRequest {
    Ntt(ntt::Request),
    Scale(scale::Request),
    Tensor(tensor::Request),
    Relin(relin::Request),
}
impl NodeRequest {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ntt(x) => x.encode(),
            Self::Scale(x) => x.encode(),
            Self::Tensor(x) => x.encode(),
            Self::Relin(x) => x.encode(),
        }
    }
}
struct RoutingInputs<'a> {
    native: [&'a [u64]; 4],
    nodes: &'a [NodeOutput],
}
fn row(v: &[u64], i: usize) -> Result<&[u64]> {
    v.get(i * DEGREE..(i + 1) * DEGREE).ok_or(Error::Statement)
}
fn values<'a>(c: &RoutingInputs<'a>, n: usize) -> Result<&'a [u64]> {
    Ok(c.nodes.get(n).ok_or(Error::Statement)?.coefficients())
}
fn joined(c: &RoutingInputs<'_>, range: core::ops::Range<usize>) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for n in range {
        out.extend(values(c, n)?);
    }
    Ok(out)
}
/// Assemble exactly the next fixed request from borrowed canonical predecessors.
/// The caller derives binding32 from its complete proof context, including any
/// arithmetic-specific labels. This function neither selects nor verifies it.
pub fn derive_request(
    n: usize,
    native: [&[u64]; 4],
    prior: &[NodeOutput],
    key: &PreparedKey,
    bind: [u8; 32],
) -> Result<NodeRequest> {
    if n >= NODES || prior.len() != n {
        return Err(Error::Statement);
    }
    crate::claims::validate_native(native)?;
    for (node, output) in prior.iter().enumerate() {
        output.require_node(node)?;
    }
    let c = &RoutingInputs {
        native,
        nodes: prior,
    };
    let NodeMetadata { kind, basis: b } = node_metadata(n)?;
    let ntt_request = |direction, input: &[u64]| {
        ntt::decode_request(
            &ntt::encode_request(
                direction,
                ntt::Basis::new(b).map_err(|_| Error::Statement)?,
                bind,
                input,
            )
            .map_err(|_| Error::Statement)?,
        )
        .map(NodeRequest::Ntt)
        .map_err(|_| Error::Statement)
    };
    match kind {
        1 => ntt_request(ntt::Direction::Inverse, row(c.native[n / 5], n % 5)?),
        2 => {
            let input = joined(c, 5 * (n - 20)..5 * (n - 20) + 5)?;
            scale_request(scale::Role::Extend5To10, bind, &input)
        }
        3 => ntt_request(
            ntt::Direction::Forward,
            row(values(c, 20 + (n - 24) / 5)?, usize::from(b))?,
        ),
        4 => {
            let mut input = Vec::with_capacity(4 * DEGREE);
            for component in 0..4 {
                if b < 5 {
                    input.extend(row(c.native[component], usize::from(b))?);
                } else {
                    input.extend(values(c, 24 + component * 5 + usize::from(b) - 5)?);
                }
            }
            Ok(NodeRequest::Tensor(
                tensor::decode_request(
                    &tensor::encode_request(
                        tensor::Basis::new(b).map_err(|_| Error::Statement)?,
                        bind,
                        &input,
                    )
                    .map_err(|_| Error::Statement)?,
                )
                .map_err(|_| Error::Statement)?,
            ))
        }
        5 => ntt_request(
            ntt::Direction::Inverse,
            row(values(c, 44 + usize::from(b))?, (n - 54) / 10)?,
        ),
        6 => {
            let input = joined(c, 54 + 10 * (n - 84)..64 + 10 * (n - 84))?;
            scale_request(scale::Role::Scale10To5, bind, &input)
        }
        7 => ntt_request(
            ntt::Direction::Forward,
            row(values(c, 84 + (n - 87) / 5)?, usize::from(b))?,
        ),
        8 => Ok(NodeRequest::Relin(
            relin::routing::embed_request(bind, key.keyset_id(), values(c, 86)?)
                .map_err(|_| Error::Statement)?,
        )),
        9 => ntt_request(
            ntt::Direction::Forward,
            relin::routing::digit_row(values(c, 97)?, (n - 98) / 5, usize::from(b))
                .map_err(|_| Error::Statement)?,
        ),
        10 => {
            let originals = [joined(c, 87..92)?, joined(c, 92..97)?];
            let digits = joined(c, 98..123)?;
            let keys = core::array::from_fn(|component| {
                core::array::from_fn(|source| {
                    key.component(component, source)
                        .expect("fixed prepared key rows")
                })
            });
            Ok(NodeRequest::Relin(
                relin::routing::mac_request(
                    bind,
                    key.keyset_id(),
                    originals.each_ref().map(Vec::as_slice),
                    &digits,
                    keys,
                )
                .map_err(|_| Error::Statement)?,
            ))
        }
        11 => ntt_request(
            ntt::Direction::Inverse,
            row(values(c, 123)?, 2 * usize::from(b) + (n - 124) / 5)?,
        ),
        _ => Err(Error::Statement),
    }
}
fn scale_request(role: scale::Role, binding: [u8; 32], input: &[u64]) -> Result<NodeRequest> {
    Ok(NodeRequest::Scale(
        scale::decode_request(
            &scale::encode_request(role, binding, input).map_err(|_| Error::Statement)?,
        )
        .map_err(|_| Error::Statement)?,
    ))
}
/// Check complete primitive header association, not arithmetic or proof validity.
pub fn require_header(r: &NodeRequest, o: &NodeOutput) -> Result<()> {
    let same_role = match (r, o) {
        (NodeRequest::Ntt(r), NodeOutput::Ntt(o)) => {
            r.direction() == o.direction() && r.basis() == o.basis()
        }
        (NodeRequest::Scale(r), NodeOutput::Scale(o)) => r.role() == o.role(),
        (NodeRequest::Tensor(r), NodeOutput::Tensor(o)) => r.basis() == o.basis(),
        (NodeRequest::Relin(r), NodeOutput::Relin(o)) => r.role() == o.role(),
        _ => false,
    };
    if !same_role {
        return Err(Error::Statement);
    }
    let wire = o.encode();
    let request = r.encode();
    let (binding, keyset) = match r {
        NodeRequest::Ntt(r) => (r.binding(), None),
        NodeRequest::Scale(r) => (r.binding(), None),
        NodeRequest::Tensor(r) => (r.binding(), None),
        NodeRequest::Relin(r) => (r.binding(), Some(r.keyset_context())),
    };
    let digest_offset = if let Some(keyset) = keyset {
        if wire[72..104] != keyset {
            return Err(Error::Statement);
        }
        112
    } else {
        80
    };
    if wire[40..72] != binding
        || wire[digest_offset..digest_offset + 32] != Sha256::digest(request)[..]
    {
        return Err(Error::Statement);
    }
    Ok(())
}
