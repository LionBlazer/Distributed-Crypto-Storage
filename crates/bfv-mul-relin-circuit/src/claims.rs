//! Bounded proposed public ciphertext residue vectors, never verified endpoints.
use crate::{DEGREE, Error, MAX_CLAIMS_BYTES, NODES, Result};
use bfv_ntt_circuit as ntt;
use bfv_relinearization_circuit as relin;
use bfv_scale_circuit as scale;
use bfv_tensor_circuit as tensor;
use sha2::{Digest, Sha512};
const HEADER: usize = 96;
/// Fixed BFVMRG01 kind/basis tags. These describe mathematical positions only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeMetadata {
    pub kind: u8,
    /// Original Q/P basis, or255 for a whole-vector relation.
    pub basis: u8,
}
#[derive(Clone)]
pub enum NodeOutput {
    Ntt(ntt::Output),
    Scale(scale::Output),
    Tensor(tensor::Output),
    Relin(relin::Output),
}
impl NodeOutput {
    pub fn coefficients(&self) -> &[u64] {
        match self {
            Self::Ntt(x) => x.coefficients(),
            Self::Scale(x) => x.coefficients(),
            Self::Tensor(x) => x.coefficients(),
            Self::Relin(x) => x.coefficients(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ntt(x) => x.encode(),
            Self::Scale(x) => x.encode(),
            Self::Tensor(x) => x.encode(),
            Self::Relin(x) => x.encode(),
        }
    }
    pub fn decode_for_node(node: usize, wire: &[u8]) -> Result<Self> {
        let kind = node_metadata(node)?.kind;
        let out = match kind {
            1 | 3 | 5 | 7 | 9 | 11 => {
                Self::Ntt(ntt::decode_output(wire).map_err(|_| Error::Statement)?)
            }
            2 | 6 => Self::Scale(scale::decode_output(wire).map_err(|_| Error::Statement)?),
            4 => Self::Tensor(tensor::decode_output(wire).map_err(|_| Error::Statement)?),
            8 | 10 => Self::Relin(relin::decode_output(wire).map_err(|_| Error::Statement)?),
            _ => return Err(Error::Statement),
        };
        out.require_node(node)?;
        Ok(out)
    }
    pub(crate) fn require_node(&self, node: usize) -> Result<()> {
        let NodeMetadata { kind, basis: b } = node_metadata(node)?;
        let valid = match (kind, self) {
            (1 | 5 | 11, Self::Ntt(o)) => {
                o.direction() == ntt::Direction::Inverse && o.basis().index() == b
            }
            (3 | 7 | 9, Self::Ntt(o)) => {
                o.direction() == ntt::Direction::Forward && o.basis().index() == b
            }
            (2, Self::Scale(o)) => o.role() == scale::Role::Extend5To10,
            (6, Self::Scale(o)) => o.role() == scale::Role::Scale10To5,
            (4, Self::Tensor(o)) => o.basis().index() == b,
            (8, Self::Relin(o)) => o.role() == relin::Role::Embed,
            (10, Self::Relin(o)) => o.role() == relin::Role::AccumulateAndAdd,
            _ => false,
        };
        if valid { Ok(()) } else { Err(Error::Statement) }
    }
}
pub fn node_metadata(node: usize) -> Result<NodeMetadata> {
    let (kind, basis) = match node {
        0..=19 => (1, (node % 5) as u8),
        20..=23 => (2, 255),
        24..=43 => (3, (5 + (node - 24) % 5) as u8),
        44..=53 => (4, (node - 44) as u8),
        54..=83 => (5, ((node - 54) % 10) as u8),
        84..=86 => (6, 255),
        87..=96 => (7, ((node - 87) % 5) as u8),
        97 => (8, 255),
        98..=122 => (9, ((node - 98) % 5) as u8),
        123 => (10, 255),
        124..=133 => (11, ((node - 124) % 5) as u8),
        _ => return Err(Error::Statement),
    };
    Ok(NodeMetadata { kind, basis })
}
fn output_bytes(node: usize) -> usize {
    let k = node_metadata(node).unwrap().kind;
    match k {
        2 => scale::Role::Extend5To10.output_bytes(),
        6 => scale::Role::Scale10To5.output_bytes(),
        4 => tensor::Basis::new((node - 44) as u8)
            .unwrap()
            .output_bytes(),
        8 => relin::Role::Embed.output_bytes(),
        10 => relin::Role::AccumulateAndAdd.output_bytes(),
        _ => ntt::Direction::Forward.output_bytes(),
    }
}
fn prefix(node: usize) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&(output_bytes(node) as u32).to_le_bytes());
    b[4..6].copy_from_slice(&(node as u16).to_le_bytes());
    let metadata = node_metadata(node).unwrap();
    b[6] = metadata.kind;
    b[7] = metadata.basis;
    b
}
/// All 134 fixed typed claims and twenty native input rows. No proof authority.
#[derive(Clone)]
pub struct GraphClaims {
    native: [Vec<u64>; 4],
    nodes: Vec<NodeOutput>,
}
pub(crate) fn validate_native(native: [&[u64]; 4]) -> Result<()> {
    if native.iter().any(|v| {
        v.len() != 5 * DEGREE
            || v.iter()
                .enumerate()
                .any(|(i, x)| *x >= bfv_fixed_geometry::MODULI[i / DEGREE])
    }) {
        Err(Error::Statement)
    } else {
        Ok(())
    }
}
impl GraphClaims {
    pub fn new(native: [Vec<u64>; 4], nodes: Vec<NodeOutput>) -> Result<Self> {
        if nodes.len() != NODES {
            return Err(Error::Statement);
        }
        validate_native(native.each_ref().map(Vec::as_slice))?;
        for (n, o) in nodes.iter().enumerate() {
            o.require_node(n)?;
        }
        Ok(Self { native, nodes })
    }
    pub fn node(&self, n: usize) -> Option<&NodeOutput> {
        self.nodes.get(n)
    }
    pub fn native_component(&self, n: usize) -> Option<&[u64]> {
        self.native.get(n).map(Vec::as_slice)
    }
    pub fn native_components(&self) -> [&[u64]; 4] {
        self.native.each_ref().map(Vec::as_slice)
    }
    pub fn nodes(&self) -> &[NodeOutput] {
        &self.nodes
    }
    /// Consume public proposed vectors for producer rebinding without mutation APIs.
    pub fn into_parts(self) -> ([Vec<u64>; 4], Vec<NodeOutput>) {
        (self.native, self.nodes)
    }
    /// The caller independently selects the proof profile. It is an ordinary
    /// unverified label; this codec does not recognize or authorize a backend.
    pub fn encode(&self, expected_profile: [u8; 64]) -> Vec<u8> {
        let mut b = vec![0; HEADER];
        b[..8].copy_from_slice(b"BFVMRG01");
        b[8..72].copy_from_slice(&expected_profile);
        b[72..76].copy_from_slice(&(NODES as u32).to_le_bytes());
        b[76..80].copy_from_slice(&(20 * DEGREE as u32).to_le_bytes());
        for row in &self.native {
            for x in row {
                b.extend(x.to_le_bytes());
            }
        }
        for (n, o) in self.nodes.iter().enumerate() {
            b.extend(prefix(n));
            b.extend(o.encode());
        }
        b
    }
    pub fn decode(expected_profile: [u8; 64], bytes: &[u8]) -> Result<Self> {
        let size =
            HEADER + 20 * DEGREE * 8 + (0..NODES).map(|n| 8 + output_bytes(n)).sum::<usize>();
        if bytes.len() > MAX_CLAIMS_BYTES {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() != size
            || bytes[..8] != *b"BFVMRG01"
            || bytes[8..72] != expected_profile
            || bytes[72..76] != (NODES as u32).to_le_bytes()
            || bytes[76..80] != (20 * DEGREE as u32).to_le_bytes()
            || bytes[80..HEADER] != [0; 16]
        {
            return Err(Error::Statement);
        }
        let mut at = HEADER;
        let native = core::array::from_fn(|_| {
            let mut out = Vec::with_capacity(5 * DEGREE);
            for _ in 0..5 * DEGREE {
                out.push(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()));
                at += 8;
            }
            out
        });
        let mut nodes = Vec::with_capacity(NODES);
        for n in 0..NODES {
            if bytes[at..at + 8] != prefix(n) {
                return Err(Error::Statement);
            }
            at += 8;
            let end = at + output_bytes(n);
            nodes.push(NodeOutput::decode_for_node(n, &bytes[at..end])?);
            at = end;
        }
        Self::new(native, nodes)
    }
    /// Append the unchanged complete raw-vector sequence, excluding derived
    /// headers. The consumer owns its domain, full provenance/profile and final
    /// graph identity; neither this feed nor its labels verify any proof.
    pub fn feed_identity(&self, h: &mut Sha512) {
        for v in &self.native {
            for x in v {
                h.update(x.to_le_bytes());
            }
        }
        for (n, o) in self.nodes.iter().enumerate() {
            h.update((n as u64).to_le_bytes());
            let metadata = node_metadata(n).unwrap();
            h.update([metadata.kind, metadata.basis]);
            for x in o.coefficients() {
                h.update(x.to_le_bytes());
            }
        }
    }
}
