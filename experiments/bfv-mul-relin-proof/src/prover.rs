//! Prover evaluates encrypted public polynomials. No owner plaintext or fixture endpoints.
use crate::{
    Error, Expected, GraphClaims, NODES, NodeOutput, PreparedGraph, Result, graph, verifier,
};
use bfv_complete_relinearization::PreparedKey;
use fhe::bfv::Ciphertext;
use fhe_traits::DeserializeParametrized;
use graph::NodeRequest;
use sha2::{Digest, Sha256};

pub struct Prover {
    graph: PreparedGraph,
    next: usize,
    cancelled: bool,
}
impl Prover {
    pub fn new(expected: &Expected, key: &PreparedKey) -> Result<Self> {
        graph::require_key(expected, key)?;
        let parameters = graph::parameters(expected.provenance())?;
        let mut native = Vec::with_capacity(4);
        for ct in expected.provenance().ciphertexts() {
            let ct = Ciphertext::from_bytes(ct, &parameters).map_err(|_| Error::Statement)?;
            if ct.len() != 2 {
                return Err(Error::Statement);
            }
            for component in ct.iter() {
                native.push(Vec::<u64>::from(component));
            }
        }
        let mut claims = GraphClaims {
            native: native.try_into().map_err(|_| Error::Statement)?,
            nodes: Vec::with_capacity(NODES),
        };
        // First pass computes raw ciphertext-residue claims. Temporary bindings are
        // excluded from the graph identity; no proof or checked result exists yet.
        for node in 0..NODES {
            let r = graph::request(&claims, key, [1; 64], node)?;
            let out = match &r {
                NodeRequest::Ntt(r) => NodeOutput::Ntt(
                    bfv_ntt_circuit::evaluate_with_certificate(r)
                        .map_err(|_| Error::Proof)?
                        .output,
                ),
                NodeRequest::Scale(r) => NodeOutput::Scale(
                    bfv_scale_circuit::evaluate_with_certificate(r)
                        .map_err(|_| Error::Proof)?
                        .output,
                ),
                NodeRequest::Tensor(r) => NodeOutput::Tensor(
                    bfv_tensor_circuit::evaluate_with_certificate(r)
                        .map_err(|_| Error::Proof)?
                        .output,
                ),
                NodeRequest::Relin(r) => NodeOutput::Relin(
                    bfv_relinearization_circuit::evaluate_with_certificate(r)
                        .map_err(|_| Error::Proof)?
                        .output,
                ),
            };
            claims.nodes.push(out);
        }
        let identity = graph::identity(expected, &claims);
        // Canonical claim headers now bind the fixed graph. This only assembles
        // public mathematical statements; all proofs are produced below.
        for node in 0..NODES {
            let request = graph::request(&claims, key, identity, node)?;
            claims.nodes[node] = bind_claim(&request, &claims.nodes[node], node)?;
        }
        let graph = PreparedGraph::prepare(expected, key, claims)?;
        Ok(Self {
            graph,
            next: 0,
            cancelled: false,
        })
    }
    pub fn graph(&self) -> &PreparedGraph {
        &self.graph
    }
    pub fn progress(&self) -> usize {
        self.next
    }
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }
    pub fn prove_next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        let Some(node) = verifier::packet_node(self.next) else {
            return Ok(None);
        };
        let proof = if node == NODES {
            let generated = bfv_arithmetic_batch_proof::prove(
                self.graph.arithmetic.context(),
                self.graph.arithmetic.requests(),
            )
            .map_err(|_| Error::Proof)?;
            if generated
                .outputs
                .iter()
                .zip(self.graph.arithmetic.outputs())
                .any(|(a, b)| a.encode() != b.encode())
            {
                return Err(Error::Statement);
            }
            generated.frame
        } else {
            match (&self.graph.requests[node], &self.graph.claims.nodes[node]) {
                (NodeRequest::Ntt(r), NodeOutput::Ntt(o)) => {
                    let g = bfv_ntt_witness_proof::prove(r).map_err(|_| Error::Proof)?;
                    if g.output.encode() != o.encode() {
                        return Err(Error::Statement);
                    }
                    g.proof
                }
                (NodeRequest::Relin(r), NodeOutput::Relin(o)) => {
                    let g = bfv_relinearization_multilinear_proof::prove(r)
                        .map_err(|_| Error::Proof)?;
                    if g.output.encode() != o.encode() {
                        return Err(Error::Statement);
                    }
                    g.proof
                }
                _ => return Err(Error::Statement),
            }
        };
        let out = verifier::encode_record(self.graph.identity, self.next, node, &proof)?;
        self.next += 1;
        Ok(Some(out))
    }
}
fn bind_claim(r: &NodeRequest, o: &NodeOutput, node: usize) -> Result<NodeOutput> {
    let mut wire = o.encode();
    let (binding, request, offset) = match r {
        NodeRequest::Ntt(r) => (r.binding(), r.encode(), 80),
        NodeRequest::Scale(r) => (r.binding(), r.encode(), 80),
        NodeRequest::Tensor(r) => (r.binding(), r.encode(), 80),
        NodeRequest::Relin(r) => (r.binding(), r.encode(), 112),
    };
    wire[40..72].copy_from_slice(&binding);
    wire[offset..offset + 32].copy_from_slice(&Sha256::digest(request));
    NodeOutput::decode(node, &wire)
}
