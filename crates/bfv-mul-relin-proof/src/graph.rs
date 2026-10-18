//! Composition-owned identity, proof labels and arithmetic17 grouping.
//! All fixed vector routing and endpoint bridges belong to the Core circuit.
use crate::{DEGREE, Error, GraphClaims, NODES, NodeOutput, Provenance, Result, profile};
use bfv_ciphertext_wire::SecondComponent;
pub(crate) use bfv_mul_relin_circuit::{NodeRequest, require_header};
use bfv_relinearization_key_source::PreparedKey;
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use fhe_traits::Serialize;
use sha2::{Digest, Sha512};
use std::sync::Arc;

/// Independently pinned complete original inputs, provenance and proposed result.
pub struct Expected {
    pub(crate) provenance: Provenance,
    pub(crate) output: Vec<u8>,
}
impl Expected {
    pub fn new(provenance: Provenance, output: Vec<u8>) -> Result<Self> {
        let v = bfv_ciphertext_wire::parse(&output).map_err(|_| Error::Statement)?;
        let SecondComponent::Stored(c1) = v.second() else {
            return Err(Error::Statement);
        };
        // Upstream level0/logbase0 key switching explicitly enables public variable-time rows.
        if !v.c0().allow_variable_time() || !c1.allow_variable_time() {
            return Err(Error::Statement);
        }
        Ok(Self { provenance, output })
    }
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
    pub fn output_ciphertext(&self) -> &[u8] {
        &self.output
    }
}
/// All fixed edges/header bindings checked; every numeric claim is still unverified.
pub struct PreparedGraph {
    pub(crate) claims: GraphClaims,
    pub(crate) requests: Vec<NodeRequest>,
    pub(crate) identity: [u8; 64],
    pub(crate) arithmetic: bfv_arithmetic_batch_proof::Expected,
}
impl PreparedGraph {
    pub fn prepare(expected: &Expected, key: &PreparedKey, claims: GraphClaims) -> Result<Self> {
        require_key(expected, key)?;
        let ciphertexts = expected.provenance.ciphertexts();
        bfv_mul_relin_circuit::check_ciphertext_bridges(
            expected
                .provenance
                .setup()
                .relinearization_material()
                .map_err(|_| Error::Statement)?
                .parameters(),
            ciphertexts.each_ref().map(Vec::as_slice),
            &expected.output,
            &claims,
        )?;
        let identity = identity(expected, &claims);
        let mut requests = Vec::with_capacity(NODES);
        for n in 0..NODES {
            let request = request(&claims, key, identity, n)?;
            require_header(&request, &claims.nodes()[n])?;
            requests.push(request);
        }
        let indices = arithmetic_indices();
        let rs = indices
            .iter()
            .map(|&n| match &requests[n] {
                NodeRequest::Scale(r) => Ok(bfv_arithmetic_batch_proof::RelationRequest::Scale(
                    r.clone(),
                )),
                NodeRequest::Tensor(r) => Ok(bfv_arithmetic_batch_proof::RelationRequest::Tensor(
                    r.clone(),
                )),
                _ => Err(Error::Statement),
            })
            .collect::<Result<Vec<_>>>()?;
        let os = indices
            .iter()
            .map(|&n| match &claims.nodes()[n] {
                NodeOutput::Scale(r) => {
                    Ok(bfv_arithmetic_batch_proof::RelationOutput::Scale(r.clone()))
                }
                NodeOutput::Tensor(r) => Ok(bfv_arithmetic_batch_proof::RelationOutput::Tensor(
                    r.clone(),
                )),
                _ => Err(Error::Statement),
            })
            .collect::<Result<Vec<_>>>()?;
        let arithmetic = bfv_arithmetic_batch_proof::Expected::new(
            arithmetic_context(identity, key.keyset_id()),
            rs,
            os,
        )
        .map_err(|_| Error::Statement)?;
        Ok(Self {
            claims,
            requests,
            identity,
            arithmetic,
        })
    }
    pub fn identity(&self) -> [u8; 64] {
        self.identity
    }
    pub fn claims(&self) -> &GraphClaims {
        &self.claims
    }
}
pub(crate) fn require_key(expected: &Expected, key: &PreparedKey) -> Result<()> {
    if key.keyset_id() != expected.provenance.anchor().full_setup_id()
        || key.original_setup_digest() != expected.provenance.original_setup_digest()
    {
        return Err(Error::Statement);
    }
    Ok(())
}
pub(crate) fn identity(expected: &Expected, claims: &GraphClaims) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/BFV-MUL-RELIN/v1/whole-graph-raw-claims/");
    h.update(crate::profile_digest());
    expected.provenance.feed_identity(&mut h);
    h.update((expected.output.len() as u64).to_le_bytes());
    h.update(&expected.output);
    claims.feed_identity(&mut h);
    h.finalize().into()
}
pub(crate) fn arithmetic_indices() -> Vec<usize> {
    bfv_mul_relin_circuit::ARITHMETIC_NODES.to_vec()
}
pub(crate) fn arithmetic_context(
    identity: [u8; 64],
    setup: [u8; 32],
) -> bfv_arithmetic_batch_proof::Context {
    bfv_arithmetic_batch_proof::Context {
        query: profile::binding(identity, NODES),
        setup,
    }
}
pub(crate) fn node_binding(identity: [u8; 64], setup: [u8; 32], n: usize) -> Result<[u8; 32]> {
    if let Some(i) = arithmetic_indices().iter().position(|&x| x == n) {
        bfv_arithmetic_batch_proof::instance_binding(arithmetic_context(identity, setup), i)
            .map_err(|_| Error::Statement)
    } else {
        Ok(profile::binding(identity, n))
    }
}
pub(crate) fn request(
    c: &GraphClaims,
    key: &PreparedKey,
    g: [u8; 64],
    n: usize,
) -> Result<NodeRequest> {
    let binding = node_binding(g, key.keyset_id(), n)?;
    Ok(bfv_mul_relin_circuit::derive_request(
        n,
        c.native_components(),
        &c.nodes()[..n],
        key,
        binding,
    )?)
}
pub(crate) fn parameters(p: &Provenance) -> Result<Arc<BfvParameters>> {
    let parameters = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_moduli(&bfv_fixed_geometry::MODULI)
        .set_plaintext_modulus(bfv_fixed_geometry::PLAINTEXT)
        .set_variance(10)
        .build_arc()
        .map_err(|_| Error::Statement)?;
    if parameters.to_bytes()
        != p.setup()
            .relinearization_material()
            .map_err(|_| Error::Statement)?
            .parameters()
    {
        return Err(Error::Statement);
    }
    Ok(parameters)
}
