//! Pure fixed predecessor routing and canonical endpoints. No evaluator in preparation.
use crate::{DEGREE, Error, GraphClaims, NODES, NodeOutput, Provenance, Result, profile};
use bfv_ciphertext_wire::{SecondComponent, StoredPowerBasis};
use bfv_complete_relinearization::PreparedKey;
use bfv_ntt_circuit as ntt;
use bfv_relinearization_circuit as relin;
use bfv_scale_circuit as scale;
use bfv_tensor_circuit as tensor;
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::Serialize;
use sha2::{Digest, Sha256, Sha512};
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
pub(crate) enum NodeRequest {
    Ntt(ntt::Request),
    Scale(scale::Request),
    Tensor(tensor::Request),
    Relin(relin::Request),
}
impl NodeRequest {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ntt(x) => x.encode(),
            Self::Scale(x) => x.encode(),
            Self::Tensor(x) => x.encode(),
            Self::Relin(x) => x.encode(),
        }
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
        check_bridges(expected, &claims)?;
        let identity = identity(expected, &claims);
        let mut requests = Vec::with_capacity(NODES);
        for n in 0..NODES {
            let request = request(&claims, key, identity, n)?;
            require_header(&request, &claims.nodes[n])?;
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
            .map(|&n| match &claims.nodes[n] {
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
    (20..24).chain(44..54).chain(84..87).collect()
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
fn node_binding(identity: [u8; 64], setup: [u8; 32], n: usize) -> Result<[u8; 32]> {
    if let Some(i) = arithmetic_indices().iter().position(|&x| x == n) {
        bfv_arithmetic_batch_proof::instance_binding(arithmetic_context(identity, setup), i)
            .map_err(|_| Error::Statement)
    } else {
        Ok(profile::binding(identity, n))
    }
}
fn row(v: &[u64], i: usize) -> Result<&[u64]> {
    v.get(i * DEGREE..(i + 1) * DEGREE).ok_or(Error::Statement)
}
fn values(c: &GraphClaims, n: usize) -> Result<&[u64]> {
    Ok(c.nodes.get(n).ok_or(Error::Statement)?.coefficients())
}
fn joined(c: &GraphClaims, range: core::ops::Range<usize>) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for n in range {
        out.extend(values(c, n)?);
    }
    Ok(out)
}
pub(crate) fn request(
    c: &GraphClaims,
    key: &PreparedKey,
    g: [u8; 64],
    n: usize,
) -> Result<NodeRequest> {
    let bind = node_binding(g, key.keyset_id(), n)?;
    let (kind, b) = crate::claims::metadata(n)?;
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
        1 => ntt_request(ntt::Direction::Inverse, row(&c.native[n / 5], n % 5)?),
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
                    input.extend(row(&c.native[component], usize::from(b))?);
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
pub(crate) fn require_header(r: &NodeRequest, o: &NodeOutput) -> Result<()> {
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
fn same_pb(poly: StoredPowerBasis<'_>, basis: usize, claimed: &[u64]) -> Result<()> {
    if poly
        .row(basis)
        .ok_or(Error::Statement)?
        .eq(claimed.iter().copied())
    {
        Ok(())
    } else {
        Err(Error::Statement)
    }
}
fn check_bridges(e: &Expected, c: &GraphClaims) -> Result<()> {
    for (operand, wire) in e.provenance.ciphertexts().iter().enumerate() {
        let parsed = bfv_ciphertext_wire::parse(wire).map_err(|_| Error::Statement)?;
        for b in 0..5 {
            same_pb(parsed.c0(), b, values(c, operand * 10 + b)?)?;
        }
        match parsed.second() {
            SecondComponent::Stored(poly) => {
                for b in 0..5 {
                    same_pb(poly, b, values(c, operand * 10 + 5 + b)?)?;
                }
            }
            SecondComponent::Seed(seed) => {
                let p = parameters(&e.provenance)?;
                let expanded = Poly::random_from_seed(
                    p.context_at_level(0).map_err(|_| Error::Statement)?,
                    Representation::Ntt,
                    *seed,
                );
                if Vec::<u64>::from(&expanded) != c.native[2 * operand + 1] {
                    return Err(Error::Statement);
                }
            }
        }
    }
    let out = bfv_ciphertext_wire::parse(&e.output).map_err(|_| Error::Statement)?;
    let SecondComponent::Stored(c1) = out.second() else {
        return Err(Error::Statement);
    };
    for (component, poly) in [out.c0(), c1].into_iter().enumerate() {
        for b in 0..5 {
            same_pb(poly, b, values(c, 124 + 5 * component + b)?)?;
        }
    }
    Ok(())
}
