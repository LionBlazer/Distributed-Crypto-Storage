//! Owner-only pre-proving witness arithmetic. Consumes secrets; NEVER a peer verifier.
//! No proof, key authentication, Source/SQL admission or assessed security is supplied.
mod fft;
mod graph;
mod program;
#[cfg(test)]
mod tests;

use crate::{
    Error, Result,
    geometry::{N, Q, T, validate_polynomials},
    statement::Statement,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// Geometry/symbolic planning only. No Source, Formation, key or SQL proof is made.
pub(super) fn inspect_unverified_air(
    statement: &Statement,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let assessment = program::inspect(statement, None)?;
    assessment.log();
    assessment.require_resources()?;
    Ok(())
}

pub(super) const SCALE: u64 = 16389;
pub(super) const PRIVATE_WITNESS_BYTES: usize = 7 * N * core::mem::size_of::<i64>();
pub(super) const LOGICAL_VECTOR_BYTES: usize = 14 * N * 8 + N + 3;
/// Public numeric observation only; not a proof/result/key/SQL receipt.
pub(super) struct GraphObservation {
    pub(super) gates: usize,
    pub(super) rows: usize,
    pub(super) slots: usize,
    pub(super) nodes: usize,
    pub(super) trace_bytes: usize,
    pub(super) logical_vector_upper_bound_bytes: usize,
    pub(super) precheck_ms: f64,
    pub(super) public_plan_ms: f64,
    pub(super) trace_build_and_audit_ms: f64,
    pub(super) coefficient_check_ms: f64,
}
const SMALL: i64 = 20;
const MAX_K: i64 = (1 << 19) - 1;
// SDK parameters.rs: inv(-t) in each Q basis, not floor(Q/t).
const DELTA: [u64; 2] = [536854528, 282551134];

#[derive(Clone, Copy)]
struct Inputs<'a> {
    nonce: [u8; 32],
    identity: [u8; 64],
    // Exact canonical natural PowerBasis arrays: c0,a for each of two operands.
    components: [[&'a [u64]; 2]; 4],
}
impl<'a> Inputs<'a> {
    fn new(statement: &'a Statement) -> Result<Self> {
        for component in 0..4 {
            validate_polynomials(statement.input(component), &Q)?;
        }
        let mut identity = Sha512::new();
        identity.update(b"DCS/GOLD-FORMATION/owner-private-original-request/v1");
        identity.update((statement.request_wire().len() as u64).to_le_bytes());
        identity.update(statement.request_wire());
        Ok(Self {
            nonce: statement.binding(),
            identity: identity.finalize().into(),
            components: core::array::from_fn(|c| {
                core::array::from_fn(|b| statement.input(c)[b].as_slice())
            }),
        })
    }
    fn validate(&self) -> Result<()> {
        if self.nonce == [0; 32] {
            return Err(Error::Binding);
        }
        for component in self.components {
            for (basis, values) in component.into_iter().enumerate() {
                if values.len() != N {
                    return Err(Error::Shape);
                }
                if values.iter().any(|&v| v >= Q[basis]) {
                    return Err(Error::Arithmetic);
                }
            }
        }
        Ok(())
    }
}

// The fixed SDK serializer emits field1, packed4096 one-byte zigzag sint64s.
// Strict canonical form only: unknown/repeated/trailing fields and oversized keys reject.
fn decode_sdk_secret(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<i64>>> {
    if bytes.len() != N + 3 || bytes[..3] != [0x0a, 0x80, 0x20] {
        return Err(Error::Shape);
    }
    let mut secret = Zeroizing::new(Vec::with_capacity(N));
    for &byte in &bytes[3..] {
        if byte > 40 {
            return Err(Error::Arithmetic);
        }
        let value = i64::from(byte >> 1) ^ -i64::from(byte & 1);
        if !(-SMALL..=SMALL).contains(&value) {
            return Err(Error::Arithmetic);
        }
        secret.push(value);
    }
    Ok(secret)
}
fn scaled(raw: [&[u64]; 2]) -> Result<[Zeroizing<Vec<u64>>; 2]> {
    for values in raw {
        if values.len() != N {
            return Err(Error::Shape);
        }
        if values.iter().any(|&v| v >= T) {
            return Err(Error::Arithmetic);
        }
    }
    Ok(raw.map(|values| Zeroizing::new(values.iter().map(|&v| v * SCALE % T).collect())))
}
fn centered(value: i128, modulus: u64) -> i64 {
    let r = value.rem_euclid(i128::from(modulus));
    if r > i128::from(modulus / 2) {
        (r - i128::from(modulus)) as i64
    } else {
        r as i64
    }
}

/// Secret owner-local witness, with no Clone/Debug/serialization or coefficient getter.
/// This is ordinary private arithmetic, not opaque evidence accepted by a peer.
pub(super) struct Witness {
    identity: [u8; 64],
    secret: Zeroizing<Vec<i64>>,
    errors: [Zeroizing<Vec<i64>>; 2],
    quotients: [[Zeroizing<Vec<i64>>; 2]; 2],
}
impl Witness {
    pub(super) fn from_sdk_key(
        statement: &Statement,
        raw: [&[u64]; 2],
        key: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        let inputs = Inputs::new(statement)?;
        Self::derive_inputs(inputs, raw, key)
    }
    fn derive_inputs(
        inputs: Inputs<'_>,
        raw: [&[u64]; 2],
        key: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        inputs.validate()?;
        let words = scaled(raw)?;
        let secret = decode_sdk_secret(key)?;
        let plan = fft::Plan::new()?;
        let secret_frequency = plan.secret_frequency(&secret)?;
        let mut witness = Self {
            identity: inputs.identity,
            secret,
            errors: core::array::from_fn(|_| Zeroizing::new(vec![0; N])),
            quotients: core::array::from_fn(|_| {
                core::array::from_fn(|_| Zeroizing::new(vec![0; N]))
            }),
        };
        for (operand, words) in words.iter().enumerate() {
            for basis in 0..2 {
                let product = plan.product(
                    inputs.components[2 * operand + 1][basis],
                    &secret_frequency,
                    Q[basis],
                )?;
                for at in 0..N {
                    let phase = i128::from(inputs.components[2 * operand][basis][at])
                        + i128::from(product[at])
                        - i128::from(DELTA[basis]) * i128::from(words[at]);
                    let error = centered(phase, Q[basis]);
                    if !(-SMALL..=SMALL).contains(&error) {
                        return Err(Error::Arithmetic);
                    }
                    if basis == 0 {
                        witness.errors[operand][at] = error;
                    } else if witness.errors[operand][at] != error {
                        return Err(Error::Arithmetic);
                    }
                    let exact = phase - i128::from(error);
                    if exact % i128::from(Q[basis]) != 0 {
                        return Err(Error::Arithmetic);
                    }
                    let k = exact / i128::from(Q[basis]);
                    if k < -i128::from(MAX_K) || k > i128::from(MAX_K) {
                        return Err(Error::Arithmetic);
                    }
                    witness.quotients[operand][basis][at] = k as i64;
                }
            }
        }
        Ok(witness)
    }
    pub(super) fn check(&self, statement: &Statement, raw: [&[u64]; 2]) -> Result<()> {
        self.check_inputs(Inputs::new(statement)?, raw)
    }
    /// Separate owner-only graph diagnostic. Existing check/protocol remain unchanged.
    pub(super) fn audit_graph(
        &self,
        statement: &Statement,
        raw: [&[u64]; 2],
    ) -> Result<GraphObservation> {
        let start = std::time::Instant::now();
        self.check(statement, raw)?;
        let words = scaled(raw)?;
        let precheck_ms = start.elapsed().as_secs_f64() * 1000.0;
        let inputs = Inputs::new(statement)?;
        let start = std::time::Instant::now();
        let plan = graph::Plan::new(inputs)?;
        let public_plan_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = std::time::Instant::now();
        let trace = plan.build(&self.secret)?;
        let trace_build_and_audit_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = std::time::Instant::now();
        for (operand, words) in words.iter().enumerate() {
            for basis in 0..2 {
                let product = plan.product(&trace, operand, basis)?;
                for at in 0..N {
                    let residual = i128::from(inputs.components[2 * operand][basis][at])
                        + i128::from(product[at])
                        - i128::from(DELTA[basis]) * i128::from(words[at])
                        - i128::from(self.errors[operand][at])
                        - i128::from(Q[basis]) * i128::from(self.quotients[operand][basis][at]);
                    if residual != 0 {
                        return Err(Error::Arithmetic);
                    }
                }
            }
        }
        let coefficient_check_ms = start.elapsed().as_secs_f64() * 1000.0;
        Ok(GraphObservation {
            gates: graph::GATES,
            rows: graph::ROWS,
            slots: graph::SLOTS,
            nodes: 65 * N,
            trace_bytes: graph::GATES * 4 * core::mem::size_of::<u64>(),
            logical_vector_upper_bound_bytes: graph::LOGICAL_VECTOR_CAP,
            precheck_ms,
            public_plan_ms,
            trace_build_and_audit_ms,
            coefficient_check_ms,
        })
    }
    fn check_inputs(&self, inputs: Inputs<'_>, raw: [&[u64]; 2]) -> Result<()> {
        inputs.validate()?;
        if inputs.identity != self.identity {
            return Err(Error::Binding);
        }
        if self.secret.len() != N || self.secret.iter().any(|v| !(-SMALL..=SMALL).contains(v)) {
            return Err(Error::Arithmetic);
        }
        for errors in &self.errors {
            if errors.len() != N || errors.iter().any(|v| !(-SMALL..=SMALL).contains(v)) {
                return Err(Error::Arithmetic);
            }
        }
        for operand in &self.quotients {
            for k in operand {
                if k.len() != N || k.iter().any(|v| !(-MAX_K..=MAX_K).contains(v)) {
                    return Err(Error::Arithmetic);
                }
            }
        }
        let words = scaled(raw)?;
        let plan = fft::Plan::new()?;
        let secret_frequency = plan.secret_frequency(&self.secret)?;
        for (operand, words) in words.iter().enumerate() {
            for basis in 0..2 {
                let product = plan.product(
                    inputs.components[2 * operand + 1][basis],
                    &secret_frequency,
                    Q[basis],
                )?;
                for at in 0..N {
                    let residual = i128::from(inputs.components[2 * operand][basis][at])
                        + i128::from(product[at])
                        - i128::from(DELTA[basis]) * i128::from(words[at])
                        - i128::from(self.errors[operand][at])
                        - i128::from(Q[basis]) * i128::from(self.quotients[operand][basis][at]);
                    if residual != 0 {
                        return Err(Error::Arithmetic);
                    }
                }
            }
        }
        Ok(())
    }
}
