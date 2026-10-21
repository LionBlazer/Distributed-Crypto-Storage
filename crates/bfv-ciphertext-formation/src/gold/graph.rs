//! Complete owner-private pre-proving graph; NOT an AIR, proof or peer verifier.
//! Public row metadata is lazy. Every secret gate/wire buffer is locally guarded.
use super::{
    Error, Result,
    geometry::{N, Q},
};
use super::{fft, geometry::Inputs};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub(super) const SLOTS: usize = 32;
pub(super) const STAGES: usize = 12;
pub(super) const FORWARD_GATES: usize = N / 2 * STAGES;
pub(super) const POINTWISE_GATES: usize = 4 * N;
pub(super) const INVERSE_GATES: usize = 4 * FORWARD_GATES;
pub(super) const GATES: usize = FORWARD_GATES + POINTWISE_GATES + INVERSE_GATES;
pub(super) const ROWS: usize = GATES / SLOTS;
const VECTORS: usize = 65;
const NODES: usize = VECTORS * N;
const GOLD: u64 = fft::GOLD;
// Includes Trace, wire bank, public tables, inventory and four lifted outputs.
pub(super) const LOGICAL_VECTOR_CAP: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Node {
    vector: u16,
    coefficient: u16,
}
impl Node {
    fn new(vector: usize, coefficient: usize) -> Result<Self> {
        if vector >= VECTORS || coefficient >= N {
            return Err(Error::Shape);
        }
        Ok(Self {
            vector: vector as u16,
            coefficient: coefficient as u16,
        })
    }
    fn slot(self) -> usize {
        usize::from(self.vector) * N + usize::from(self.coefficient)
    }
    /// Fixed future native tuple ID; no witness-selected node label.
    pub(super) fn id(self) -> u64 {
        1 + u64::from(self.vector) * 65536 + u64::from(self.coefficient)
    }
}

/// Metadata only: all coefficients/counts come from the original public request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Gate {
    pub(super) inputs: [Option<Node>; 2],
    pub(super) outputs: [Option<Node>; 2],
    pub(super) linear: [[u64; 2]; 2],
    pub(super) output_uses: [u8; 2],
}
impl Gate {
    fn apply(&self, input: [u64; 2]) -> [u64; 2] {
        core::array::from_fn(|out| {
            add(
                fft::mul(self.linear[out][0], input[0]),
                fft::mul(self.linear[out][1], input[1]),
            )
        })
    }
}
pub(super) struct Row {
    pub(super) gates: [Gate; SLOTS],
}

/// Full literal request + actual canonical A data, with bounded PUBLIC tables.
pub(super) struct Plan {
    identity: [u8; 64],
    a_frequency: [Vec<u64>; 4],
    forward: [Vec<u64>; STAGES],
    inverse: [Vec<u64>; STAGES],
    twist: Vec<u64>,
    normalize: Vec<u64>,
}
impl Plan {
    pub(super) fn new(inputs: Inputs<'_>) -> Result<Self> {
        inputs.validate()?;
        if N != 4096
            || GATES != 139264
            || ROWS != 4352
            || NODES != 266240
            || logical_vectors()? > LOGICAL_VECTOR_CAP
        {
            return Err(Error::Resource);
        }
        let fast = fft::Plan::new()?;
        let mut identity = Sha512::new();
        identity.update(b"DCS/GOLD-FORMATION/private-fixed-graph/v1");
        identity.update(inputs.nonce);
        identity.update(inputs.identity); // SHA512 of the entire original request wire.
        for component in inputs.components {
            for values in component {
                identity.update((values.len() as u64).to_le_bytes());
                for &value in values {
                    identity.update(value.to_le_bytes());
                }
            }
        }
        let a_frequency = (0..4)
            .map(|job| {
                fast.public_frequency(inputs.components[2 * (job / 2) + 1][job % 2], Q[job % 2])
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| Error::Shape)?;
        let omega = fft::mul(fft::PSI, fft::PSI);
        let inv_omega = fft::pow(omega, GOLD - 2);
        let forward = twiddles(omega);
        let inverse = twiddles(inv_omega);
        let twist = powers(fft::PSI, N);
        let inv_psi = fft::pow(fft::PSI, GOLD - 2);
        let inv_n = fft::pow(N as u64, GOLD - 2);
        let normalize = powers(inv_psi, N)
            .into_iter()
            .map(|v| fft::mul(v, inv_n))
            .collect();
        let plan = Self {
            identity: identity.finalize().into(),
            a_frequency,
            forward,
            inverse,
            twist,
            normalize,
        };
        plan.audit_inventory()?;
        Ok(plan)
    }
    pub(super) fn row(&self, index: usize) -> Result<Row> {
        if index >= ROWS {
            return Err(Error::Shape);
        }
        let mut gates = [Gate {
            inputs: [None; 2],
            outputs: [None; 2],
            linear: [[0; 2]; 2],
            output_uses: [0; 2],
        }; SLOTS];
        for (slot, gate) in gates.iter_mut().enumerate() {
            *gate = self.gate(index * SLOTS + slot)?;
        }
        Ok(Row { gates })
    }
    fn gate(&self, index: usize) -> Result<Gate> {
        if index >= GATES {
            return Err(Error::Shape);
        }
        if index < FORWARD_GATES {
            return self.butterfly(None, index);
        }
        let index = index - FORWARD_GATES;
        if index < POINTWISE_GATES {
            let job = index / N;
            let at = index % N;
            return Ok(Gate {
                inputs: [Some(Node::new(12, at)?), None],
                outputs: [Some(Node::new(13 + job, at)?), None],
                linear: [[self.a_frequency[job][at], 0], [0, 0]],
                output_uses: [1, 0],
            });
        }
        let index = index - POINTWISE_GATES;
        self.butterfly(Some(index / FORWARD_GATES), index % FORWARD_GATES)
    }
    fn butterfly(&self, job: Option<usize>, index: usize) -> Result<Gate> {
        let stage = index / (N / 2);
        let at = index % (N / 2);
        let half = 1 << stage;
        let block = at / half;
        let offset = at % half;
        let a = block * 2 * half + offset;
        let b = a + half;
        let (input_vector, output_vector, w) = if let Some(job) = job {
            (
                if stage == 0 {
                    13 + job
                } else {
                    17 + job * STAGES + stage - 1
                },
                17 + job * STAGES + stage,
                self.inverse[stage][offset],
            )
        } else {
            (stage, stage + 1, self.forward[stage][offset])
        };
        let input_a = if stage == 0 { reverse(a) } else { a };
        let input_b = if stage == 0 { reverse(b) } else { b };
        let mut linear = [[1, w], [1, neg(w)]];
        if job.is_none() && stage == 0 {
            for row in &mut linear {
                row[0] = fft::mul(row[0], self.twist[input_a]);
                row[1] = fft::mul(row[1], self.twist[input_b]);
            }
        }
        if job.is_some() && stage == STAGES - 1 {
            for value in &mut linear[0] {
                *value = fft::mul(*value, self.normalize[a]);
            }
            for value in &mut linear[1] {
                *value = fft::mul(*value, self.normalize[b]);
            }
        }
        let uses = if job.is_none() && stage == STAGES - 1 {
            4
        } else {
            1
        };
        Ok(Gate {
            inputs: [
                Some(Node::new(input_vector, input_a)?),
                Some(Node::new(input_vector, input_b)?),
            ],
            outputs: [
                Some(Node::new(output_vector, a)?),
                Some(Node::new(output_vector, b)?),
            ],
            linear,
            output_uses: [uses; 2],
        })
    }
    pub(super) fn audit_inventory(&self) -> Result<()> {
        let mut inventory = Inventory::new();
        for index in 0..GATES {
            inventory.include(self.gate(index)?)?;
        }
        inventory.finish()
    }
    pub(super) fn build(&self, secret: &[i64]) -> Result<Trace> {
        let mut wires = source_bank(secret)?;
        let mut values = Zeroizing::new(Vec::with_capacity(GATES));
        for index in 0..ROWS {
            for gate in self.row(index)?.gates {
                let input = gate
                    .inputs
                    .map(|node| node.map_or(0, |node| wires[node.slot()]));
                let output = gate.apply(input);
                for (node, value) in gate.outputs.into_iter().zip(output) {
                    if let Some(node) = node {
                        wires[node.slot()] = value;
                    }
                }
                values.push([input[0], input[1], output[0], output[1]]);
            }
        }
        let trace = Trace {
            identity: self.identity,
            values,
        };
        drop(wires); // Audit must not overlap two full private wire banks.
        self.audit(&trace, secret)?;
        Ok(trace)
    }
    /// Checks exact predecessor values AND equations; local equations alone are insufficient.
    pub(super) fn audit(&self, trace: &Trace, secret: &[i64]) -> Result<()> {
        if trace.identity != self.identity {
            return Err(Error::Binding);
        }
        if trace.values.len() != GATES {
            return Err(Error::Shape);
        }
        let mut wires = source_bank(secret)?;
        for (index, values) in trace.values.iter().enumerate() {
            if values.iter().any(|&v| v >= GOLD) {
                return Err(Error::Arithmetic);
            }
            let gate = self.gate(index)?;
            let input = gate
                .inputs
                .map(|node| node.map_or(0, |node| wires[node.slot()]));
            if values[..2] != input || values[2..] != gate.apply(input) {
                return Err(Error::Arithmetic);
            }
            for (node, value) in gate.outputs.into_iter().zip(&values[2..]) {
                if let Some(node) = node {
                    wires[node.slot()] = *value;
                } else if *value != 0 {
                    return Err(Error::Arithmetic);
                }
            }
        }
        Ok(())
    }
    pub(super) fn product(
        &self,
        trace: &Trace,
        operand: usize,
        basis: usize,
    ) -> Result<Zeroizing<Vec<i64>>> {
        if trace.identity != self.identity {
            return Err(Error::Binding);
        }
        if operand >= 2 || basis >= 2 || trace.values.len() != GATES {
            return Err(Error::Shape);
        }
        let job = operand * 2 + basis;
        let first = FORWARD_GATES + POINTWISE_GATES + job * FORWARD_GATES + (STAGES - 1) * (N / 2);
        let mut product = Zeroizing::new(vec![0; N]);
        let limit = 20_i128 * N as i128 * i128::from(Q[basis] - 1);
        for gate_index in first..first + N / 2 {
            let gate = self.gate(gate_index)?;
            for (node, &value) in gate.outputs.into_iter().zip(&trace.values[gate_index][2..]) {
                let node = node.ok_or(Error::Shape)?;
                if value >= GOLD {
                    return Err(Error::Arithmetic);
                }
                let value = if value <= GOLD / 2 {
                    i128::from(value)
                } else {
                    -i128::from(GOLD - value)
                };
                if value.abs() > limit {
                    return Err(Error::Arithmetic);
                }
                product[usize::from(node.coefficient)] =
                    i64::try_from(value).map_err(|_| Error::Arithmetic)?;
            }
        }
        Ok(product)
    }
}

/// No Clone/Debug/serialization, public export, key/SDK handle or accepting status.
pub(super) struct Trace {
    identity: [u8; 64],
    pub(super) values: Zeroizing<Vec<[u64; 4]>>,
}

struct Inventory {
    balance: Vec<i32>,
    producers: Vec<u8>,
}
impl Inventory {
    fn new() -> Self {
        let mut this = Self {
            balance: vec![0; NODES],
            producers: vec![0; NODES],
        };
        for at in 0..N {
            this.balance[at] = 1;
            this.producers[at] = 1;
        }
        // Exact outer boundary: one range-bank consumer for each final inverse coefficient.
        for job in 0..4 {
            for at in 0..N {
                this.balance[(28 + job * STAGES) * N + at] -= 1;
            }
        }
        this
    }
    fn include(&mut self, gate: Gate) -> Result<()> {
        for node in gate.inputs.into_iter().flatten() {
            if node.id() >= GOLD {
                return Err(Error::Shape);
            }
            self.balance[node.slot()] -= 1;
        }
        for (node, uses) in gate.outputs.into_iter().zip(gate.output_uses) {
            match node {
                Some(node) if (1..=4).contains(&uses) => {
                    self.balance[node.slot()] += i32::from(uses);
                    self.producers[node.slot()] = self.producers[node.slot()]
                        .checked_add(1)
                        .ok_or(Error::Shape)?;
                }
                None if uses == 0 => (),
                _ => return Err(Error::Shape),
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.balance.iter().any(|&v| v != 0) || self.producers.iter().any(|&v| v != 1) {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
fn source_bank(secret: &[i64]) -> Result<Zeroizing<Vec<u64>>> {
    if secret.len() != N || secret.iter().any(|v| !(-20..=20).contains(v)) {
        return Err(Error::Arithmetic);
    }
    let mut bank = Zeroizing::new(vec![0; NODES]);
    for (cell, &value) in bank.iter_mut().zip(secret) {
        *cell = if value < 0 {
            GOLD - value.unsigned_abs()
        } else {
            value as u64
        };
    }
    Ok(bank)
}
fn powers(root: u64, length: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(length);
    let mut power = 1;
    for _ in 0..length {
        out.push(power);
        power = fft::mul(power, root);
    }
    out
}
fn twiddles(root: u64) -> [Vec<u64>; STAGES] {
    core::array::from_fn(|stage| {
        let half = 1 << stage;
        powers(fft::pow(root, (N / (2 * half)) as u64), half)
    })
}
fn reverse(value: usize) -> usize {
    value.reverse_bits() >> (usize::BITS as usize - STAGES)
}
fn add(a: u64, b: u64) -> u64 {
    ((u128::from(a) + u128::from(b)) % u128::from(GOLD)) as u64
}
fn neg(a: u64) -> u64 {
    if a == 0 { 0 } else { GOLD - a }
}
fn logical_vectors() -> Result<usize> {
    // Trace + one private wire bank + all public A/twiddle/twist tables +
    // public inventory + four lifted outputs; not SDK/allocator/whole-PID RAM.
    let terms = [
        GATES * 4 * 8,
        NODES * 8,
        (4 * N + 2 * (N - 1) + 2 * N) * 8,
        NODES * 5,
        4 * N * 8,
    ];
    terms
        .into_iter()
        .try_fold(0usize, |a, b| a.checked_add(b).ok_or(Error::Resource))
}
