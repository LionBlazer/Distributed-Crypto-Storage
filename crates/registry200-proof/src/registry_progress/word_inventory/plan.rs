//! Deterministic complete row inventory. No private witness and no proof capability.
use super::expr::{Node, Op, Pool};
use crate::Val;
use p3_field::PrimeCharacteristicRing;
use std::collections::BTreeMap;
pub(super) const PORTS: usize = 64;
pub(super) const BITS: usize = 256;
pub(super) const GATES: usize = 20;
pub(super) const WIDTH: usize = 248 + PORTS + BITS;
pub(super) const PHASES: usize = 9;
pub(super) const INPUT: usize = 0;
pub(super) const ARITH: usize = 1;
pub(super) const ASSERT: usize = 2;
pub(super) const RANGE: usize = 3;
pub(super) const HASH: usize = 4;
pub(super) const POLICY_READ: usize = 5;
pub(super) const POLICY_TABLE: usize = 6;
pub(super) const MASK_TABLE: usize = 7;
pub(super) const MASK_READ: usize = 8;
pub(super) const PORT_META: usize = PHASES; // active, constant, fixed, wire, signed count
pub(super) const OPS: usize = PORT_META + 5 * PORTS;
pub(super) const RANGE_BITS: usize = OPS + 4 * GATES;
pub(super) const HASH_OUTPUT: usize = RANGE_BITS + BITS; // twelve (wire,count) pairs
pub(super) const POLICY_VALUES: usize = HASH_OUTPUT + 24;
pub(super) const MASK_INDEX: usize = POLICY_VALUES + 5;
pub(super) const RANGE_ON_HASH: usize = MASK_INDEX + 1;
pub(super) const POLICY_ACTIVE: usize = RANGE_ON_HASH + 1;
pub(super) const POLICY_SLOTS: usize = 12;
pub(super) const PP_WIDTH: usize = POLICY_ACTIVE + POLICY_SLOTS;
#[derive(Clone)]
pub(super) struct Port {
    pub id: usize,
    pub provider: bool,
    pub constant: Option<Val>,
}
#[derive(Clone)]
pub(super) struct Row {
    pub phase: usize,
    pub ports: Vec<Port>,
    pub ops: Vec<Op>,
    pub bits: [bool; BITS],
    pub hash: Option<usize>,
    pub table: Option<usize>,
    pub mask: Option<usize>,
    pub read: Option<usize>,
    pub labels: Vec<String>,
    pub range: bool,
    pub policies: Vec<usize>,
}
impl Row {
    fn new(phase: usize) -> Self {
        Self {
            phase,
            ports: Vec::new(),
            ops: Vec::new(),
            bits: [false; BITS],
            hash: None,
            table: None,
            mask: None,
            read: None,
            labels: Vec::new(),
            range: false,
            policies: Vec::new(),
        }
    }
}
#[derive(Clone)]
pub(super) struct Plan {
    pub pool: Pool,
    pub rows: Vec<Row>,
    pub height: usize,
    pub uses: Vec<u32>,
    pub max_fanout: u32,
    pub phases: [usize; PHASES],
    pub wire_reads: usize,
    pub hash_blocks: usize,
    pub policy_queries: usize,
    pub stream_fields: usize,
}
impl Plan {
    pub fn new(pool: Pool) -> Result<Self, String> {
        if !pool.errors.is_empty() {
            return Err(pool.errors.join(","));
        }
        if pool.nodes.is_empty() || pool.nodes.len() > 1_000_000 {
            return Err("node-count".into());
        }
        let mut this = Self {
            uses: vec![0; pool.nodes.len()],
            pool,
            rows: Vec::new(),
            height: 0,
            max_fanout: 0,
            phases: [0; PHASES],
            wire_reads: 0,
            hash_blocks: 0,
            policy_queries: 0,
            stream_fields: 0,
        };
        // Every nonconstant value has ONE producer; consumer multiplicities count
        // each occurrence, including two reads of the same operand/age.
        let input = this
            .pool
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| matches!(n, Node::Input(..)).then_some(i))
            .collect::<Vec<_>>();

        let gates = this
            .pool
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| {
                if let Node::Arith(op, a, b) = n {
                    Some((i, *op, *a, *b))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for chunk in gates.chunks(GATES) {
            let mut row = Row::new(ARITH);
            for (id, op, a, b) in chunk {
                this.port(&mut row, *a, false)?;
                this.port(&mut row, *b, false)?;
                this.port(&mut row, *id, true)?;
                row.ops.push(*op);
            }
            this.push(row)?;
        }
        let assertions = this.pool.assertions.clone();
        for chunk in assertions.chunks(PORTS) {
            let mut row = Row::new(ASSERT);
            for id in chunk {
                this.port(&mut row, *id, false)?;
            }
            this.push(row)?;
        }
        let ranges = this
            .pool
            .ranges
            .iter()
            .map(|(id, n)| (*id, *n))
            .collect::<Vec<_>>();
        let mut ranges = ranges.chunks(8);
        let mut input = input.into_iter();
        // Hash uses ports0..11. A verifier-selected range block uses12..19;
        // otherwise Input providers start at12 (or at20 after a range block).
        // No standalone Input/Range rows and no private routing selector exist.
        for i in 0..this.pool.hashes.len() {
            let mut row = Row::new(HASH);
            let hash = this.pool.hashes[i].clone();
            for id in hash.input {
                this.port(&mut row, id, false)?;
            }
            if let Some(chunk) = ranges.next() {
                row.range = true;
                for (slot, (id, n)) in chunk.iter().enumerate() {
                    if !(1..=32).contains(n) {
                        return Err("range-width".into());
                    }
                    this.port(&mut row, *id, false)?;
                    for bit in 0..usize::from(*n) {
                        row.bits[32 * slot + bit] = true;
                    }
                }
                while row.ports.len() < 20 {
                    this.port(&mut row, 0, false)?;
                }
            }
            while row.ports.len() < PORTS {
                let Some(id) = input.next() else {
                    break;
                };
                this.port(&mut row, id, true)?;
            }
            row.hash = Some(i);
            row.labels.push(hash.label);
            this.push(row)?;
        }
        if input.next().is_some() || ranges.next().is_some() {
            return Err("hash-spare-capacity".into());
        }
        for first in (0..this.pool.policies.len()).step_by(POLICY_SLOTS) {
            let mut row = Row::new(POLICY_READ);
            for i in first..(first + POLICY_SLOTS).min(this.pool.policies.len()) {
                let q = this.pool.policies[i].clone();
                this.port(&mut row, q.a, false)?;
                this.port(&mut row, q.b, false)?;
                for id in q.output {
                    this.port(&mut row, id, true)?;
                }
                row.policies.push(i);
            }
            this.push(row)?;
        }
        if this.pool.policy_frequencies.len() != 25 {
            return Err("policy-table25".into());
        }
        for i in 0..25 {
            let mut row = Row::new(POLICY_TABLE);
            row.table = Some(i);
            this.port(&mut row, this.pool.policy_frequencies[i], true)?;
            this.push(row)?;
        }
        if this.pool.mask.len() != 32 || this.pool.reads.len() != 4 {
            return Err("mask-inventory".into());
        }
        for i in 0..32 {
            let m = this.pool.mask[i].clone();
            let mut row = Row::new(MASK_TABLE);
            row.mask = Some(i);
            for id in m.bits.into_iter().chain(m.frequencies).chain([m.byte]) {
                this.port(&mut row, id, true)?;
            }
            for bit in 0..24 {
                row.bits[bit] = true;
            }
            this.push(row)?;
        }
        for i in 0..4 {
            let read = this.pool.reads[i].clone();
            let mut row = Row::new(MASK_READ);
            row.read = Some(i);
            this.port(&mut row, read.age, false)?;
            this.port(&mut row, read.output, true)?;
            this.push(row)?;
        }
        this.height = this
            .rows
            .len()
            .max(super::TARGET_HEIGHT)
            .checked_next_power_of_two()
            .ok_or("height-overflow")?;
        this.max_fanout = this.uses.iter().copied().max().unwrap_or(0);
        this.hash_blocks = this.pool.hashes.len();
        this.policy_queries = this.pool.policies.len();
        this.stream_fields = this
            .pool
            .fields
            .keys()
            .filter(|s| s.starts_with("stream/"))
            .count();
        this.inventory()?;
        Ok(this)
    }
    fn port(&mut self, row: &mut Row, id: usize, provider: bool) -> Result<(), String> {
        let node = self.pool.nodes.get(id).ok_or("foreign-wire")?;
        let constant = if let Node::Constant(v) = node {
            Some(*v)
        } else {
            None
        };
        if provider && constant.is_some() {
            return Err("constant-provider".into());
        }
        if !provider && constant.is_none() {
            self.uses[id] = self.uses[id].checked_add(1).ok_or("fanout-overflow")?;
            self.wire_reads = self.wire_reads.checked_add(1).ok_or("read-overflow")?;
        }
        row.ports.push(Port {
            id,
            provider,
            constant,
        });
        Ok(())
    }
    fn push(&mut self, row: Row) -> Result<(), String> {
        if row.ports.len() > PORTS || row.ops.len() > GATES || row.phase >= PHASES {
            return Err("row-overflow".into());
        }
        self.phases[row.phase] += 1;
        self.rows.push(row);
        Ok(())
    }
    pub fn inventory(&self) -> Result<(), String> {
        let mut producers = vec![0usize; self.pool.nodes.len()];
        let mut consumers = vec![0u32; self.pool.nodes.len()];
        for row in &self.rows {
            for p in &row.ports {
                if p.constant.is_none() {
                    if p.provider {
                        producers[p.id] += 1;
                    } else {
                        consumers[p.id] = consumers[p.id].checked_add(1).ok_or("count-overflow")?;
                    }
                }
            }
            if let Some(i) = row.hash {
                for id in self.pool.hashes[i].output {
                    producers[id] += 1;
                }
            }
        }
        for (i, node) in self.pool.nodes.iter().enumerate() {
            if !matches!(node, Node::Constant(_))
                && (producers[i] != 1 || consumers[i] != self.uses[i])
            {
                return Err(format!(
                    "uncovered-value:{i}:{}:{}",
                    producers[i], consumers[i]
                ));
            }
            let bound = match node {
                Node::Constant(_) | Node::Arith(..) => true,
                Node::Input(label, ty) => {
                    !label.is_empty()
                        && match ty {
                            super::expr::Ty::U32 => self.pool.ranges.get(&i) == Some(&32),
                            super::expr::Ty::Bits(n) => self.pool.ranges.get(&i) == Some(n),
                            _ => true,
                        }
                }
                Node::Hash(h, w) => {
                    self.pool.hashes.get(*h).and_then(|v| v.output.get(*w)) == Some(&i)
                }
                Node::Policy(q, w) => {
                    self.pool.policies.get(*q).and_then(|v| v.output.get(*w)) == Some(&i)
                }
                Node::PolicyFrequency(q) => self.pool.policy_frequencies.get(*q) == Some(&i),
                Node::MaskBit(q, w) => {
                    self.pool.mask.get(*q).and_then(|v| v.bits.get(*w)) == Some(&i)
                }
                Node::MaskFrequency(q, w) => {
                    self.pool.mask.get(*q).and_then(|v| v.frequencies.get(*w)) == Some(&i)
                }
                Node::MaskByte(q) => self.pool.mask.get(*q).map(|v| v.byte) == Some(i),
                Node::MaskRead(q) => self.pool.reads.get(*q).map(|v| v.output) == Some(i),
            };
            if !bound {
                return Err(format!("unbound-special-value:{i}"));
            }
        }
        let expected = [
            ("source", 680),
            ("enrollment", 64),
            ("command", 160),
            ("statement", 96),
            ("old-progress", 48),
            ("new-progress", 48),
            ("old", 208),
            ("new", 208),
            ("result", 160),
        ];
        for (label, n) in expected {
            for i in 0..n {
                if !self
                    .pool
                    .fields
                    .contains_key(&format!("stream/{label}/{i}"))
                {
                    return Err(format!("missing-field:{label}/{i}"));
                }
            }
            let count = self
                .pool
                .fields
                .keys()
                .filter(|s| s.starts_with(&format!("stream/{label}/")))
                .count();
            if count != n {
                return Err(format!("extra-field:{label}"));
            }
        }
        for bank in ["old", "new"] {
            for i in 0..208 {
                let id = self
                    .pool
                    .fields
                    .get(&format!("{bank}/serialized/{i}"))
                    .ok_or("missing-208")?;
                if self.pool.fields.get(&format!("stream/{bank}/{i}")) != Some(id) {
                    return Err("foreign-208-serialization".into());
                }
            }
        }
        // Exact typed layout coverage, independent of aggregate wire balance.
        let mut ranged = BTreeMap::new();
        let mut policy_seen = vec![false; self.pool.policies.len()];
        for row in &self.rows {
            if row.range && row.phase != HASH {
                return Err("range-phase".into());
            }
            if row.phase == HASH {
                let hash = &self.pool.hashes[row.hash.ok_or("missing-hash")?];
                if row.ports.len() < 12 {
                    return Err("hash-ports".into());
                }
                for (i, id) in hash.input.iter().enumerate() {
                    let p = &row.ports[i];
                    if p.id != *id || p.provider {
                        return Err("foreign-hash-input".into());
                    }
                }
                let first = if row.range {
                    if row.ports.len() < 20 {
                        return Err("range-slots".into());
                    }
                    for slot in 0..8 {
                        let p = &row.ports[12 + slot];
                        let n = (0..32).take_while(|bit| row.bits[32 * slot + bit]).count();
                        if (n..32).any(|bit| row.bits[32 * slot + bit]) {
                            return Err("range-bit-gap".into());
                        }
                        if n == 0 {
                            if p.provider || p.constant != Some(Val::ZERO) {
                                return Err("range-padding".into());
                            }
                        } else {
                            if p.provider
                                || p.constant.is_some()
                                || self.pool.ranges.get(&p.id) != Some(&(n as u8))
                                || ranged.insert(p.id, n as u8).is_some()
                            {
                                return Err("foreign-range".into());
                            }
                        }
                    }
                    20
                } else {
                    if row.bits.iter().any(|v| *v) {
                        return Err("inactive-range-bits".into());
                    }
                    12
                };
                for p in &row.ports[first..] {
                    if !p.provider || !matches!(self.pool.nodes[p.id], Node::Input(..)) {
                        return Err("foreign-input-provider".into());
                    }
                }
            }
            if row.phase == POLICY_READ {
                if row.policies.is_empty()
                    || row.policies.len() > POLICY_SLOTS
                    || row.ports.len() != 5 * row.policies.len()
                {
                    return Err("policy-slots".into());
                }
                for (slot, id) in row.policies.iter().enumerate() {
                    let seen = policy_seen.get_mut(*id).ok_or("foreign-policy")?;
                    if *seen {
                        return Err("duplicate-policy".into());
                    }
                    *seen = true;
                    let q = &self.pool.policies[*id];
                    let ids = [q.a, q.b, q.output[0], q.output[1], q.output[2]];
                    for (i, id) in ids.iter().enumerate() {
                        let p = &row.ports[5 * slot + i];
                        if p.id != *id || p.provider != (i >= 2) {
                            return Err("foreign-policy-port".into());
                        }
                    }
                }
            } else if !row.policies.is_empty() {
                return Err("policy-phase".into());
            }
        }
        if ranged != self.pool.ranges
            || policy_seen.iter().any(|v| !*v)
            || self.phases[INPUT] != 0
            || self.phases[RANGE] != 0
        {
            return Err("packed-complete-coverage".into());
        }
        if self.hash_blocks != 209
            || self.stream_fields != 1672
            || self.phases[HASH] != 209
            || self.phases[MASK_TABLE] != 32
            || self.phases[MASK_READ] != 4
            || self.phases[POLICY_TABLE] != 25
        {
            return Err("full-stream-inventory".into());
        }
        if self.max_fanout == 0 || self.max_fanout > u32::MAX / 2 {
            return Err("fanout-bound".into());
        }
        Ok(())
    }
    pub fn admissible_rows(&self) -> bool {
        self.rows.len() <= super::TARGET_HEIGHT
    }
    pub fn pp_row(&self, r: usize) -> Vec<Val> {
        let mut p = vec![Val::ZERO; PP_WIDTH];
        let Some(row) = self.rows.get(r) else {
            return p;
        };
        p[row.phase] = Val::ONE;
        p[RANGE_ON_HASH] = Val::from_bool(row.range);
        for slot in 0..row.policies.len() {
            p[POLICY_ACTIVE + slot] = Val::ONE;
        }
        for (i, port) in row.ports.iter().enumerate() {
            let at = PORT_META + 5 * i;
            p[at] = Val::ONE;
            if let Some(v) = port.constant {
                p[at + 1] = Val::ONE;
                p[at + 2] = v;
            } else {
                p[at + 3] = Val::from_usize(port.id + 1);
                p[at + 4] = if port.provider {
                    Val::from_u32(self.uses[port.id])
                } else {
                    -Val::ONE
                };
            }
        }
        for (i, op) in row.ops.iter().enumerate() {
            let k = match op {
                Op::Add => 0,
                Op::Sub => 1,
                Op::Mul => 2,
                Op::Neg => 3,
            };
            p[OPS + 4 * i + k] = Val::ONE;
        }
        for (i, active) in row.bits.iter().enumerate() {
            p[RANGE_BITS + i] = Val::from_bool(*active);
        }
        if let Some(i) = row.hash {
            for (w, id) in self.pool.hashes[i].output.into_iter().enumerate() {
                p[HASH_OUTPUT + 2 * w] = Val::from_usize(id + 1);
                p[HASH_OUTPUT + 2 * w + 1] = Val::from_u32(self.uses[id]);
            }
        }
        if let Some(i) = row.table {
            let a = (i / 5) as u8;
            let b = (i % 5) as u8;
            let data = [
                a,
                b,
                a.max(b),
                u8::from(a <= b),
                u8::from(crate::lifecycle::conflicts(a, b)),
            ];
            for (j, v) in data.into_iter().enumerate() {
                p[POLICY_VALUES + j] = Val::from_u8(v);
            }
        }
        if let Some(i) = row.mask {
            p[MASK_INDEX] = Val::from_usize(i * 8);
        }
        p
    }
    pub fn summary(&self) -> String {
        format!(
            "complete=true fits_H512={} target_height={} actual_rows={} padded_height={} main_width={} pp_width={} values={} wire_reads={} max_fanout={} assertions={} ranges={} hash_absorbs={} policy_queries={} policy_table=25 mask_bytes=32 mask_reads=4 stream_fields={} phases={:?}",
            self.admissible_rows(),
            super::TARGET_HEIGHT,
            self.rows.len(),
            self.height,
            WIDTH,
            PP_WIDTH,
            self.pool.nodes.len(),
            self.wire_reads,
            self.max_fanout,
            self.pool.assertions.len(),
            self.pool.ranges.len(),
            self.hash_blocks,
            self.policy_queries,
            self.stream_fields,
            self.phases
        )
    }
    pub fn coverage(&self) -> BTreeMap<String, usize> {
        let mut map = BTreeMap::new();
        for name in self.pool.fields.keys() {
            let key = name
                .rsplit_once('/')
                .map(|(a, _)| a)
                .unwrap_or(name)
                .to_owned();
            *map.entry(key).or_insert(0) += 1;
        }
        map
    }
}
