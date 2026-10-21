//! Static routes only. Construction never accepts Metadata, Expected or ciphertext.
use super::*;
pub(super) struct Plan {
    schedule: graph::Schedule,
}
impl Plan {
    pub(super) fn new() -> Result<Self> {
        if H != 2048
            || PP != 656
            || FANOUT + SLOTS != PP
            || GRAPH_ROWS != 1463
            || CS_FIRST != 1977
            || RANGE_ONLY_FIRST != 2043
            || COEFFICIENT_WORDS != H * HASH_PORTS
            || PORTS != 247
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            schedule: graph::Schedule::new(RelationKind::Data)?,
        })
    }
    pub(super) fn scheduled(&self, index: usize) -> Result<graph::ScheduledGate> {
        self.schedule.gate(index)
    }
    pub(super) fn row(&self, index: usize) -> Result<[Val; PP]> {
        if index >= H {
            return Err(Error::Shape);
        }
        let mut p = [Val::ZERO; PP];
        p[FLAGS + old_pp::RANGE] = Val::ONE;
        p[FLAGS + old_pp::RESET] = Val::from_bool(index.is_multiple_of(4));
        p[FLAGS + old_pp::EMIT] = Val::from_bool(index % 4 == 3);
        p[POWER] = Val::from_u64(1u64 << (12 * (index % 4)));
        let range = RelationKind::Data.range();
        for k in 0..2 {
            let at = 2 * index + k;
            let base = GRAPH_PORTS + k * range.stride;
            p[base] = Val::from_u64(node(0, at)?);
            p[base + range.w] = Val::from_u64(node(RelationKind::Data.w_tag(0), at)?);
            for job in 0..2 {
                p[base + range.product + job] =
                    Val::from_u64(node(RelationKind::Data.final_vector(job), at)?);
                p[ORIGINAL_PORTS + 2 * k + job] = Val::from_u64(node(C0_TAG + job, at)?);
            }
        }
        if index % 4 == 3 {
            p[GRAPH_PORTS + 18] = Val::from_u64(node(RelationKind::Data.cs_tag(), index / 4)?);
        }
        if index < GRAPH_ROWS {
            p[FLAGS + old_pp::ARITH] = Val::ONE;
            for slot in 0..SLOTS {
                let gate_index = index * SLOTS + slot;
                if gate_index >= GATES {
                    continue;
                }
                let base = 4 * slot;
                p[ACTIVE + slot] = Val::ONE;
                match self.schedule.gate(gate_index)? {
                    graph::ScheduledGate::Butterfly(gate) => {
                        for (port, id) in gate.inputs.iter().chain(&gate.outputs).enumerate() {
                            if let Some(id) = id {
                                p[base + port] = Val::from_u64(id.id());
                            }
                        }
                        for (at, &v) in gate.linear.iter().flatten().enumerate() {
                            p[COEFFICIENTS + base + at] = Val::from_u64(v);
                        }
                        let fanout = gate.output_uses == [2, 2];
                        if gate.output_uses != if fanout { [2, 2] } else { [1, 1] } {
                            return Err(Error::Shape);
                        }
                        p[FANOUT + slot] = Val::from_bool(fanout);
                    }
                    graph::ScheduledGate::Pointwise(point) => {
                        if point.job >= 2 || point.coefficient >= N {
                            return Err(Error::Shape);
                        }
                        p[base] = Val::from_u64(point.input.id());
                        p[base + 1] = Val::from_u64(node(FREQ_TAG + point.job, point.coefficient)?);
                        p[base + 2] = Val::from_u64(point.output.id());
                        p[COEFFICIENTS + base] = Val::ONE; // fixed structural marker, never A data
                        p[POINTWISE + slot] = Val::ONE;
                    }
                }
            }
        } else if index < RANGE_ONLY_FIRST {
            let (start, length, tag, flag) = if index < CS_FIRST {
                (CW_FIRST, 514, RelationKind::Data.w_tag(0), old_pp::SOURCE)
            } else {
                (CS_FIRST, 66, RelationKind::Data.cs_tag(), old_pp::CS)
            };
            let block = index - start;
            for flag in [old_pp::HASH, flag] {
                p[FLAGS + flag] = Val::ONE;
            }
            p[FLAGS + old_pp::FIRST] = Val::from_bool(block == 0);
            p[FLAGS + old_pp::LAST] = Val::from_bool(block + 1 == length);
            p[FLAGS + old_pp::CONTEXT] = Val::from_bool(block == 0);
            p[FLAGS + old_pp::SALT] = Val::from_bool(block == 1);
            p[FLAGS + old_pp::PAYLOAD] = Val::from_bool(block >= 2);
            if block >= 2 {
                for (at, out) in p.iter_mut().take(8).enumerate() {
                    *out = Val::from_u64(node(tag, 8 * (block - 2) + at)?);
                }
            }
        }
        Ok(p)
    }
}
pub(super) fn hash_row(index: usize) -> Result<[Val; HASH_PP]> {
    if index >= H {
        return Err(Error::Shape);
    }
    let mut p = [Val::ZERO; HASH_PP];
    for (i, out) in p.iter_mut().take(HASH_PORTS).enumerate() {
        let at = HASH_PORTS * index + i;
        *out = Val::from_u64(node(FREQ_TAG + at / N, at % N)?);
    }
    p[HASH_FIRST] = Val::from_bool(index == 0);
    p[HASH_LAST] = Val::from_bool(index + 1 == H);
    Ok(p)
}
pub(super) fn count(p: &[Val; PP], port: usize) -> Result<i32> {
    if port >= PORTS {
        return Err(Error::Shape);
    }
    let flag = |i: usize| p[FLAGS + i].as_canonical_u64() as i32;
    if port < GRAPH_PORTS {
        let active = p[ACTIVE + port / 4].as_canonical_u64() as i32;
        let point = p[POINTWISE + port / 4].as_canonical_u64() as i32;
        let fanout = p[FANOUT + port / 4].as_canonical_u64() as i32;
        let graph = match port % 4 {
            0 | 1 => -active,
            2 => active + fanout,
            3 => active - point + fanout,
            _ => return Err(Error::Shape),
        };
        Ok(graph - if port < 8 { flag(old_pp::PAYLOAD) } else { 0 })
    } else if port >= ORIGINAL_PORTS {
        Ok(-1)
    } else {
        let local = port - GRAPH_PORTS;
        let range = RelationKind::Data.range();
        let bank = local % range.stride;
        Ok(if local == 18 {
            flag(old_pp::EMIT)
        } else if bank == 0 || bank == range.w {
            1
        } else if (range.product..range.product + 2).contains(&bank) {
            -1
        } else {
            0
        })
    }
}

pub(super) struct Inventory {
    pub(super) gates: usize,
    pub(super) hashes: usize,
    pub(super) range_coefficients: usize,
    pub(super) public_coefficients: usize,
    pub(super) weighted_uses: usize,
    pub(super) producers: usize,
}
/// Exact combined multiset. No per-AIR-zero fiction: PUBLIC sources live in AIR1.
pub(super) fn inventory(plan: &Plan) -> Result<Inventory> {
    let mut balance = vec![0i32; 45 * N];
    let mut producers = vec![0u8; 45 * N];
    let mut positive = 0usize;
    let mut negative = 0usize;
    let mut include = |id: u64, count: i32| -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        if id == 0 || count.unsigned_abs() > 4 {
            return Err(Error::Shape);
        }
        let tag = ((id - 1) / 65536) as usize;
        let at = ((id - 1) % 65536) as usize;
        if node(tag, at)? != id {
            return Err(Error::Shape);
        }
        let cell = tag * N + at;
        balance[cell] = balance[cell].checked_add(count).ok_or(Error::Resource)?;
        if count > 0 {
            producers[cell] = producers[cell].checked_add(1).ok_or(Error::Resource)?;
            positive = positive
                .checked_add(count as usize)
                .ok_or(Error::Resource)?;
        } else {
            negative = negative
                .checked_add((-count) as usize)
                .ok_or(Error::Resource)?;
        }
        Ok(())
    };
    let mut gates = 0;
    let mut hashes = 0;
    for row in 0..H {
        let p = plan.row(row)?;
        gates += p[ACTIVE..ACTIVE + SLOTS]
            .iter()
            .map(|x| x.as_canonical_u64() as usize)
            .sum::<usize>();
        hashes += p[FLAGS + old_pp::HASH].as_canonical_u64() as usize;
        for (port, &id) in p.iter().take(PORTS).enumerate() {
            include(id.as_canonical_u64(), count(&p, port)?)?;
        }
        for id in hash_row(row)?.iter().take(HASH_PORTS) {
            include(id.as_canonical_u64(), 1)?;
        }
    }
    drop(include);
    if gates != GATES || hashes != 580 || balance.iter().any(|&v| v != 0) || positive != negative {
        return Err(Error::Shape);
    }
    for tag in 0..45 {
        for at in 0..N {
            if producers[tag * N + at] != u8::from(tag != 40 || at < 512) {
                return Err(Error::Shape);
            }
        }
    }
    Ok(Inventory {
        gates,
        hashes,
        range_coefficients: 2 * H,
        public_coefficients: 8 * H,
        weighted_uses: positive,
        producers: producers.iter().map(|&v| usize::from(v)).sum(),
    })
}
