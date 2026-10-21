//! Streaming adapter over ORIGINAL Graph::row32. No NTT/gate math is copied.
use super::*;
use std::sync::Arc;

pub(super) struct Plan {
    pub(super) original: Descriptor,
    expected: Expected,
}
impl Plan {
    pub(super) fn new(expected: &Expected) -> Result<Self> {
        let original = Descriptor::new(ExpectedRef::Data(&expected.core))?;
        if original.kind != RelationKind::Data
            || original.values.len() != PV
            || GRAPH_ROWS != 1438
            || CW_FIRST != 1438
            || CS_FIRST != 1952
            || HASH_END != 2030
            || H != 2048
            || GATES != original.kind.graph_rows() * graph::SLOTS
            || PORTS != 248
            || super::super::super::geometry::N != 4096
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            original,
            expected: expected.clone(),
        })
    }
    pub(super) fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
    #[cfg(test)]
    pub(super) fn gate(&self, index: usize) -> Result<Option<graph::Gate>> {
        if index >= GRAPH_ROWS * SLOTS {
            return Err(Error::Shape);
        }
        if index >= GATES {
            return Ok(None);
        }
        Ok(Some(
            self.original.graph.row(index / graph::SLOTS)?.gates[index % graph::SLOTS],
        ))
    }
    pub(super) fn row(&self, index: usize) -> Result<[Val; PP]> {
        if index >= H {
            return Err(Error::Shape);
        }
        let mut p = [Val::ZERO; PP];
        if index < 128 {
            p[MASK_ACTIVE] = Val::ONE;
            p[MASK_RESET] = Val::from_bool(index.is_multiple_of(16));
            p[MASK_EMIT] = Val::from_bool(index % 16 == 15);
            p[MASK_POWER] = Val::from_u64(1 << (30 - 2 * (index % 16)));
            if index % 16 == 15 {
                p[WORD_PORT] = Val::from_u64(old_pp::node(41, 7 - index / 16)?);
            }
        }
        p[FLAGS + old_pp::RANGE] = Val::ONE;
        p[FLAGS + old_pp::RESET] = Val::from_bool(index.is_multiple_of(4));
        p[FLAGS + old_pp::EMIT] = Val::from_bool(index % 4 == 3);
        p[POWER] = Val::from_u64(1u64 << (12 * (index % 4)));
        // Every physical row contains two complete range coefficients, including
        // the five range-only tail rows. No coefficient is clamped or omitted.
        let range = RelationKind::Data.range();
        for k in 0..2 {
            let at = 2 * index + k;
            let base = GRAPH_PORTS + k * range.stride;
            p[base] = Val::from_u64(old_pp::node(0, at)?);
            p[base + range.w] = Val::from_u64(old_pp::node(RelationKind::Data.w_tag(0), at)?);
            for job in 0..2 {
                p[base + range.product + job] =
                    Val::from_u64(old_pp::node(RelationKind::Data.final_vector(job), at)?);
                p[RANGE_C0 + 2 * k + job] = Val::from_u64(self.original.c0[job][at]);
            }
        }
        if index % 4 == 3 {
            p[GRAPH_PORTS + 18] =
                Val::from_u64(old_pp::node(RelationKind::Data.cs_tag(), index / 4)?)
        }
        if index < GRAPH_ROWS {
            p[FLAGS + old_pp::ARITH] = Val::ONE;
            // Cache each original 32-gate row while consuming the 56-gate dense row.
            let mut cached = None;
            let mut cache_index = usize::MAX;
            for slot in 0..SLOTS {
                let gate_index = index * SLOTS + slot;
                if gate_index >= GATES {
                    continue;
                }
                let source = gate_index / graph::SLOTS;
                if source != cache_index {
                    cached = Some(self.original.graph.row(source)?);
                    cache_index = source
                }
                let gate = &cached.as_ref().ok_or(Error::Shape)?.gates[gate_index % graph::SLOTS];
                p[ACTIVE + slot] = Val::ONE;
                let point =
                    (graph::FORWARD_GATES..graph::FORWARD_GATES + 2 * 4096).contains(&gate_index);
                let fanout =
                    (graph::FORWARD_GATES - 2048..graph::FORWARD_GATES).contains(&gate_index);
                p[POINTWISE + slot] = Val::from_bool(point);
                p[FANOUT + slot] = Val::from_bool(fanout);
                let want = if fanout {
                    [2, 2]
                } else if point {
                    [1, 0]
                } else {
                    [1, 1]
                };
                if gate.output_uses != want {
                    return Err(Error::Shape);
                }
                for (port, node) in gate.inputs.iter().chain(&gate.outputs).enumerate() {
                    if let Some(node) = node {
                        p[4 * slot + port] = Val::from_u64(node.id())
                    }
                }
                for (at, &v) in gate.linear.iter().flatten().enumerate() {
                    p[COEFFICIENTS + 4 * slot + at] = Val::from_u64(v)
                }
            }
        } else if index < STMT_FIRST {
            let (role, start, length, tag, flag) = if index < CS_FIRST {
                (
                    0,
                    CW_FIRST,
                    514,
                    RelationKind::Data.w_tag(0),
                    old_pp::SOURCE,
                )
            } else {
                (1, CS_FIRST, 66, RelationKind::Data.cs_tag(), old_pp::CS)
            };
            let block = index - start;
            for flag in [old_pp::HASH, flag] {
                p[FLAGS + flag] = Val::ONE
            }
            p[FLAGS + old_pp::FIRST] = Val::from_bool(block == 0);
            p[FLAGS + old_pp::LAST] = Val::from_bool(block + 1 == length);
            p[FLAGS + old_pp::CONTEXT] = Val::from_bool(block == 0);
            p[FLAGS + old_pp::SALT] = Val::from_bool(block == 1);
            p[FLAGS + old_pp::PAYLOAD] = Val::from_bool(block >= 2);
            p[CONTEXT..CONTEXT + 8].copy_from_slice(&self.original.contexts[role]);
            p[ROOT..ROOT + 4].copy_from_slice(&self.original.roots[role]);
            if block >= 2 {
                for (at, out) in p.iter_mut().take(8).enumerate() {
                    *out = Val::from_u64(old_pp::node(tag, 8 * (block - 2) + at)?)
                }
            }
        }
        if (STMT_FIRST..HASH_END).contains(&index) {
            let block = index - STMT_FIRST;
            p[FLAGS + old_pp::HASH] = Val::ONE;
            p[FLAGS + old_pp::MASK] = Val::ONE;
            p[FLAGS + old_pp::FIRST] = Val::from_bool(block == 0);
            p[FLAGS + old_pp::LAST] = Val::from_bool(block == 11);
            p[ROOT..ROOT + 4].copy_from_slice(&self.expected.statement);
            for lane in 0..8 {
                let word = 8 * block + lane;
                if word < 13 || word == 95 {
                    p[FIXED + lane] = Val::ONE;
                    p[FIXED_VALUE + lane] = if word < 13 {
                        self.expected.header[word]
                    } else {
                        Val::ZERO
                    };
                }
                if (78..86).contains(&word) {
                    p[lane] = Val::from_u64(old_pp::node(41, word - 78)?);
                    p[STMT_LOOKUP + lane] = Val::ONE;
                }
            }
        }
        Ok(p)
    }
}

/// Exact verifier-owned signed count for every occurrence, including duplicate reads.
pub(super) fn count(p: &[Val; PP], port: usize) -> Result<i32> {
    if port >= PORTS {
        return Err(Error::Shape);
    }
    let flag = |i: usize| p[FLAGS + i].as_canonical_u64() as i32;
    if port < GRAPH_PORTS {
        let slot = port / 4;
        let active = p[ACTIVE + slot].as_canonical_u64() as i32;
        let point = p[POINTWISE + slot].as_canonical_u64() as i32;
        let fanout = p[FANOUT + slot].as_canonical_u64() as i32;
        let n = match port % 4 {
            0 => -active,
            1 => -active + point,
            2 => active + fanout,
            3 => active - point + fanout,
            _ => return Err(Error::Shape),
        };
        Ok(n - if port < 8 {
            flag(old_pp::PAYLOAD) + p[STMT_LOOKUP + port].as_canonical_u64() as i32
        } else {
            0
        })
    } else if port == WORD_PORT {
        Ok(p[MASK_EMIT].as_canonical_u64() as i32)
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
    pub(super) hash_rows: usize,
    pub(super) coefficients: usize,
    pub(super) positive_uses: usize,
    pub(super) negative_uses: usize,
    pub(super) producers: usize,
}
impl Plan {
    pub(super) fn inventory(&self) -> Result<Inventory> {
        let n = 4096;
        let cs = RelationKind::Data.cs_tag();
        let mut balance = vec![0i32; 42 * n];
        let mut producers = vec![0u8; 42 * n];
        let mut active = 0;
        let mut hashes = 0;
        let mut coefficients = 0;
        let mut positive = 0;
        let mut negative = 0;
        for row in 0..H {
            let p = self.row(row)?;
            if p[FLAGS + old_pp::RANGE] != Val::ONE {
                return Err(Error::Shape);
            }
            coefficients += 2;
            for slot in 0..SLOTS {
                active += usize::try_from(p[ACTIVE + slot].as_canonical_u64())
                    .map_err(|_| Error::Shape)?
            }
            hashes += usize::try_from(p[FLAGS + old_pp::HASH].as_canonical_u64())
                .map_err(|_| Error::Shape)?;
            if row >= GRAPH_ROWS && p[ACTIVE..ACTIVE + SLOTS].iter().any(|&x| x != Val::ZERO) {
                return Err(Error::Shape);
            }
            for port in 0..PORTS {
                let count = count(&p, port)?;
                if count.abs() > 4 {
                    return Err(Error::Shape);
                }
                if count == 0 {
                    continue;
                }
                let id = p[port].as_canonical_u64();
                if id == 0 {
                    return Err(Error::Shape);
                }
                let tag = ((id - 1) / 65536) as usize;
                let at = ((id - 1) % 65536) as usize;
                if tag > 41
                    || at >= n
                    || (tag == cs && at >= 512)
                    || (tag == 41 && at >= 8)
                    || old_pp::node(tag, at)? != id
                {
                    return Err(Error::Shape);
                }
                let cell = tag * n + at;
                balance[cell] = balance[cell].checked_add(count).ok_or(Error::Resource)?;
                if count > 0 {
                    producers[cell] = producers[cell].checked_add(1).ok_or(Error::Shape)?;
                    positive += count as usize
                } else {
                    negative += (-count) as usize
                }
            }
        }
        if active != GATES
            || hashes != 592
            || coefficients != n
            || balance.iter().any(|&x| x != 0)
            || positive != negative
        {
            return Err(Error::Shape);
        }
        let mut producer_count = 0;
        for tag in 0..42 {
            for at in 0..n {
                let want = u8::from(tag < cs || (tag == cs && at < 512) || (tag == 41 && at < 8));
                if producers[tag * n + at] != want {
                    return Err(Error::Shape);
                }
                producer_count += usize::from(want)
            }
        }
        Ok(Inventory {
            gates: active,
            hash_rows: hashes,
            coefficients,
            positive_uses: positive,
            negative_uses: negative,
            producers: producer_count,
        })
    }
}
