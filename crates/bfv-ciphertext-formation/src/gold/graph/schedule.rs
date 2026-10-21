//! Single static FFT schedule. It owns no request, ciphertext, Expected or private data.
//! The original Plan resolves typed pointwise slots with its unchanged public A table.
use super::{
    Error, FORWARD_GATES, GOLD, Gate, N, Node, Result, STAGES, fft, neg, powers, reverse, twiddles,
};
use crate::gold::relation::RelationKind;

pub(in crate::gold) struct Schedule {
    kind: RelationKind,
    forward: [Vec<u64>; STAGES],
    inverse: [Vec<u64>; STAGES],
    twist: Vec<u64>,
    normalize: Vec<u64>,
}
pub(in crate::gold) enum ScheduledGate {
    Butterfly(Gate),
    Pointwise(Pointwise),
}
pub(in crate::gold) struct Pointwise {
    pub(in crate::gold) input: Node,
    pub(in crate::gold) output: Node,
    pub(in crate::gold) job: usize,
    pub(in crate::gold) coefficient: usize,
}
impl Schedule {
    pub(in crate::gold) fn new(kind: RelationKind) -> Result<Self> {
        if N != 4096 || !matches!(kind.products(), 2 | 4) {
            return Err(Error::Shape);
        }
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
        Ok(Self {
            kind,
            forward,
            inverse,
            twist,
            normalize,
        })
    }
    pub(in crate::gold) fn gate(&self, index: usize) -> Result<ScheduledGate> {
        if index >= self.kind.graph_rows() * super::SLOTS {
            return Err(Error::Shape);
        }
        if index < FORWARD_GATES {
            return Ok(ScheduledGate::Butterfly(self.butterfly(None, index)?));
        }
        let index = index - FORWARD_GATES;
        if index < self.kind.products() * N {
            let job = index / N;
            let at = index % N;
            return Ok(ScheduledGate::Pointwise(Pointwise {
                input: Node::new(12, at)?,
                output: Node::new(13 + job, at)?,
                job,
                coefficient: at,
            }));
        }
        let index = index - self.kind.products() * N;
        Ok(ScheduledGate::Butterfly(self.butterfly(
            Some(index / FORWARD_GATES),
            index % FORWARD_GATES,
        )?))
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
                    13 + self.kind.products() + job * STAGES + stage - 1
                },
                13 + self.kind.products() + job * STAGES + stage,
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
            self.kind.products() as u8
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
}
