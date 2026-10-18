//! Exact query-dependent routing. Verifier calls no arithmetic evaluator here.
use crate::{COEFFICIENTS, COMPONENTS, DEGREE, Error, Input, PreparedKey, Result};
use bfv_ntt_circuit::{Basis, Direction};
use bfv_relinearization_circuit::Role;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stage {
    pub ordinal: usize,
    pub kind: u8,
    pub source: u8,
    pub target: u8,
}
impl Stage {
    pub fn at(ordinal: usize) -> Result<Self> {
        let (kind, source, target) = match ordinal {
            0..=4 => (1, 2, ordinal as u8),
            5 => (2, 255, 255),
            6..=30 => (3, ((ordinal - 6) / 5) as u8, ((ordinal - 6) % 5) as u8),
            31 => (4, 255, 255),
            _ => return Err(Error::Stage),
        };
        Ok(Self {
            ordinal,
            kind,
            source,
            target,
        })
    }
    pub fn metadata(self) -> [u8; 4] {
        [self.ordinal as u8, self.kind, self.source, self.target]
    }
    pub fn output_bytes(self) -> usize {
        match self.kind {
            1 | 3 => Direction::Forward.output_bytes(),
            2 => Role::Embed.output_bytes(),
            4 => Role::AccumulateAndAdd.output_bytes(),
            _ => unreachable!("sealed stage"),
        }
    }
}
pub(crate) enum Request {
    Ntt(bfv_ntt_circuit::Request),
    Relin(bfv_relinearization_circuit::Request),
}
pub(crate) struct State {
    next: usize,
    cancelled: bool,
    inverse: Vec<u64>,
    embedded: Vec<u64>,
    digits: Vec<u64>,
    result: Option<[Vec<u64>; 2]>,
}
impl State {
    pub fn new() -> Self {
        Self {
            next: 0,
            cancelled: false,
            inverse: Vec::new(),
            embedded: Vec::new(),
            digits: Vec::new(),
            result: None,
        }
    }
    pub fn progress(&self) -> usize {
        self.next
    }
    pub fn next(&self) -> Result<Option<Stage>> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if self.next == COMPONENTS {
            return Ok(None);
        }
        Ok(Some(Stage::at(self.next)?))
    }
    pub fn request(&self, key: &PreparedKey, input: &Input, identity: [u8; 64]) -> Result<Request> {
        let stage = self.next()?.ok_or(Error::Stage)?;
        let binding = crate::profile::stage_binding(identity, stage.metadata());
        match stage.kind {
            1 => {
                let target = usize::from(stage.target);
                let original = input.component(2).ok_or(Error::Shape)?;
                let bytes = bfv_ntt_circuit::encode_request(
                    Direction::Inverse,
                    Basis::new(stage.target)?,
                    binding,
                    &original[target * DEGREE..(target + 1) * DEGREE],
                )?;
                Ok(Request::Ntt(bfv_ntt_circuit::decode_request(&bytes)?))
            }
            2 => {
                let bytes = bfv_relinearization_circuit::encode_request(
                    Role::Embed,
                    binding,
                    key.keyset_id(),
                    &self.inverse,
                )?;
                Ok(Request::Relin(bfv_relinearization_circuit::decode_request(
                    &bytes,
                )?))
            }
            3 => {
                let row = 5 * usize::from(stage.source) + usize::from(stage.target);
                let bytes = bfv_ntt_circuit::encode_request(
                    Direction::Forward,
                    Basis::new(stage.target)?,
                    binding,
                    &self.embedded[row * DEGREE..(row + 1) * DEGREE],
                )?;
                Ok(Request::Ntt(bfv_ntt_circuit::decode_request(&bytes)?))
            }
            4 => {
                // ALL query-dependent digits come from the 25 preceding proven
                // outputs. ALL key values are the verifier's own setup constants.
                if self.digits.len() != 25 * DEGREE {
                    return Err(Error::Stage);
                }
                let mut values = Vec::with_capacity(85 * DEGREE);
                for target in 0..5 {
                    for component in 0..2 {
                        let original = input.component(component).ok_or(Error::Shape)?;
                        values.extend_from_slice(&original[target * DEGREE..(target + 1) * DEGREE]);
                    }
                    for source in 0..5 {
                        let row = 5 * source + target;
                        values.extend_from_slice(&self.digits[row * DEGREE..(row + 1) * DEGREE]);
                    }
                    for keys in [&key.c0, &key.c1] {
                        for row in keys {
                            values.extend_from_slice(&row[target * DEGREE..(target + 1) * DEGREE]);
                        }
                    }
                }
                let bytes = bfv_relinearization_circuit::encode_request(
                    Role::AccumulateAndAdd,
                    binding,
                    key.keyset_id(),
                    &values,
                )?;
                Ok(Request::Relin(bfv_relinearization_circuit::decode_request(
                    &bytes,
                )?))
            }
            _ => Err(Error::Stage),
        }
    }
    /// Called only after successful proof generation, or actual verifier admission.
    /// No Result error occurs after a partial append/ordinal advance.
    pub fn apply(&mut self, stage: Stage, values: &[u64]) -> Result<()> {
        if self.next()? != Some(stage) {
            return Err(Error::Stage);
        }
        let count = match stage.kind {
            1 | 3 => DEGREE,
            2 => 25 * DEGREE,
            4 => 2 * COEFFICIENTS,
            _ => return Err(Error::Stage),
        };
        if values.len() != count {
            return Err(Error::Shape);
        }
        match stage.kind {
            1 => self.inverse.extend_from_slice(values),
            2 => {
                self.embedded = values.to_vec();
                self.inverse = Vec::new();
            }
            3 => {
                self.digits.extend_from_slice(values);
                if stage.ordinal == 30 {
                    self.embedded = Vec::new();
                }
            }
            4 => {
                let mut output: [Vec<u64>; 2] =
                    core::array::from_fn(|_| Vec::with_capacity(COEFFICIENTS));
                for (component, out) in output.iter_mut().enumerate() {
                    for target in 0..5 {
                        let row = 2 * target + component;
                        out.extend_from_slice(&values[row * DEGREE..(row + 1) * DEGREE]);
                    }
                }
                self.result = Some(output);
                self.digits = Vec::new();
            }
            _ => return Err(Error::Stage),
        }
        self.next += 1;
        Ok(())
    }
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.inverse = Vec::new();
        self.embedded = Vec::new();
        self.digits = Vec::new();
        self.result = None;
    }
    pub fn finish(self) -> Result<[Vec<u64>; 2]> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        if self.next != COMPONENTS {
            return Err(Error::Incomplete);
        }
        self.result.ok_or(Error::Incomplete)
    }
}
