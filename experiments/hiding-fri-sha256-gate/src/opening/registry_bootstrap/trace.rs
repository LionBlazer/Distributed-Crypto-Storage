//! Owner-local opening witness. Never a public registry/controller exporter.
use super::{
    air::{self, *},
    statement::{self, Expected, Statement},
};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::opening::{
    locking::trace::{Registry, Transaction},
    poseidon,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone)]
pub(in crate::opening) struct Witness {
    pub(super) plain: [u8; 2348],
    pub(super) controllers: [[u8; 32]; 2],
    /// Source-opening, enrollment and registry salts, independently sampled.
    pub(super) salts: [[Val; 4]; 3],
}
pub(super) fn bits(out: &mut [Val], value: u64) {
    for (i, bit) in out.iter_mut().enumerate() {
        *bit = Val::from_bool(value & (1 << i) != 0);
    }
}
impl Witness {
    /// Owner-local producer input; no private material is returned publicly.
    pub(in crate::opening) fn new(
        plain: [u8; 2348],
        controllers: [[u8; 32]; 2],
        salts: [[Val; 4]; 3],
    ) -> Result<Self, Error> {
        if controllers.contains(&[0; 32]) {
            return Err(Error::Shape);
        }
        Ok(Self {
            plain,
            controllers,
            salts,
        })
    }
    /// Computes an enrollment anchor before the query-dependent C_open exists.
    pub(in crate::opening) fn enrollment(
        &self,
        source: &crate::opening::statement::Statement,
        genesis: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        let e = Expected::checked(source, genesis, [0; 32], [0; 32])?;
        Ok(crate::opening::locking::statement::encoded(
            crate::opening::commitment::digest(&statement::enrollment_fields(&e, self)),
        ))
    }
    pub(super) fn table(&self) -> [u8; 32] {
        self.plain[124..156].try_into().unwrap()
    }
    pub(super) fn registry(&self) -> Registry {
        Registry {
            revision: 2,
            tx: core::array::from_fn(|t| Transaction {
                id: t as u32 + 1,
                controller: self.controllers[t],
                sequence: 1,
                failed: false,
                held: [0; 4],
            }),
        }
    }
    pub(in crate::opening) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        s.expected.require_contract()?;
        let air = air::BootstrapAir::new(s);
        let mut bank = vec![Val::ZERO; WIDTH];
        for (word, value) in self.table().as_chunks::<4>().0.iter().enumerate() {
            bank[TABLE + word] = Val::from_u32(u32::from_le_bytes(*value));
        }
        for (word, value) in self.plain[2220..2348].as_chunks::<4>().0.iter().enumerate() {
            bank[IDS + word] = Val::from_u32(u32::from_le_bytes(*value));
        }
        for (t, controller) in self.controllers.iter().enumerate() {
            for (i, byte) in controller.iter().enumerate() {
                bits(
                    &mut bank[CONTROLLERS + 256 * t + 8 * i..CONTROLLERS + 256 * t + 8 * i + 8],
                    u64::from(*byte),
                );
            }
            let count = Val::from_u32(controller.iter().map(|b| b.count_ones()).sum());
            bank[INVERSES + t] = if count == Val::ZERO {
                Val::ZERO
            } else {
                count.inverse()
            };
        }
        for (i, salt) in self.salts.iter().enumerate() {
            bank[SALTS + 4 * i..SALTS + 4 * (i + 1)].copy_from_slice(salt);
        }
        let mut values = vec![Val::ZERO; WIDTH * TRACE_HEIGHT];
        let mut checkpoint = [Val::ZERO; 12];
        for (physical, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            row.copy_from_slice(&bank);
            if physical < 85 {
                for slot in 0..8 {
                    let field = physical * 8 + slot;
                    if (87..674).contains(&field) {
                        let at = 4 * (field - 87);
                        bits(
                            &mut row[WORDS + 32 * slot..WORDS + 32 * (slot + 1)],
                            u64::from(u32::from_le_bytes(
                                self.plain[at..at + 4].try_into().unwrap(),
                            )),
                        );
                    }
                }
            }
            row[CHECKPOINT..WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = absorb(physical) {
                for (slot, value) in input[..8].iter_mut().enumerate() {
                    *value = air.field(row, stream, block * 8 + slot, slot);
                }
                if !reset(physical) {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = poseidon::write(&mut row[..CHECKPOINT], input);
            if absorb(physical).is_some() {
                checkpoint = output;
            }
        }
        Ok(RowMajorMatrix::new(values, WIDTH))
    }
    pub(in crate::opening) fn statement(&self, expected: &Expected) -> Result<Statement, Error> {
        statement::proposed(expected, self)
    }
}
