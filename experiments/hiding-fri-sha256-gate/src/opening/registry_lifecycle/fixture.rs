//! PUBLIC NONSECRET owner-side inputs, isolated from proof verification.
use super::{
    model::{Command, Operation, Registry},
    statement::{self, Expected, Phase},
    trace::Witness,
};
use crate::backend::{Error, Val};
use crate::opening::{
    Relation, commitment, fixture as source_fixture, statement as source, trace as source_trace,
};
use p3_field::PrimeCharacteristicRing;
pub(super) const GENESIS: [u8; 32] = [0xA7; 32];
pub(super) const PARENT: [u8; 32] = [0xB7; 32];
const KEY: [u8; 32] = [0x71; 32];
const KEY_SALT: [Val; 4] = [Val::ONE; 4];
const OPEN_SALT: [Val; 4] = [Val::TWO; 4];
pub(super) struct Fixture {
    pub source: source::Statement,
    pub source_witness: source_trace::Witness,
    pub witness: Witness,
}
impl Fixture {
    pub fn new() -> Result<Self, Error> {
        let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
        let suffix = source_fixture::canonical_suffix();
        let (source, source_witness) = source_fixture::from_suffix(
            Relation::CanonicalIndex,
            KEY,
            (KEY_SALT, OPEN_SALT),
            [0x83; 32],
            data,
            &suffix,
        )?;
        let mut plain = [0; 2348];
        plain[..12].copy_from_slice(&data);
        plain[12..124].copy_from_slice(&source.heads[0]);
        plain[124..].copy_from_slice(&suffix);
        let witness = Witness {
            plain,
            controllers: [[0x41; 32], [0x42; 32]],
            salts: [
                OPEN_SALT,
                [Val::from_u8(3); 4],
                [Val::from_u8(4); 4],
                [Val::from_u8(5); 4],
                [Val::from_u8(6); 4],
                [Val::from_u8(7); 4],
            ],
            old: Registry::default(),
            command: None,
        };
        Ok(Self {
            source,
            source_witness,
            witness,
        })
    }
    pub fn source(&self, query: [u8; 32]) -> source::Statement {
        let mut source = self.source.clone();
        source.request = query;
        source.open_commitment = commitment::digest(&commitment::opening_fields(
            &source,
            OPEN_SALT,
            &self.witness.plain,
        ));
        source
    }
    pub fn bootstrap(&self) -> Result<(Expected, Witness), Error> {
        let mut e = Expected::bootstrap(&self.source, GENESIS, PARENT, [0; 32])?;
        e.enrollment = commitment::digest(&statement::enrollment_fields(&e, &self.witness));
        Ok((e, self.witness.clone()))
    }
    pub fn transition(
        &self,
        state: Registry,
        command: Command,
        query: [u8; 32],
        parent: [u8; 32],
    ) -> Result<(Expected, Witness), Error> {
        command.require_shape()?;
        state.require_canonical()?;
        let source = self.source(query);
        let mut witness = self.witness.clone();
        witness.old = state;
        witness.command = Some(command);
        let (bootstrap, _) = self.bootstrap()?;
        let mut e = Expected::transition(
            &source,
            GENESIS,
            parent,
            statement::encoded(bootstrap.enrollment),
            [0; 32],
            [0; 32],
        )?;
        let old = statement::digest(&statement::registry_fields(
            &e,
            &witness,
            &witness.old,
            witness.salts[2],
        ));
        e.phase = Phase::Transition {
            old,
            command: [Val::ZERO; 4],
        };
        let command = statement::digest(&statement::command_fields(
            &e,
            &witness,
            witness.command.as_ref().unwrap(),
        ));
        e.phase = Phase::Transition { old, command };
        Ok((e, witness))
    }
    pub fn begin(&self) -> Result<(Expected, Witness), Error> {
        let mut old = self.witness.clone();
        old.salts[2] = old.salts[4];
        let command = Command::control(Operation::Begin, 1, 1, 0);
        let (mut e, mut w) = self.transition(Registry::default(), command, [0x84; 32], PARENT)?;
        w.salts[2] = old.salts[2];
        let root = statement::digest(&statement::registry_fields(&e, &w, &w.old, w.salts[2]));
        e.phase = Phase::Transition {
            old: root,
            command: [Val::ZERO; 4],
        };
        let cmd = statement::digest(&statement::command_fields(
            &e,
            &w,
            w.command.as_ref().unwrap(),
        ));
        e.phase = Phase::Transition {
            old: root,
            command: cmd,
        };
        Ok((e, w))
    }
}
