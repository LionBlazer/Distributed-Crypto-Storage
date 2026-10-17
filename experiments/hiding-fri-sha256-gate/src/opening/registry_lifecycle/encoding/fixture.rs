//! PUBLIC NONSECRET conditional cryptographic statement, not accepted Journal history.
use super::super::{
    fixture::Fixture as ParentFixture,
    model::{Command, Operation, Registry},
    statement as lifecycle,
    trace::Witness as ParentWitness,
};
use super::{
    CommandOpening, CompiledQuery,
    statement::{Expected, Statement},
    trace::Witness,
};
use crate::backend::{Error, Val};
use crate::primitive::PublicStatement;
use p3_field::PrimeCharacteristicRing;
pub(super) struct Fixture {
    pub source: ParentFixture,
    pub parent: lifecycle::Expected,
    pub parent_witness: ParentWitness,
    pub expected: Expected,
    pub statement: Statement,
    pub witness: Witness,
}
pub(super) const SQL: &str =
    "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED";
impl Fixture {
    pub(super) fn new(limit: u8) -> Result<Self, Error> {
        let source = ParentFixture::new()?;
        let first = Registry::default()
            .step(
                &Command::control(Operation::Begin, 1, 1, 0),
                super::super::fixture::PARENT,
                [255, 0, 255, 128],
            )?
            .next;
        let mut old = first
            .step(
                &Command::control(Operation::Begin, 2, 2, 0),
                super::super::fixture::PARENT,
                [255, 0, 255, 128],
            )?
            .next;
        old.transactions[1].held[0] = 4;
        let query = [0xC3; 32];
        let sql = SQL.replace("LIMIT 1", &format!("LIMIT {limit}"));
        let compiled = CompiledQuery::compile(&sql, [0xC4; 32], query)?;
        let opening = CommandOpening {
            transaction: 1,
            principal: 1,
            controller: source.witness.controllers[0],
            revision: old.revision,
            sequence: 1,
            salt: source.witness.salts[3],
        };
        let command = compiled.command(&opening)?;
        let (parent, parent_witness) =
            source.transition(old, command, query, super::super::fixture::PARENT)?;
        let producer = parent_witness.statement(&parent)?;
        let expected = compiled.bind(&parent, &producer, opening)?;
        let witness = Witness::from_parent(&expected, &parent_witness, [Val::from_u8(9); 4])?;
        let statement = witness.statement(expected.clone());
        Ok(Self {
            source,
            parent,
            parent_witness,
            expected,
            statement,
            witness,
        })
    }
}
pub(super) fn gate(mode: &str) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    let (expected, statement, bytes, sizes, generation_ms) = {
        let f = Fixture::new(1)?;
        crate::security(
            &f.parent.source,
            "public-nonsecret-registry200-encoding-source",
        )?;
        crate::security(
            &f.expected.producer,
            "public-nonsecret-registry200-encoding-lifecycle",
        )?;
        crate::security(
            &f.statement,
            "public-nonsecret-registry200-result144-encoding",
        )?;
        if mode == "security" {
            return Ok(());
        }
        let start = std::time::Instant::now();
        let (_, parent) =
            super::super::prove(&f.parent, &f.source.source_witness, &f.parent_witness)?;
        let bytes = super::prove_and_encode(
            &f.expected,
            &f.parent_witness,
            &parent,
            f.witness.encoding_salt,
        )?;
        let generation_ms = start.elapsed().as_secs_f64() * 1000.0;
        let frame = super::frame::Frame::parse(&bytes)?;
        let sizes = frame.parts.map(<[u8]>::len);
        (f.expected, f.statement, bytes, sizes, generation_ms)
    };
    let start = std::time::Instant::now();
    let fresh = super::decode_and_verify(&expected, &bytes)?;
    if fresh.public_values() != statement.public_values() {
        return Err(Error::Shape);
    }
    println!(
        "{{\"stage\":\"verified_registry200_encoding_evidence\",\"generation_ms\":{generation_ms},\"fresh_decode_verify_ms\":{},\"source_proof_bytes\":{},\"lifecycle_proof_bytes\":{},\"encoding_proof_bytes\":{},\"frame_bytes\":{},\"live_sql_grant\":false,\"formed_ciphertext\":false,\"agreed_finality\":false}}",
        start.elapsed().as_secs_f64() * 1000.0,
        sizes[0],
        sizes[1],
        sizes[2],
        bytes.len()
    );
    Ok(())
}
