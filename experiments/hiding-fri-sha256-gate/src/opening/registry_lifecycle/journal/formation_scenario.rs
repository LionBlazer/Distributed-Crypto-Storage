//! PUBLIC NONSECRET real signed history exercised by the formation gate and owning consumer tests.
use super::super::{
    encoding,
    model::{Command, Operation},
};
use super::{fixture::Fixture, owner::PrivateState};
use crate::backend::{Error, Val};
use p3_field::PrimeCharacteristicRing;
use version_journal::{Body, Journal, TransitionVerifier};
pub(in crate::opening::registry_lifecycle) struct EncodingProduct {
    pub statement: encoding::Statement,
    pub frame: Vec<u8>,
    pub opening: bfv_ciphertext_formation::EncodedOpening,
    pub coefficients: zeroize::Zeroizing<Vec<u64>>,
    #[cfg(test)]
    pub alternate: Option<(encoding::Statement, Vec<u8>)>,
}
pub(super) fn append(
    journal: &mut Journal,
    verifier: &impl TransitionVerifier,
    parent: [u8; 32],
    body: &Body,
    timestamp: u64,
) -> version_journal::Result<version_journal::Header> {
    let header = super::fixture::candidate(journal, parent, body, timestamp)?;
    journal.import_block(
        header.clone(),
        &body.encode(journal.profile())?,
        10000,
        verifier,
    )?;
    Ok(header)
}
pub(in crate::opening::registry_lifecycle) fn produce(limit: u8) -> Result<EncodingProduct, Error> {
    produce_inner(limit, None)
}
#[cfg(test)]
pub(super) fn produce_with_alternate(limit: u8) -> Result<EncodingProduct, Error> {
    produce_inner(limit, Some([Val::from_u8(34); 4]))
}
fn produce_inner(limit: u8, alternate_salt: Option<[Val; 4]>) -> Result<EncodingProduct, Error> {
    #[cfg(not(test))]
    if alternate_salt.is_some() {
        return Err(Error::Shape);
    }
    let f = Fixture::new().map_err(|_| Error::Shape)?;
    let verifier = f.verifier().map_err(|_| Error::Shape)?;
    let mut journal = Journal::new(f.genesis.clone()).map_err(|_| Error::Shape)?;
    let parent = journal.genesis_head();
    let boot = f
        .bootstrap(&journal, parent, [0xF1; 32])
        .map_err(|_| Error::Verification)?;
    append(&mut journal, &verifier, parent.block, &boot.body, 1001)
        .map_err(|_| Error::Verification)?;
    let private = boot.private;
    drop(boot.body);
    let parent = journal.best_validated();
    let begin = f
        .transition(
            &journal,
            parent,
            &private,
            Command::control(Operation::Begin, 1, 1, 0),
            [0xF2; 32],
        )
        .map_err(|_| Error::Verification)?;
    append(&mut journal, &verifier, parent.block, &begin.body, 1002)
        .map_err(|_| Error::Verification)?;
    let PrivateState { registry, salt } = begin.private;
    drop(begin.body);
    let mut command = Command::control(Operation::Acquire, 1, 1, 1);
    command.mask = [255; 32];
    command.mode = 4;
    command.wait = 2;
    command.limit = limit;
    command.projection = 2;
    let parent = journal.best_validated();
    #[cfg(test)]
    if alternate_salt.is_some() {
        let before = journal.best_validated();
        let headers = journal.header_count();
        let wrong = f
            .prepare(
                &journal,
                parent,
                &PrivateState {
                    registry: registry.clone(),
                    salt,
                },
                command.clone(),
                [0xF3; 32],
            )
            .unwrap();
        let wrong_sql =
            format!("SELECT amount FROM records WHERE age>=0 LIMIT {limit} FOR SHARE SKIP LOCKED");
        assert!(
            wrong
                .prove_formation_encoding(super::owner::FormationEncodingRequest {
                    journal: &mut journal,
                    verifier: &verifier,
                    genesis: &f.genesis,
                    owner: &Fixture::owner(),
                    sql: &wrong_sql,
                    sql_nonce: [0xF4; 32],
                    salt: [Val::from_u8(33); 4],
                    alternate_salt: None,
                    timestamp: 1003
                })
                .is_err()
        );
        assert_eq!(journal.best_validated(), before);
        assert_eq!(journal.header_count(), headers);
    }
    let prepared = f
        .prepare(
            &journal,
            parent,
            &PrivateState { registry, salt },
            command,
            [0xF3; 32],
        )
        .map_err(|_| Error::Shape)?;
    let sql =
        format!("SELECT amount FROM records WHERE age>=0 LIMIT {limit} FOR UPDATE SKIP LOCKED");
    prepared
        .prove_formation_encoding(super::owner::FormationEncodingRequest {
            journal: &mut journal,
            verifier: &verifier,
            genesis: &f.genesis,
            owner: &Fixture::owner(),
            sql: &sql,
            sql_nonce: [0xF4; 32],
            salt: [Val::from_u8(33); 4],
            #[cfg(test)]
            alternate_salt,
            timestamp: 1003,
        })
        .map_err(|_| Error::Verification)
}
