//! PUBLIC NONSECRET Source data/blinds. Actual Owner keys stay inside the real Core API.
use super::{Expected, compiler::CompiledPrivatePredicate, trace::Witness};
use crate::{
    backend::{Error, Val},
    opening::{fixture as source_fixture, statement as source, trace::Witness as SourceWitness},
};
use p3_field::PrimeCharacteristicRing;
use registry200_proof::{admission::CanonicalSource, coefficient_encoding::statement::BfvBinding};
use zeroize::Zeroizing;
pub(super) const SQL: &str = "SELECT age, amount FROM records WHERE age IN (0, 128, 255)";
pub(super) const DATA: [u8; 12] = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
pub(super) struct Fixture {
    pub source_statement: source::Statement,
    pub source_witness: SourceWitness,
    pub source: Expected,
    pub query: Expected,
    pub source_encoding: Witness,
    pub query_encoding: Witness,
}
pub(super) fn public_binding() -> BfvBinding {
    BfvBinding::new(
        [0x53; 32],
        bfv_key_transform::Statement {
            expected: bfv_key_transform::Expected {
                descriptor: bfv_key_transform::SetupDescriptor {
                    database: [0x44; 16],
                    key_domain: [0x71; 16],
                    public_setup_digest: [0x95; 32],
                    key_epoch: 1,
                },
                coefficients: [Val::ONE; 4],
            },
            transformed: [Val::ONE; 4],
        },
    )
}
pub(super) fn actual_binding() -> Result<BfvBinding, Error> {
    use bfv_query_core::{Geometry, KeyScope, Owner};
    let (owner, setup) = Owner::generate(Geometry::Rows16).map_err(|_| Error::Shape)?;
    let handle = owner
        .key_anchor(
            &setup,
            KeyScope {
                database: [0x44; 16],
                bfv_key_domain: [0x71; 16],
                epoch: 1,
            },
        )
        .map_err(|_| Error::Shape)?;
    let evidence = handle.prove().map_err(|_| Error::Shape)?;
    let checked = setup
        .verify_key_transform(handle.public_anchor(), evidence.as_bytes())
        .map_err(|_| Error::Verification)?;
    let binding = BfvBinding::new(
        handle.public_anchor().full_setup_id(),
        checked.statement().clone(),
    );
    drop(evidence);
    drop(handle);
    drop(owner);
    drop(setup);
    Ok(binding)
}
pub(super) fn prepare(
    sql: &str,
    blind: [u8; 32],
    nonce: [u8; 32],
    binding: BfvBinding,
    data: [u8; 12],
) -> Result<Fixture, Error> {
    prepare_with_suffix(
        sql,
        blind,
        nonce,
        binding,
        data,
        source_fixture::canonical_suffix(),
    )
}
pub(super) fn prepare_with_suffix(
    sql: &str,
    blind: [u8; 32],
    nonce: [u8; 32],
    binding: BfvBinding,
    data: [u8; 12],
    suffix: Vec<u8>,
) -> Result<Fixture, Error> {
    let compiled = CompiledPrivatePredicate::compile(sql, Zeroizing::new(blind), nonce)?;
    let open = [Val::from_u8(17); 4];
    let (mut source_statement, source_witness) = source_fixture::from_suffix(
        registry200_proof::source::Relation::CanonicalIndex,
        core::array::from_fn(|i| i as u8),
        ([Val::from_u8(11); 4], open),
        [0; 32],
        data,
        &suffix,
    )?;
    source_statement.request = compiled.query(&source_statement, &binding);
    let mut plain = data.to_vec();
    plain.extend(source_statement.heads[0]);
    plain.extend(suffix);
    source_statement.open_commitment = registry200_proof::source::commitment::digest(
        &registry200_proof::source::commitment::opening_fields(&source_statement, open, &plain),
    );
    let checked = CanonicalSource::checked_claim(&source_statement)?;
    let (source, query, mask) = compiled.bind(&checked, binding, [Val::from_u8(23); 4])?;
    let source_encoding = Witness::source(&source, Zeroizing::new(plain), [17; 4], [29; 4])?;
    let query_encoding = Witness::private_mask(&query, mask, [23; 4], [31; 4])?;
    Ok(Fixture {
        source_statement,
        source_witness,
        source,
        query,
        source_encoding,
        query_encoding,
    })
}
pub(super) fn shape() -> Result<Fixture, Error> {
    prepare(SQL, [0xB1; 32], [0xA1; 32], public_binding(), DATA)
}
pub(super) fn genuine() -> Result<Fixture, Error> {
    prepare(SQL, [0xB1; 32], [0xA1; 32], actual_binding()?, DATA)
}
