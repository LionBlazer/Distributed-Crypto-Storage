//! Owner-side real Journal-to-WriteImage preparation. No mutation admission is added.
use super::super::{
    model::{Command, Operation, Registry, Transaction},
    statement as lifecycle,
    write::{
        self,
        compiler::{ActorOpening, CompiledWrite},
        frame,
        statement::{Expected, Parent, Statement},
        trace::{self, Witness},
    },
};
use super::{
    Application, Control,
    fixture::{self, Fixture},
    owner::PrivateState,
};
use crate::{
    backend::{Error, Val},
    opening::statement as source,
};
use p3_field::PrimeCharacteristicRing;
use registry200_proof::admission::CanonicalSource;
use std::time::Instant;
use version_journal::{HeadRef, Journal};
fn vj<T>(x: version_journal::Result<T>) -> Result<T, Error> {
    x.map_err(|_| Error::Shape)
}
pub(in crate::opening::registry_lifecycle) struct Request<'a> {
    pub sql: &'a str,
    pub nonce: [u8; 32],
    pub transaction: u64,
    pub principal: u8,
}
fn prepare(
    f: &Fixture,
    journal: &Journal,
    parent: HeadRef,
    private: &PrivateState,
    r: Request<'_>,
) -> Result<(Expected, Witness), Error> {
    vj(f.application.require_genesis(journal.genesis()))?;
    if parent.genesis != journal.genesis_id()
        || parent.database != f.application.database
        || !(1..=2).contains(&r.principal)
    {
        return Err(Error::Shape);
    }
    let heads = vj(f.application.control(vj(journal.validated_shards(parent))?))?;
    let Control::Active {
        enrollment,
        registry,
    } = vj(Control::decode(&f.application, heads))?
    else {
        return Err(Error::Shape);
    };
    let context = Parent {
        genesis: parent.genesis,
        application: f.application.id(),
        block: parent.block,
        enrollment,
        registry,
    };
    let compiled = CompiledWrite::compile(r.sql, r.nonce)?;
    let query = compiled.query(&context);
    let source = f.source.source(query);
    vj(f.application.require_source(&source))?;
    let canonical = CanonicalSource::checked_claim(&source)?;
    let mut opening = f.source.witness.clone();
    opening.old = private.registry.clone();
    opening.salts[2] = private.salt;
    opening.command = None;
    let draft = Expected::checked(&canonical, context.clone(), compiled.identity(), [0; 32])?;
    // Externally validated C_old and C_enroll are matched before ANY new command hash or trace.
    trace::require_parent_openings(&draft, &opening)?;
    let actor = opening
        .old
        .transactions
        .iter()
        .find(|tx| tx.id == r.transaction)
        .ok_or(Error::Shape)?;
    let actor = ActorOpening {
        transaction: r.transaction,
        principal: r.principal,
        controller: opening.controllers[usize::from(r.principal - 1)],
        revision: opening.old.revision,
        sequence: actor.sequence,
        salt: [Val::from_u8(19); 4],
    };
    let (expected, command) = compiled.bind(&canonical, context, actor)?;
    let witness = Witness {
        opening,
        command,
        image_salt: [Val::from_u8(23); 4],
    };
    let _ = witness.statement(&expected)?;
    Ok((expected, witness))
}
/// Public evidence and actual public history only; all private preparation was dropped.
pub(in crate::opening::registry_lifecycle) struct Product {
    pub expected: Expected,
    pub statement: Statement,
    pub frame: Vec<u8>,
    pub journal: Journal,
    pub application: Application,
    pub generation_ms: f64,
    pub write_generation_ms: f64,
    pub fresh_verification_ms: f64,
    pub body_bytes: [usize; 3],
}
pub(in crate::opening::registry_lifecycle) fn produce(
    sql: &str,
    nonce: [u8; 32],
) -> Result<Product, Error> {
    let full = Instant::now();
    let f = vj(Fixture::new())?;
    let verifier = vj(f.verifier())?;
    let mut journal = vj(Journal::new(f.genesis.clone()))?;
    let mut private = None;
    let mut body_bytes = [0; 3];
    for (index, body_size) in body_bytes.iter_mut().enumerate() {
        let parent = journal.best_validated();
        let produced = if index == 0 {
            vj(f.bootstrap(&journal, parent, [0xD1; 32]))?
        } else {
            let mut c = Command::control(
                if index == 1 {
                    Operation::Begin
                } else {
                    Operation::Acquire
                },
                1,
                1,
                if index == 1 { 0 } else { 1 },
            );
            if index == 2 {
                c.mask = [255; 32];
                c.mode = 4;
                c.limit = 4;
            }
            vj(f.transition(
                &journal,
                parent,
                private.as_ref().unwrap(),
                c,
                [0xD1 + index as u8; 32],
            ))?
        };
        let encoded = vj(produced.body.encode(journal.profile()))?;
        *body_size = encoded.len();
        let header = vj(fixture::candidate(
            &journal,
            parent.block,
            &produced.body,
            2000 + index as u64,
        ))?;
        vj(journal.import_block(header, &encoded, 10000, &verifier))?;
        private = Some(produced.private);
    }
    let parent = journal.best_validated();
    let accounted = journal.accounted_bytes();
    let controls = vj(f.application.control(vj(journal.validated_shards(parent))?))?;
    let started = Instant::now();
    let (expected, witness) = prepare(
        &f,
        &journal,
        parent,
        private.as_ref().unwrap(),
        Request {
            sql,
            nonce,
            transaction: 1,
            principal: 1,
        },
    )?;
    let (statement, pair) = write::prove(&expected, &f.source.source_witness, &witness)?;
    let bytes = frame::encode(&expected, &statement, &pair).map_err(|_| Error::Verification)?;
    drop(pair);
    drop(witness);
    drop(private);
    let application = f.application.clone();
    drop(f);
    let write_generation_ms = started.elapsed().as_secs_f64() * 1000.;
    let generation_ms = full.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let fresh = frame::decode_and_verify(&expected, &bytes).map_err(|_| Error::Verification)?;
    if fresh.values() != statement.values()
        || journal.best_validated() != parent
        || journal.accounted_bytes() != accounted
        || vj(application.control(vj(journal.validated_shards(parent))?))? != controls
    {
        return Err(Error::Verification);
    }
    let fresh_verification_ms = started.elapsed().as_secs_f64() * 1000.;
    Ok(Product {
        expected,
        statement,
        frame: bytes,
        journal,
        application,
        generation_ms,
        write_generation_ms,
        fresh_verification_ms,
        body_bytes,
    })
}
/// Explicit mathematical PUBLIC NONSECRET fixture; it claims NO validated Journal parent.
/// Used only by analytical security and rebuilt owning relation tests.
pub(in crate::opening::registry_lifecycle) fn conditional(
    sql: &str,
    mode: u8,
) -> Result<
    (
        registry200_proof::source::circuit::Witness,
        Expected,
        Witness,
    ),
    Error,
> {
    conditional_data(sql, mode, None)
}
/// Alternate PUBLIC NONSECRET source values are encrypted and genuinely proved by owning tests.
pub(in crate::opening::registry_lifecycle) fn conditional_data(
    sql: &str,
    mode: u8,
    data: Option<[u8; 12]>,
) -> Result<
    (
        registry200_proof::source::circuit::Witness,
        Expected,
        Witness,
    ),
    Error,
> {
    let mut f = vj(Fixture::new())?;
    if let Some(data) = data {
        let suffix = crate::opening::fixture::canonical_suffix();
        let (source, source_witness) = crate::opening::fixture::from_suffix(
            crate::opening::Relation::CanonicalIndex,
            [0x71; 32],
            ([Val::ONE; 4], [Val::TWO; 4]),
            [0x83; 32],
            data,
            &suffix,
        )?;
        f.source.witness.plain[..12].copy_from_slice(&data);
        f.source.witness.plain[12..124].copy_from_slice(&source.heads[0]);
        f.source.witness.plain[124..].copy_from_slice(&suffix);
        f.source.source = source;
        f.source.source_witness = source_witness;
        f.application = vj(Application::new(
            f.application.network,
            f.application.source_id,
            f.application.control_id,
            &f.source.source,
        ))?;
        f.genesis.database = f.application.database;
        f.genesis.application_commitment = f.application.id();
        f.genesis.initial_shards = f.application.initial_shards();
        vj(f.application.require_genesis(&f.genesis))?;
    }
    let source = f.source.source([0xE1; 32]);
    let mut opening = f.source.witness.clone();
    opening.old = Registry {
        revision: 3,
        allocator: 1,
        transactions: vec![Transaction {
            id: 1,
            principal: 1,
            sequence: 2,
            failed: false,
            snapshot: [0x83; 32],
            held: [mode; 4],
            savepoints: vec![],
        }],
    };
    opening.command = None;
    opening.salts[2] = [Val::from_u8(29); 4];
    let anchor = lifecycle::Expected::bootstrap(
        &source,
        f.genesis.id().map_err(|_| Error::Shape)?,
        [0xE2; 32],
        [0; 32],
    )?;
    let enrollment =
        crate::opening::commitment::digest(&lifecycle::enrollment_fields(&anchor, &opening));
    let mut anchor = anchor;
    anchor.enrollment = enrollment;
    let registry = lifecycle::digest(&lifecycle::registry_fields(
        &anchor,
        &opening,
        &opening.old,
        opening.salts[2],
    ));
    let parent = Parent {
        genesis: anchor.genesis,
        application: f.application.id(),
        block: anchor.parent,
        enrollment: source::encode_digest(enrollment),
        registry: source::encode_digest(registry),
    };
    let compiled = CompiledWrite::compile(sql, [0xE3; 32])?;
    let query = compiled.query(&parent);
    let source = f.source.source(query);
    let canonical = CanonicalSource::checked_claim(&source)?;
    let (expected, command) = compiled.bind(
        &canonical,
        parent,
        ActorOpening {
            transaction: 1,
            principal: 1,
            controller: opening.controllers[0],
            revision: 3,
            sequence: 2,
            salt: [Val::from_u8(31); 4],
        },
    )?;
    let witness = Witness {
        opening,
        command,
        image_salt: [Val::from_u8(37); 4],
    };
    Ok((f.source.source_witness, expected, witness))
}
pub(super) fn gate(mode: &str) -> Result<(), Error> {
    if mode == "security" {
        let (_, expected, witness) =
            conditional("UPDATE records SET amount = amount + 1 WHERE age >= 128", 4)?;
        let statement = witness.statement(&expected)?;
        crate::security(expected.source(), "public-nonsecret-write-image-source")?;
        return crate::security(&statement, "registry200-write-image");
    }
    if mode != "prove" {
        return Err(Error::Shape);
    }
    let full = Instant::now();
    let product = produce(
        "UPDATE records SET amount = amount + 1 WHERE age >= 128",
        [0xF1; 32],
    )?;
    let parts = frame::Frame::parse(&product.frame).map_err(|_| Error::Shape)?;
    let source_bytes = parts.source.len();
    let child_bytes = parts.child.len();
    println!(
        "{}",
        serde_json::json!({"stage":"verified_registry200_write_image","history_transition_calls":3,"body_bytes":product.body_bytes,"source_proof_bytes":source_bytes,"child_proof_bytes":child_bytes,"frame_bytes":product.frame.len(),"validated_parent":product.expected.parent().block,"application":product.application.id(),"logical_image_root":source::encode_digest(product.statement.image),"journal_accounted_bytes":product.journal.accounted_bytes(),"generation_ms":product.generation_ms,"write_generation_ms":product.write_generation_ms,"fresh_verification_ms":product.fresh_verification_ms,"full_cli_ms":full.elapsed().as_secs_f64()*1000.,"registry_unchanged":true,"logical_image_only":true,"data_admission":false,"sql_grant":false,"global_finality":false,"controller_possession":false})
    );
    Ok(())
}
