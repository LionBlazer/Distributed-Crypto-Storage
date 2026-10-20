//! Private fixed Control state. AEAD, phase CAS, actual proofs and I/O belong to the Vault.
use super::super::private_state_codec::{REGISTRY, Reader, Writer};
use super::*;
use crate::private_predicate::{SourceOwner, source::LoadedSource};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_joint::Manifest;
use registry200_proof::{
    lifecycle::{circuit::commitment, statement as ls},
    source::{self, statement as ss},
};

pub(in crate::private_predicate::source::locking::joint) const IDLE_BYTES: usize =
    8 + REGISTRY + 64 + 64;
const COMMAND_BYTES: usize = 1 + 8 + 1 + 8 + 32 + 32 + 5 + 1;
pub(in crate::private_predicate::source::locking::joint) const CONTROL_BYTES: usize =
    8 + COMMAND_BYTES + 32 + 32 + 8 + 32 + 4 * 32 + REGISTRY + 64 + 64 + 1;
const IDLE_MAGIC: &[u8; 8] = b"JIDPRV01";
const CONTROL_MAGIC: &[u8; 8] = b"JCTPRV01";

pub(in crate::private_predicate::source::locking::joint) fn require_idle_parent(
    opening: &JointRegistryOpening,
    parent: &JointControlParent,
) -> crate::Result<()> {
    parent.require_stamp(&opening.binding, &opening.parent, opening.context)
}

fn canonical_bank(
    registry: &Registry,
    controllers: &[[u8; 32]; 2],
    salts: &[[u64; 4]; 2],
) -> crate::Result<()> {
    registry.require_canonical().map_err(cryptography)?;
    if controllers.contains(&[0; 32]) || salts.iter().flatten().any(|v| *v >= Val::ORDER_U64) {
        return Err(invalid("Noncanonical private Control bank"));
    }
    Ok(())
}

// Host bookkeeping is checked against the genuinely root-opened bank. This
// helper is private owner mathematics, never a Registry getter or proof receipt.
pub(in crate::private_predicate::source::locking::joint) fn require_host_bank(
    opening: &JointRegistryOpening,
    clients: [(u64, u8); 2],
) -> crate::Result<()> {
    opening.registry.require_canonical().map_err(cryptography)?;
    if clients[0].0 != 0 && clients[0].0 == clients[1].0
        || opening.registry.transactions.len() != clients.iter().filter(|c| c.0 != 0).count()
        || clients.iter().any(|(id, principal)| {
            !(1..=2).contains(principal)
                || (*id != 0
                    && !opening
                        .registry
                        .transactions
                        .iter()
                        .any(|tx| tx.id == *id && tx.principal == *principal))
        })
    {
        return Err(invalid(
            "Managed client map differs from the complete opened Registry",
        ));
    }
    Ok(())
}
pub(in crate::private_predicate::source::locking::joint) fn host_begin_id(
    opening: &JointRegistryOpening,
    clients: [(u64, u8); 2],
) -> crate::Result<u64> {
    require_host_bank(opening, clients)?;
    opening
        .registry
        .allocator
        .checked_add(1)
        .ok_or_else(|| invalid("Registry allocator exhausted"))
}
pub(in crate::private_predicate::source::locking::joint) fn require_host_initial(
    opening: &JointRegistryOpening,
) -> crate::Result<()> {
    if *opening.registry != Registry::default() {
        return Err(invalid(
            "Managed Host creation requires the genuine empty Bootstrap bank",
        ));
    }
    Ok(())
}
pub(in crate::private_predicate::source::locking::joint) fn require_host_control(
    candidate: &JointControlCandidate,
    transaction: u64,
    principal: u8,
    verb: u8,
) -> crate::Result<()> {
    let c = &candidate.command;
    let correct = match verb {
        1 => c.operation == Operation::Begin && !c.abort,
        2 => c.operation == Operation::End && !c.abort,
        3 => c.operation == Operation::End && c.abort,
        _ => false,
    };
    if !correct || c.transaction != transaction || c.principal != principal {
        return Err(invalid(
            "Managed call differs from the actual Control opening",
        ));
    }
    Ok(())
}

/// Canonical grammar only. The caller must bind the full independent stamp in
/// its authenticated record and actually audit the bank before phase promotion.
pub(in crate::private_predicate::source::locking::joint) fn encode_idle(
    opening: &JointRegistryOpening,
) -> crate::Result<Zeroizing<[u8; IDLE_BYTES]>> {
    canonical_bank(&opening.registry, &opening.controllers, &opening.salts)?;
    let mut bytes = Zeroizing::new([0; IDLE_BYTES]);
    let mut w = Writer {
        bytes: bytes.as_mut(),
        at: 0,
    };
    w.put(IDLE_MAGIC);
    w.registry(&opening.registry);
    for controller in opening.controllers.iter() {
        w.put(controller);
    }
    for salt in opening.salts.iter().flatten() {
        w.word(*salt);
    }
    assert_eq!(w.at, IDLE_BYTES);
    Ok(bytes)
}

fn idle(bytes: &[u8], parent: &JointControlParent) -> crate::Result<JointRegistryOpening> {
    if bytes.len() != IDLE_BYTES {
        return Err(invalid("Private Idle requires its exact fixed length"));
    }
    let mut r = Reader { bytes, at: 0 };
    if r.array::<8>()? != *IDLE_MAGIC {
        return Err(invalid("Private Idle role differs"));
    }
    let registry = r.registry()?;
    let controllers = controllers(&mut r)?;
    let salts = salts::<2>(&mut r)?;
    canonical_bank(&registry, &controllers, &salts)?;
    if r.at != IDLE_BYTES {
        return Err(invalid("Trailing private Idle bytes"));
    }
    Ok(JointRegistryOpening {
        binding: parent.binding.clone(),
        parent: parent.verified.clone(),
        context: parent.context.id(),
        registry,
        controllers,
        salts,
    })
}

fn loaded(
    owner: &SourceOwner,
    fetched: FetchedSource<'_>,
    parent: &JointControlParent,
) -> crate::Result<LoadedSource> {
    if fetched.object != parent.binding.application_descriptor().source_object() {
        return Err(invalid("Private Control Source object differs"));
    }
    let loaded = owner.load(fetched)?;
    let app = JointApplication::new(
        parent.binding.application_descriptor().clone(),
        parent.binding.journal_genesis(),
    )
    .map_err(cryptography)?;
    app.source_spec()
        .require_source(&loaded.draft)
        .map_err(cryptography)?;
    Ok(loaded)
}

fn roots(
    opening: &JointRegistryOpening,
    parent: &JointControlParent,
    loaded: &LoadedSource,
) -> crate::Result<()> {
    parent.require_stamp(&opening.binding, &opening.parent, opening.context)?;
    let Control::Active {
        enrollment,
        registry,
    } = parent.verified.control()
    else {
        return Err(invalid("Private Idle requires Active Registry"));
    };
    let app = JointApplication::new(
        parent.binding.application_descriptor().clone(),
        parent.binding.journal_genesis(),
    )
    .map_err(cryptography)?;
    let expected = ls::Expected::transition(
        &loaded.draft,
        app.genesis(),
        parent.head().block,
        enrollment,
        registry,
        [0; 32],
    )
    .map_err(cryptography)?;
    let table = Zeroizing::new(table(loaded)?);
    let ids = Zeroizing::new(ids(loaded)?);
    if ss::encode_digest(source_hash(commitment::enrollment_fields_opening(
        &expected,
        &table,
        &opening.controllers,
        opening.salts[0].map(Val::from_u64),
    ))) != enrollment
        || ss::encode_digest(life_hash(commitment::registry_fields_opening(
            &expected,
            &table,
            &ids,
            &opening.controllers,
            &opening.registry,
            opening.salts[1].map(Val::from_u64),
        ))) != registry
    {
        return Err(invalid(
            "Private Idle differs from real Source/parent roots",
        ));
    }
    Ok(())
}

/// No parent is decoded from bytes. The caller supplies its independently
/// replayed sealed parent/context; real Source and both roots are checked here.
pub(in crate::private_predicate::source::locking::joint) fn restore_idle(
    bytes: &[u8],
    owner: &SourceOwner,
    fetched: FetchedSource<'_>,
    parent: &JointControlParent,
) -> crate::Result<JointRegistryOpening> {
    let opening = idle(bytes, parent)?;
    let loaded = loaded(owner, fetched, parent)?;
    roots(&opening, parent, &loaded)?;
    Ok(opening)
}

fn command_shape(command: &Command, outcome: u8) -> crate::Result<()> {
    command.require_shape().map_err(cryptography)?;
    if !matches!(
        (command.operation, outcome),
        (Operation::Begin, 0) | (Operation::End, 0 | 3)
    ) {
        return Err(invalid("Private Control requires Begin or End outcome"));
    }
    Ok(())
}

pub(in crate::private_predicate::source::locking::joint) fn encode_control(
    candidate: &JointControlCandidate,
) -> crate::Result<Zeroizing<[u8; CONTROL_BYTES]>> {
    canonical_bank(&candidate.next, &candidate.controllers, &candidate.salts)?;
    command_shape(&candidate.command, *candidate.outcome)?;
    if candidate
        .command_salt
        .iter()
        .chain(candidate.result_salt.iter())
        .any(|v| *v >= Val::ORDER_U64)
    {
        return Err(invalid("Noncanonical private Control command/result salt"));
    }
    candidate.require_private_openings()?;
    let mut bytes = Zeroizing::new([0; CONTROL_BYTES]);
    let mut w = Writer {
        bytes: bytes.as_mut(),
        at: 0,
    };
    w.put(CONTROL_MAGIC);
    command(&mut w, &candidate.command);
    for salt in candidate
        .command_salt
        .iter()
        .chain(candidate.result_salt.iter())
    {
        w.word(*salt);
    }
    w.word(*candidate.revision);
    w.put(candidate.table.as_ref());
    for id in candidate.row_ids.iter() {
        w.put(id);
    }
    w.registry(&candidate.next);
    for controller in candidate.controllers.iter() {
        w.put(controller);
    }
    for salt in candidate.salts.iter().flatten() {
        w.word(*salt);
    }
    w.byte(*candidate.outcome);
    assert_eq!(w.at, CONTROL_BYTES);
    Ok(bytes)
}

/// Pure private restoration. The enclosing owner must first authenticate its
/// phase/generation, prior Idle digest and exact public bytes, and must genuinely
/// check Source/Life/Kind plus owner Header/Body through closed History before
/// promotion/publication. No model step, proof generation or receipt is used here.
pub(in crate::private_predicate::source::locking::joint) fn restore_control(
    bytes: &[u8],
    preceding_idle: &[u8],
    owner: &SourceOwner,
    fetched: FetchedSource<'_>,
    parent: &JointControlParent,
    request: &JointRequest,
    manifest: &Manifest,
) -> crate::Result<JointControlCandidate> {
    if bytes.len() != CONTROL_BYTES {
        return Err(invalid("Private Control requires its exact fixed length"));
    }
    let mut r = Reader { bytes, at: 0 };
    if r.array::<8>()? != *CONTROL_MAGIC {
        return Err(invalid("Private Control role differs"));
    }
    let command = read_command(&mut r)?;
    let command_salt = salts::<1>(&mut r)?;
    let result_salt = salts::<1>(&mut r)?;
    let revision = Zeroizing::new(r.word()?);
    let table = Zeroizing::new(r.array()?);
    let mut row_ids = Zeroizing::new([[0; 32]; 4]);
    for id in row_ids.iter_mut() {
        *id = r.array()?;
    }
    let next = r.registry()?;
    let controllers = controllers(&mut r)?;
    let salts = salts::<2>(&mut r)?;
    let outcome = Zeroizing::new(r.byte()?);
    if r.at != CONTROL_BYTES {
        return Err(invalid("Trailing private Control bytes"));
    }
    canonical_bank(&next, &controllers, &salts)?;
    command_shape(&command, *outcome)?;
    let old = idle(preceding_idle, parent)?;
    let loaded = loaded(owner, fetched, parent)?;
    roots(&old, parent, &loaded)?;
    if *controllers != *old.controllers
        || salts[0] != old.salts[0]
        || *revision != old.registry.revision
        || *table != self::table(&loaded)?
        || *row_ids != ids(&loaded)?
    {
        return Err(invalid(
            "Private Control changed its predecessor/Source opening",
        ));
    }
    match command.operation {
        Operation::Begin => {
            if command.transaction
                != old
                    .registry
                    .allocator
                    .checked_add(1)
                    .ok_or_else(|| invalid("Control allocator exhausted"))?
                || command.sequence != 0
                || old.registry.transactions.len() == 2
            {
                return Err(invalid("Private Begin differs from preceding Idle"));
            }
        }
        Operation::End => {
            let tx = old
                .registry
                .transactions
                .iter()
                .find(|tx| tx.id == command.transaction)
                .ok_or_else(|| invalid("Private End actor is absent"))?;
            if tx.principal != command.principal
                || tx.sequence != command.sequence
                || *outcome != if command.abort || tx.failed { 3 } else { 0 }
            {
                return Err(invalid("Private End differs from preceding Idle"));
            }
        }
        _ => return Err(invalid("Private Control operation differs")),
    }
    let statement = statement(parent, request, manifest, &loaded)?;
    let candidate = JointControlCandidate {
        parent: JointControlParent {
            binding: parent.binding.clone(),
            verified: parent.verified.clone(),
            context: parent.context.clone(),
        },
        request: request.encode().map_err(cryptography)?,
        statement,
        command,
        command_salt: Zeroizing::new(command_salt[0]),
        result_salt: Zeroizing::new(result_salt[0]),
        revision,
        table,
        row_ids,
        next,
        controllers,
        salts,
        outcome,
    };
    let _ = candidate.expectation(Manifest::decode(&manifest.encode()).map_err(cryptography)?)?;
    candidate.require_private_openings()?;
    Ok(candidate)
}

fn statement(
    parent: &JointControlParent,
    request: &JointRequest,
    manifest: &Manifest,
    loaded: &LoadedSource,
) -> crate::Result<ls::Statement> {
    let app = JointApplication::new(
        parent.binding.application_descriptor().clone(),
        parent.binding.journal_genesis(),
    )
    .map_err(cryptography)?;
    let Control::Active {
        enrollment,
        registry,
    } = parent.verified.control()
    else {
        return Err(invalid("Private Control requires Active Registry"));
    };
    let claim = request
        .inner()
        .source(app.source_spec())
        .map_err(cryptography)?;
    let mut actual = loaded.draft.clone();
    actual.request = claim.request;
    actual.open_commitment = claim.open_commitment;
    if actual.values() != claim.values()
        || actual.heads != claim.heads
        || actual.packets != claim.packets
    {
        return Err(invalid("Private Control request differs from real Source"));
    }
    Ok(ls::Statement {
        expected: ls::Expected::transition(
            &claim,
            app.genesis(),
            parent.head().block,
            enrollment,
            registry,
            request.inner().command,
        )
        .map_err(cryptography)?,
        next: ss::decode_digest(manifest.next_root()).map_err(cryptography)?,
        result: ss::decode_digest(manifest.result_root()).map_err(cryptography)?,
    })
}

fn table(loaded: &LoadedSource) -> crate::Result<[u8; 32]> {
    loaded.plain[124..156]
        .try_into()
        .map_err(|_| invalid("Invalid real Source TableId"))
}
fn ids(loaded: &LoadedSource) -> crate::Result<[[u8; 32]; 4]> {
    let mut ids = Zeroizing::new([[0; 32]; 4]);
    for (i, id) in ids.iter_mut().enumerate() {
        *id = loaded.plain[2220 + 32 * i..2252 + 32 * i]
            .try_into()
            .map_err(|_| invalid("Invalid real Source RowId"))?;
    }
    Ok(*ids)
}
fn controllers(r: &mut Reader<'_>) -> crate::Result<Zeroizing<[[u8; 32]; 2]>> {
    let mut controllers = Zeroizing::new([[0; 32]; 2]);
    for controller in controllers.iter_mut() {
        *controller = r.array()?;
    }
    Ok(controllers)
}
fn salts<const N: usize>(r: &mut Reader<'_>) -> crate::Result<Zeroizing<[[u64; 4]; N]>> {
    let mut salts = Zeroizing::new([[0; 4]; N]);
    for salt in salts.iter_mut().flatten() {
        *salt = r.word()?;
        if *salt >= Val::ORDER_U64 {
            return Err(invalid("Noncanonical private Control salt"));
        }
    }
    Ok(salts)
}
fn command(w: &mut Writer<'_>, command: &Command) {
    w.byte(command.operation as u8);
    w.word(command.transaction);
    w.byte(command.principal);
    w.word(command.sequence);
    w.put(&command.name);
    w.put(&command.mask);
    w.put(&[
        command.mode,
        command.wait,
        command.offset,
        command.limit,
        command.projection,
    ]);
    w.byte(u8::from(command.abort));
}
fn read_command(r: &mut Reader<'_>) -> crate::Result<Zeroizing<Command>> {
    let operation = match r.byte()? {
        0 => Operation::Begin,
        6 => Operation::End,
        _ => return Err(invalid("Private Control opcode differs")),
    };
    let mut command = Zeroizing::new(Command::control(operation, 0, 0, 0));
    command.transaction = r.word()?;
    command.principal = r.byte()?;
    command.sequence = r.word()?;
    command.name = r.array()?;
    command.mask = r.array()?;
    command.mode = r.byte()?;
    command.wait = r.byte()?;
    command.offset = r.byte()?;
    command.limit = r.byte()?;
    command.projection = r.byte()?;
    command.abort = r.boolean()?;
    command.require_shape().map_err(cryptography)?;
    Ok(command)
}
fn life_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = ls::digest(&fields);
    fields.fill(Val::ZERO);
    root
}
fn source_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = source::commitment::digest(&fields);
    fields.fill(Val::ZERO);
    root
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
