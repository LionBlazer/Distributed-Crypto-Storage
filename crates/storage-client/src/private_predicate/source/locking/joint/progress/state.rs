//! Canonical private grammar and bookkeeping. None of these bytes is evidence.
use super::super::private_state_codec::{REGISTRY, Reader, Writer};
use super::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    lifecycle,
    registry_progress::{
        BootstrapExpected,
        circuit::{ProgressOpening, State, StatementOpening},
    },
    source::statement as ss,
};
use zeroize::Zeroize;

pub(super) const STATEMENT_BYTES: usize = 342;
pub(super) const PROGRESS_BYTES: usize = STATEMENT_BYTES + 8 + 1 + 4 + 4 + 8 + 1 + 8 + 32;
pub(super) const STATE_BYTES: usize = REGISTRY + 2 * (1 + PROGRESS_BYTES);
pub(super) const BANK_BYTES: usize = 8 + STATE_BYTES + 64 + 64;
pub(super) const CALL_BYTES: usize = 56;
pub(super) const PARKED_BYTES: usize = CALL_BYTES + 32 + 32 + 8;
pub(super) const BOOK_BYTES: usize = 200 + CALL_BYTES + 2 * PARKED_BYTES;

fn salt(s: &[u64; 4]) -> Result<()> {
    if s.iter().any(|v| *v >= Val::ORDER_U64) {
        Err(Error::Encoding)
    } else {
        Ok(())
    }
}
pub(super) fn empty_statement() -> StatementOpening {
    StatementOpening {
        scope: [0; 64],
        enrollment: [0; 4],
        client: [0; 32],
        call: 0,
        transaction: 0,
        principal: 0,
        controller: [0; 32],
        invocation: [0; 32],
        sql_identity: [0; 32],
        snapshot: [0; 32],
        mask: [0; 32],
        mode: 0,
        wait: 0,
        offset: 0,
        limit: 0,
        projection: 0,
        salt: [0; 4],
    }
}
fn put_statement(w: &mut Writer<'_>, s: &StatementOpening) {
    w.put(&s.scope);
    for v in s.enrollment {
        w.word(v);
    }
    w.put(&s.client);
    w.word(s.call);
    w.word(s.transaction);
    w.byte(s.principal);
    w.put(&s.controller);
    w.put(&s.invocation);
    w.put(&s.sql_identity);
    w.put(&s.snapshot);
    w.put(&s.mask);
    for v in [s.mode, s.wait, s.offset, s.limit, s.projection] {
        w.byte(v);
    }
    for v in s.salt {
        w.word(v);
    }
}
pub(super) fn encode_statement(s: &StatementOpening) -> Result<Zeroizing<[u8; STATEMENT_BYTES]>> {
    s.require_shape().map_err(crypto)?;
    let mut out = Zeroizing::new([0; STATEMENT_BYTES]);
    let mut w = Writer {
        bytes: out.as_mut(),
        at: 0,
    };
    put_statement(&mut w, s);
    assert_eq!(w.at, STATEMENT_BYTES);
    Ok(out)
}
fn read_statement(r: &mut Reader<'_>) -> Result<StatementOpening> {
    let mut s = Zeroizing::new(empty_statement());
    s.scope = r.array().map_err(crypto)?;
    for v in &mut s.enrollment {
        *v = r.word().map_err(crypto)?;
    }
    s.client = r.array().map_err(crypto)?;
    s.call = r.word().map_err(crypto)?;
    s.transaction = r.word().map_err(crypto)?;
    s.principal = r.byte().map_err(crypto)?;
    s.controller = r.array().map_err(crypto)?;
    s.invocation = r.array().map_err(crypto)?;
    s.sql_identity = r.array().map_err(crypto)?;
    s.snapshot = r.array().map_err(crypto)?;
    s.mask = r.array().map_err(crypto)?;
    s.mode = r.byte().map_err(crypto)?;
    s.wait = r.byte().map_err(crypto)?;
    s.offset = r.byte().map_err(crypto)?;
    s.limit = r.byte().map_err(crypto)?;
    s.projection = r.byte().map_err(crypto)?;
    for v in &mut s.salt {
        *v = r.word().map_err(crypto)?;
    }
    s.require_shape().map_err(crypto)?;
    Ok((*s).clone())
}
pub(super) fn decode_statement(bytes: &[u8]) -> Result<Zeroizing<StatementOpening>> {
    if bytes.len() != STATEMENT_BYTES {
        return Err(Error::Encoding);
    }
    let mut r = Reader { bytes, at: 0 };
    let s = Zeroizing::new(read_statement(&mut r)?);
    if r.at != bytes.len() {
        return Err(Error::Encoding);
    }
    Ok(s)
}
fn put_progress(w: &mut Writer<'_>, p: &ProgressOpening) {
    put_statement(w, &p.statement);
    w.word(p.microstep);
    w.byte(p.cursor);
    for v in p.visited {
        w.byte(u8::from(v));
    }
    for v in p.selected {
        w.byte(u8::from(v));
    }
    w.word(p.holder);
    w.byte(p.holder_mode);
    w.word(p.blocked_revision);
    for v in p.salt {
        w.word(v);
    }
}
fn read_progress(r: &mut Reader<'_>) -> Result<ProgressOpening> {
    let mut p = Zeroizing::new(ProgressOpening {
        statement: read_statement(r)?,
        microstep: 0,
        cursor: 0,
        visited: [false; 4],
        selected: [false; 4],
        holder: 0,
        holder_mode: 0,
        blocked_revision: 0,
        salt: [0; 4],
    });
    p.microstep = r.word().map_err(crypto)?;
    p.cursor = r.byte().map_err(crypto)?;
    for v in &mut p.visited {
        *v = r.boolean().map_err(crypto)?;
    }
    for v in &mut p.selected {
        *v = r.boolean().map_err(crypto)?;
    }
    p.holder = r.word().map_err(crypto)?;
    p.holder_mode = r.byte().map_err(crypto)?;
    p.blocked_revision = r.word().map_err(crypto)?;
    for v in &mut p.salt {
        *v = r.word().map_err(crypto)?;
    }
    p.require_shape().map_err(crypto)?;
    Ok((*p).clone())
}

#[derive(Clone)]
pub(super) struct Bank {
    pub state: Zeroizing<State>,
    pub controllers: Zeroizing<[[u8; 32]; 2]>,
    pub enroll_salt: Zeroizing<[u64; 4]>,
    pub registry_salt: Zeroizing<[u64; 4]>,
}
impl Bank {
    pub fn encode(&self) -> Result<Zeroizing<[u8; BANK_BYTES]>> {
        self.state.require_canonical().map_err(crypto)?;
        salt(&self.enroll_salt)?;
        salt(&self.registry_salt)?;
        if self.controllers.contains(&[0; 32]) {
            return Err(Error::Encoding);
        }
        let mut out = Zeroizing::new([0; BANK_BYTES]);
        let mut w = Writer {
            bytes: out.as_mut(),
            at: 0,
        };
        w.put(b"POBANK01");
        w.registry(&self.state.registry);
        for p in &self.state.progress {
            if let Some(p) = p {
                w.byte(1);
                put_progress(&mut w, p);
            } else {
                w.put(&[0; 1 + PROGRESS_BYTES]);
            }
        }
        for c in self.controllers.iter() {
            w.put(c);
        }
        for s in [&self.enroll_salt, &self.registry_salt] {
            for v in s.iter() {
                w.word(*v);
            }
        }
        assert_eq!(w.at, BANK_BYTES);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BANK_BYTES {
            return Err(Error::Encoding);
        }
        let mut r = Reader { bytes, at: 0 };
        if r.array::<8>().map_err(crypto)? != *b"POBANK01" {
            return Err(Error::Encoding);
        }
        let mut state = Zeroizing::new(State::default());
        let mut registry = r.registry().map_err(crypto)?;
        state.registry = core::mem::take(&mut *registry);
        for p in &mut state.progress {
            if r.boolean().map_err(crypto)? {
                *p = Some(read_progress(&mut r)?);
            } else if r.array::<PROGRESS_BYTES>().map_err(crypto)? != [0; PROGRESS_BYTES] {
                return Err(Error::Encoding);
            }
        }
        let mut controllers = Zeroizing::new([[0; 32]; 2]);
        for c in controllers.iter_mut() {
            *c = r.array().map_err(crypto)?;
        }
        let mut salts = Zeroizing::new([[0; 4]; 2]);
        for s in salts.iter_mut() {
            for v in s.iter_mut() {
                *v = r.word().map_err(crypto)?;
            }
        }
        let bank = Self {
            state,
            controllers,
            enroll_salt: Zeroizing::new(salts[0]),
            registry_salt: Zeroizing::new(salts[1]),
        };
        if r.at != bytes.len() {
            return Err(Error::Encoding);
        }
        drop(bank.encode()?);
        Ok(bank)
    }
    pub fn expected(
        &self,
        pins: &Pins,
        parent: [u8; 32],
        source: &registry200_proof::source::Statement,
        plain: &[u8; 2348],
    ) -> Result<BootstrapExpected> {
        let canonical = CanonicalSource::checked_claim(source).map_err(crypto)?;
        let a = app(&pins.binding)?;
        a.source_spec().require_source(source).map_err(crypto)?;
        if *self.controllers != *pins.controllers {
            return Err(Error::Pins);
        }
        let draft = lifecycle::statement::Expected::bootstrap(source, a.genesis(), parent, [0; 32])
            .map_err(crypto)?;
        let enrollment = registry200_proof::source::commitment::digest(
            &lifecycle::circuit::commitment::enrollment_fields_opening(
                &draft,
                &plain[124..156].try_into().unwrap(),
                &self.controllers,
                self.enroll_salt.map(Val::from_u64),
            ),
        );
        BootstrapExpected::new(
            &canonical,
            a.genesis(),
            parent,
            ss::encode_digest(enrollment),
        )
        .map_err(crypto)
    }
    pub fn root(
        &self,
        pins: &Pins,
        parent: [u8; 32],
        source: &registry200_proof::source::Statement,
        plain: &[u8; 2348],
    ) -> Result<([u8; 32], [u8; 32])> {
        let expected = self.expected(pins, parent, source, plain)?;
        let root = self
            .state
            .root(&expected, plain, &self.controllers, *self.registry_salt)
            .map_err(crypto)?;
        Ok((
            ss::encode_digest(expected.enrollment()),
            ss::encode_digest(root),
        ))
    }
    pub fn require_parent(
        &self,
        pins: &Pins,
        parent: &registry200_finality::progress::VerifiedParent,
        source: &registry200_proof::source::Statement,
        plain: &[u8; 2348],
    ) -> Result<()> {
        if parent.binding_id() != pins.binding.id()
            || parent.application_descriptor().encode()
                != pins.binding.application_descriptor().encode()
        {
            return Err(Error::Pins);
        }
        let (enrollment, registry) = self.root(pins, parent.head().block, source, plain)?;
        if parent.control()
            != (registry200_journal::Control::Active {
                enrollment,
                registry,
            })
        {
            return Err(Error::Pins);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Begin,
    Acquire,
    Savepoint,
    RollbackTo,
    Release,
    EndClose,
    EndAbort,
}
impl Kind {
    pub fn tag(self) -> u8 {
        match self {
            Self::Begin => 1,
            Self::Acquire => 2,
            Self::Savepoint => 3,
            Self::RollbackTo => 4,
            Self::Release => 5,
            Self::EndClose => 6,
            Self::EndAbort => 7,
        }
    }
    pub fn decode(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Begin),
            2 => Ok(Self::Acquire),
            3 => Ok(Self::Savepoint),
            4 => Ok(Self::RollbackTo),
            5 => Ok(Self::Release),
            6 => Ok(Self::EndClose),
            7 => Ok(Self::EndAbort),
            _ => Err(Error::Encoding),
        }
    }
    pub fn operation(self) -> lifecycle::circuit::model::Operation {
        use lifecycle::circuit::model::Operation as O;
        match self {
            Self::Begin => O::Begin,
            Self::Acquire => O::Acquire,
            Self::Savepoint => O::Savepoint,
            Self::RollbackTo => O::RollbackTo,
            Self::Release => O::Release,
            Self::EndClose | Self::EndAbort => O::End,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RawCall {
    pub slot: usize,
    pub kind: Kind,
    pub sequence: u64,
    pub digest: [u8; 32],
    pub transaction: u64,
}
impl RawCall {
    pub fn encode(&self) -> Zeroizing<[u8; CALL_BYTES]> {
        let mut b = Zeroizing::new([0; CALL_BYTES]);
        b[0] = 1;
        b[1] = self.slot as u8;
        b[2] = self.kind.tag();
        b[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        b[16..48].copy_from_slice(&self.digest);
        b[48..56].copy_from_slice(&self.transaction.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Option<Self>> {
        if b.len() != CALL_BYTES {
            return Err(Error::Encoding);
        }
        if b == [0; CALL_BYTES] {
            return Ok(None);
        }
        if b[0] != 1 || b[1] > 1 || b[3..8] != [0; 5] {
            return Err(Error::Encoding);
        }
        let c = Self {
            slot: b[1] as usize,
            kind: Kind::decode(b[2])?,
            sequence: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            digest: b[16..48].try_into().unwrap(),
            transaction: u64::from_le_bytes(b[48..56].try_into().unwrap()),
        };
        if c.sequence == 0 || c.transaction == 0 {
            return Err(Error::Encoding);
        }
        Ok(Some(c))
    }
    fn clear(&mut self) {
        self.slot = 0;
        self.kind = Kind::Begin;
        self.sequence.zeroize();
        self.digest.zeroize();
        self.transaction.zeroize();
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Parked {
    pub call: RawCall,
    pub statement: [u8; 32],
    pub progress: [u8; 32],
    pub record: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Client {
    pub binding: ClientBinding,
    pub active: u64,
    pub last: u64,
    pub digest: [u8; 32],
    pub record: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Book {
    pub clients: [Client; 2],
    pub flight: Option<RawCall>,
    pub parked: [Option<Parked>; 2],
}
impl Drop for Book {
    fn drop(&mut self) {
        for c in &mut self.clients {
            c.binding.id.zeroize();
            c.binding.principal.zeroize();
            c.active.zeroize();
            c.last.zeroize();
            c.digest.zeroize();
            c.record.zeroize();
        }
        if let Some(c) = &mut self.flight {
            c.clear()
        }
        for p in self.parked.iter_mut().flatten() {
            p.call.clear();
            p.statement.zeroize();
            p.progress.zeroize();
            p.record.zeroize();
        }
    }
}
impl Book {
    pub fn empty(pins: &Pins) -> Self {
        Self {
            clients: pins.clients.map(|binding| Client {
                binding,
                active: 0,
                last: 0,
                digest: [0; 32],
                record: 0,
            }),
            flight: None,
            parked: [None, None],
        }
    }
    pub fn encode(&self) -> Zeroizing<[u8; BOOK_BYTES]> {
        let mut b = Zeroizing::new([0; BOOK_BYTES]);
        b[..8].copy_from_slice(b"POBOOK01");
        for (i, c) in self.clients.iter().enumerate() {
            let n = 8 + 96 * i;
            b[n..n + 32].copy_from_slice(&c.binding.id);
            b[n + 32] = c.binding.principal;
            b[n + 40..n + 48].copy_from_slice(&c.active.to_le_bytes());
            b[n + 48..n + 56].copy_from_slice(&c.last.to_le_bytes());
            b[n + 56..n + 88].copy_from_slice(&c.digest);
            b[n + 88..n + 96].copy_from_slice(&c.record.to_le_bytes());
        }
        if let Some(c) = self.flight {
            b[200..256].copy_from_slice(c.encode().as_ref());
        }
        for (i, p) in self.parked.iter().enumerate() {
            if let Some(p) = p {
                let n = 256 + i * PARKED_BYTES;
                b[n..n + 56].copy_from_slice(p.call.encode().as_ref());
                b[n + 56..n + 88].copy_from_slice(&p.statement);
                b[n + 88..n + 120].copy_from_slice(&p.progress);
                b[n + 120..n + 128].copy_from_slice(&p.record.to_le_bytes());
            }
        }
        b
    }
    pub fn decode(bytes: &[u8], pins: &Pins) -> Result<Self> {
        if bytes.len() != BOOK_BYTES || &bytes[..8] != b"POBOOK01" {
            return Err(Error::Encoding);
        }
        let mut book = Self::empty(pins);
        for (i, c) in book.clients.iter_mut().enumerate() {
            let n = 8 + 96 * i;
            if bytes[n..n + 32] != c.binding.id
                || bytes[n + 32] != c.binding.principal
                || bytes[n + 33..n + 40] != [0; 7]
            {
                return Err(Error::Pins);
            }
            c.active = u64::from_le_bytes(bytes[n + 40..n + 48].try_into().unwrap());
            c.last = u64::from_le_bytes(bytes[n + 48..n + 56].try_into().unwrap());
            c.digest = bytes[n + 56..n + 88].try_into().unwrap();
            c.record = u64::from_le_bytes(bytes[n + 88..n + 96].try_into().unwrap());
            if (c.last == 0) != (c.record == 0)
                || (c.last == 0 && c.digest != [0; 32])
                || c.record > MAX_RECORDS as u64
            {
                return Err(Error::Encoding);
            }
        }
        book.flight = RawCall::decode(&bytes[200..256])?;
        for (i, p) in book.parked.iter_mut().enumerate() {
            let n = 256 + i * PARKED_BYTES;
            if let Some(call) = RawCall::decode(&bytes[n..n + 56])? {
                let statement = bytes[n + 56..n + 88].try_into().unwrap();
                let progress = bytes[n + 88..n + 120].try_into().unwrap();
                let _ = ss::decode_digest(statement).map_err(crypto)?;
                let _ = ss::decode_digest(progress).map_err(crypto)?;
                let record = u64::from_le_bytes(bytes[n + 120..n + 128].try_into().unwrap());
                if call.slot != i
                    || call.kind != Kind::Acquire
                    || record == 0
                    || record > MAX_RECORDS as u64
                {
                    return Err(Error::Encoding);
                }
                *p = Some(Parked {
                    call,
                    statement,
                    progress,
                    record,
                });
            } else if bytes[n..n + PARKED_BYTES] != [0; PARKED_BYTES] {
                return Err(Error::Encoding);
            }
        }
        Ok(book)
    }
    pub fn audit(&self, bank: &Bank, pins: &Pins) -> Result<()> {
        bank.state.require_canonical().map_err(crypto)?;
        if self.clients[0].active != 0 && self.clients[0].active == self.clients[1].active {
            return Err(Error::Pins);
        }
        if bank.state.registry.transactions.len()
            != self.clients.iter().filter(|c| c.active != 0).count()
        {
            return Err(Error::Pins);
        }
        for (i, c) in self.clients.iter().enumerate() {
            if c.binding != pins.clients[i] {
                return Err(Error::Pins);
            }
            let actor = bank
                .state
                .registry
                .transactions
                .iter()
                .position(|tx| tx.id == c.active && tx.principal == c.binding.principal);
            if (c.active != 0) != actor.is_some() {
                return Err(Error::Pins);
            }
            let actual = actor.and_then(|t| bank.state.progress[t].as_ref());
            match (actual, self.parked[i]) {
                (None, None) => {}
                (Some(p), Some(saved))
                    if saved.call.slot == i
                        && saved.call.transaction == c.active
                        && saved.call.sequence
                            == c.last.checked_add(1).ok_or(Error::ResourceLimit)?
                        && p.statement.client == c.binding.id
                        && p.statement.principal == c.binding.principal
                        && p.statement.call == saved.call.sequence
                        && p.statement.transaction == c.active
                        && p.statement.controller
                            == pins.controllers[usize::from(c.binding.principal - 1)]
                        && ss::encode_digest(p.statement.root().map_err(crypto)?)
                            == saved.statement
                        && ss::encode_digest(p.root().map_err(crypto)?) == saved.progress => {}
                _ => return Err(Error::Pins),
            }
        }
        Ok(())
    }
    pub fn start(&self, call: RawCall, resume: bool) -> Result<Self> {
        let c = self.clients.get(call.slot).ok_or(Error::Pins)?;
        if self.flight.is_some()
            || call.sequence != c.last.checked_add(1).ok_or(Error::ResourceLimit)?
        {
            return Err(Error::Cas);
        }
        if let Some(p) = self.parked[call.slot] {
            if !resume || p.call != call {
                return Err(Error::Cas);
            }
        } else if resume {
            return Err(Error::Phase);
        }
        match call.kind {
            Kind::Begin if c.active == 0 => {}
            Kind::Begin => return Err(Error::Phase),
            _ if c.active == call.transaction && c.active != 0 => {}
            _ => return Err(Error::Phase),
        }
        let mut next = self.clone();
        next.flight = Some(call);
        Ok(next)
    }
    pub fn park(
        &self,
        call: RawCall,
        statement: [u8; 32],
        progress: [u8; 32],
        record: u64,
    ) -> Result<Self> {
        if self.flight != Some(call)
            || call.kind != Kind::Acquire
            || record == 0
            || record > MAX_RECORDS as u64
        {
            return Err(Error::Cas);
        }
        let mut next = self.clone();
        next.parked[call.slot] = Some(Parked {
            call,
            statement,
            progress,
            record,
        });
        next.flight = None;
        Ok(next)
    }
    pub fn terminal(&self, call: RawCall, record: u64) -> Result<Self> {
        if self.flight != Some(call) || record == 0 || record > MAX_RECORDS as u64 {
            return Err(Error::Cas);
        }
        let mut next = self.clone();
        let c = &mut next.clients[call.slot];
        if call.sequence != c.last.checked_add(1).ok_or(Error::ResourceLimit)? {
            return Err(Error::Cas);
        }
        match call.kind {
            Kind::Begin => c.active = call.transaction,
            Kind::EndClose | Kind::EndAbort => c.active = 0,
            _ => {}
        }
        c.last = call.sequence;
        c.digest = call.digest;
        c.record = record;
        next.parked[call.slot] = None;
        Ok(next)
    }
    pub fn acknowledge(&self, call: RawCall) -> Result<Self> {
        if self.flight != Some(call) || self.clients[call.slot].last != call.sequence {
            return Err(Error::Cas);
        }
        let mut next = self.clone();
        next.flight = None;
        Ok(next)
    }
}
