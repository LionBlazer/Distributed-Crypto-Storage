//! PUBLIC independent expectations. None establishes authorization or admission.
use super::*;
pub(super) const BINDING_BYTES: usize = 528;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub degree: u32,
    pub moduli: [u64; 2],
    pub plaintext: u64,
    pub variance: u32,
}
impl Parameters {
    pub fn fixed() -> Self {
        Self {
            degree: N as u32,
            moduli: Q,
            plaintext: T,
            variance: 10,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct KeyExpected {
    scope: [u8; 32],
    context: [Val; 8],
    root: [Val; 4],
    binding: [u8; 64],
}
impl KeyExpected {
    pub fn checked(
        scope: [u8; 32],
        parameters: Parameters,
        context: [u64; 8],
        root: [u64; 4],
    ) -> Result<Self> {
        if scope == [0; 32] || parameters != Parameters::fixed() {
            return Err(Error::Binding);
        }
        if context.iter().chain(&root).any(|&v| v >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        let mut bytes = Vec::new();
        bytes.extend(profile_digest());
        bytes.extend(scope);
        for v in [
            u64::from(parameters.degree),
            Q[0],
            Q[1],
            T,
            u64::from(parameters.variance),
        ] {
            bytes.extend(v.to_le_bytes());
        }
        for v in context.into_iter().chain(root) {
            bytes.extend(v.to_le_bytes());
        }
        Ok(Self {
            scope,
            context: context.map(Val::from_u64),
            root: root.map(Val::from_u64),
            binding: digest64(b"DCS/Gold-owner/key-expectation/v1", &[&bytes]),
        })
    }
    pub fn scope(&self) -> [u8; 32] {
        self.scope
    }
    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }
    pub fn context_words(&self) -> [u64; 8] {
        self.context.map(|v| v.as_canonical_u64())
    }
    pub fn root_words(&self) -> [u64; 4] {
        self.root.map(|v| v.as_canonical_u64())
    }
    #[cfg(feature = "gold-owner")]
    pub(super) fn context(&self) -> [Val; 8] {
        self.context
    }
    #[cfg(feature = "gold-owner")]
    pub(super) fn root(&self) -> [Val; 4] {
        self.root
    }
}
/// Public hashes/identifiers only. SQL, operators, constants and mask stay private.
/// These are independent metadata pins, never claims of rights/currentness.
#[derive(Clone, PartialEq, Eq)]
pub struct InputScope {
    pub database: [u8; 16],
    pub transaction: u64,
    pub call: u64,
    pub principal: u8,
    pub application: [u8; 32],
    pub genesis: [u8; 32],
    pub rules: [u8; 32],
    pub context: [u8; 32],
    pub parent: [u8; 32],
    pub client: [u8; 32],
    pub controller: [u8; 32],
    pub source_version: [u8; 32],
    pub data_admission: [u8; 32],
    pub snapshot: [u8; 32],
    pub statement: [u8; 32],
    pub command: [u8; 32],
    pub attempt: [u8; 32],
    pub nonce: [u8; 32],
}
#[derive(Clone, PartialEq, Eq)]
pub struct InputBinding {
    bytes: Vec<u8>,
    statement: [u8; 32],
    context: [u8; 32],
}
impl InputBinding {
    pub fn checked(scope: InputScope) -> Result<Self> {
        let hashes = [
            scope.application,
            scope.genesis,
            scope.rules,
            scope.context,
            scope.parent,
            scope.client,
            scope.controller,
            scope.source_version,
            scope.data_admission,
            scope.snapshot,
            scope.statement,
            scope.command,
            scope.attempt,
            scope.nonce,
        ];
        if scope.database == [0; 16]
            || scope.transaction == 0
            || scope.call == 0
            || !(1..=2).contains(&scope.principal)
            || hashes.contains(&[0; 32])
        {
            return Err(Error::Binding);
        }
        let mut bytes = Vec::with_capacity(BINDING_BYTES);
        bytes.extend(b"GOIB0001");
        bytes.extend(profile_digest());
        bytes.extend(scope.database);
        bytes.extend(scope.transaction.to_le_bytes());
        bytes.extend(scope.call.to_le_bytes());
        bytes.push(scope.principal);
        bytes.extend([0; 7]);
        for hash in hashes {
            bytes.extend(hash);
        }
        if bytes.len() != BINDING_BYTES {
            return Err(Error::Shape);
        }
        Ok(Self {
            bytes,
            statement: scope.statement,
            context: scope.context,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[cfg(feature = "gold-owner")]
    pub(super) fn statement(&self) -> [u8; 32] {
        self.statement
    }
    /// Independently selected public context pin; this authenticates no caller.
    pub fn context(&self) -> [u8; 32] {
        self.context
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BINDING_BYTES {
            return Err(Error::Shape);
        }
        let mut r = Reader::new(bytes);
        if r.take(8)? != b"GOIB0001" || r.take(32)? != profile_digest() {
            return Err(Error::Binding);
        }
        let database = r.array()?;
        let transaction = u64::from_le_bytes(r.array()?);
        let call = u64::from_le_bytes(r.array()?);
        let principal = r.take(1)?[0];
        if r.take(7)? != [0; 7] {
            return Err(Error::Shape);
        }
        let scope = InputScope {
            database,
            transaction,
            call,
            principal,
            application: r.array()?,
            genesis: r.array()?,
            rules: r.array()?,
            context: r.array()?,
            parent: r.array()?,
            client: r.array()?,
            controller: r.array()?,
            source_version: r.array()?,
            data_admission: r.array()?,
            snapshot: r.array()?,
            statement: r.array()?,
            command: r.array()?,
            attempt: r.array()?,
            nonce: r.array()?,
        };
        r.end()?;
        let actual = Self::checked(scope)?;
        if actual.as_bytes() != bytes {
            return Err(Error::Shape);
        }
        Ok(actual)
    }
}
