//! Caller-owned private inputs. No fixture, evaluator or accepted state is imported.
use super::super::word_inventory::owner::PrimaryInputs;
use super::{Error, Result};
use crate::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;
#[derive(Default)]
pub struct CommandInput {
    pub op: usize,
    pub actor: Option<usize>,
    pub principal: usize,
    pub id: u64,
    pub name: [u32; 8],
    pub mode: u8,
    pub wait: u8,
    pub offset: u8,
    pub limit: u8,
    pub projection: u8,
    pub abort: bool,
}
#[derive(Default)]
pub struct WalkInput {
    pub client: [Val; 8],
    pub call: u64,
    pub invocation: [Val; 8],
    pub sql: [Val; 8],
    pub cursor: u8,
    pub micro: u64,
    pub holder: u64,
    pub mode: u8,
    pub revision: u64,
    pub old_salt: [Val; 4],
    pub new_salt: [Val; 4],
    pub statement_salt: [Val; 4],
    pub visited: [bool; 4],
    pub selected: [bool; 4],
}
impl Drop for CommandInput {
    fn drop(&mut self) {
        self.op = 0;
        self.actor = None;
        self.principal = 0;
        self.id = 0;
        self.name.fill(0);
        self.mode = 0;
        self.wait = 0;
        self.offset = 0;
        self.limit = 0;
        self.projection = 0;
        self.abort = false;
    }
}
impl Drop for WalkInput {
    fn drop(&mut self) {
        self.client.fill(Val::ZERO);
        self.call = 0;
        self.invocation.fill(Val::ZERO);
        self.sql.fill(Val::ZERO);
        self.cursor = 0;
        self.micro = 0;
        self.holder = 0;
        self.mode = 0;
        self.revision = 0;
        self.old_salt.fill(Val::ZERO);
        self.new_salt.fill(Val::ZERO);
        self.statement_salt.fill(Val::ZERO);
        self.visited.fill(false);
        self.selected.fill(false);
    }
}

/// Complete private immutable source opening; no raw getter, Clone or serialization.
pub struct SourceOpening {
    words: [Val; 587],
    salt: [Val; 4],
    bytes: [u8; 12],
}
impl SourceOpening {
    pub fn checked(plain: Zeroizing<Vec<u8>>, salt: Zeroizing<[u64; 4]>) -> Result<Self> {
        if plain.len() != 2348 || salt.iter().any(|&v| v >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        let words = crate::source::statement::words(&plain)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::Shape)?;
        Ok(Self {
            words,
            salt: salt.map(Val::from_u64),
            bytes: plain[..12].try_into().map_err(|_| Error::Shape)?,
        })
    }
    // Consuming private transfer to the sibling EMPTY208 producer; no raw public getter.
    pub(super) fn into_bootstrap(self) -> (Zeroizing<[u8; 2348]>, Zeroizing<[u64; 4]>) {
        let mut plain = Zeroizing::new([0; 2348]);
        for (out, word) in plain.as_chunks_mut::<4>().0.iter_mut().zip(self.words) {
            out.copy_from_slice(&(word.as_canonical_u64() as u32).to_le_bytes());
        }
        (
            plain,
            Zeroizing::new(self.salt.map(|v| v.as_canonical_u64())),
        )
    }
}
impl Drop for SourceOpening {
    fn drop(&mut self) {
        self.words.fill(Val::ZERO);
        self.salt.fill(Val::ZERO);
        self.bytes.fill(0);
    }
}
/// Owner-private controller and complete old/new bank openings, never authenticated metadata.
pub struct RegistryOpening {
    controllers: [[Val; 8]; 2],
    banks: [[Val; 208]; 2],
}
impl RegistryOpening {
    pub fn new(controllers: [[Val; 8]; 2], banks: [[Val; 208]; 2]) -> Self {
        Self { controllers, banks }
    }
}
impl Drop for RegistryOpening {
    fn drop(&mut self) {
        self.controllers.iter_mut().for_each(|v| v.fill(Val::ZERO));
        self.banks.iter_mut().for_each(|v| v.fill(Val::ZERO));
    }
}
/// Move-only owning preparation. Best-effort clearing is not a stack/allocator erasure claim.
/// ```compile_fail
/// use registry200_proof::registry_progress::word::PrivateInputs;
/// fn duplicate(x: &PrivateInputs) -> PrivateInputs { x.clone() }
/// ```
pub struct PrivateInputs {
    pub(super) inner: PrimaryInputs,
}
impl PrivateInputs {
    pub fn new(
        source: SourceOpening,
        registry: RegistryOpening,
        command: CommandInput,
        walk: WalkInput,
        mask: Zeroizing<[u8; 32]>,
        salts: [[Val; 4]; 3],
    ) -> Self {
        Self {
            inner: PrimaryInputs {
                source: source.words,
                source_salt: source.salt,
                source_bytes: source.bytes,
                controllers: registry.controllers,
                banks: registry.banks,
                command,
                walk,
                mask: *mask,
                salts,
            },
        }
    }
}
