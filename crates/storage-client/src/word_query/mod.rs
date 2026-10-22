//! Private SQL-to-original-Word/Gold preparation. No SQL/finality acceptance route.
#[cfg(test)]
mod native_tests;
mod public;
#[cfg(test)]
mod tests;
use bfv_query_core::gold::{self, InputBinding, InputScope, Mask256, Owner};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
pub use public::{ImmutableEvidence, ProvedPublicQuery};
use registry200_proof::{
    Val, registry_progress::word, source::statement::encode_digest,
    two_lane_encoding::data_formation as installed,
};
use sha2::{Digest, Sha256};
use sql_plan::{LockStrength, LockWait, Projection, QueryPlan};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    Shape,
    Entropy,
    Binding,
    Consumed,
    Word(word::Error),
    Input(gold::Error),
    Query(word::read::query::Error),
    Formation(bfv_ciphertext_formation::gold::Error),
    Packet(registry200_joint::word::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "private Word SQL preparation rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

/// Claimed owner-side actor identity; this authenticates neither client nor rights.
#[derive(Clone, Copy)]
pub struct Actor {
    pub slot: usize,
    pub principal: u8,
    pub transaction: u64,
}
/// Owned private proof material from the owner's independent state lifecycle.
pub struct Material {
    pub source: word::SourceOpening,
    pub registry: word::RegistryOpening,
    pub actor: Actor,
    pub walk: word::WalkInput,
    pub salts: Zeroizing<[[u64; 4]; 3]>,
}
/// Current owner opening only; the next registry/result is produced by the fixed
/// private witness recipes rather than supplied as a precomputed SQL outcome.
pub struct CurrentMaterial {
    pub source: word::SourceOpening,
    pub registry: word::CurrentRegistry,
    pub actor: Actor,
    pub walk: word::WalkInput,
    pub salts: Zeroizing<[[u64; 4]; 3]>,
}
pub struct PreparedCurrentQuery {
    query: PreparedQuery,
    expected: word::Expected,
    opening: word::TransitionOpening,
}
impl PreparedCurrentQuery {
    pub fn expected(&self) -> &word::Expected {
        &self.expected
    }
    pub fn into_parts(self) -> (PreparedQuery, word::Expected, word::TransitionOpening) {
        (self.query, self.expected, self.opening)
    }
}
/// Exact SQL is not retained. Fresh OS blinding hides its dictionary and policy.
/// ```compile_fail
/// fn expose(x:storage_client::word_query::CompiledLockingSelect) { let _=x.mask; }
/// ```
pub struct CompiledLockingSelect {
    sql: Zeroizing<[u8; 32]>,
    mask: Zeroizing<[u8; 32]>,
    policy: Zeroizing<[u8; 5]>,
    salt: Zeroizing<[u64; 4]>,
}
impl CompiledLockingSelect {
    pub fn compile(sql: &str) -> Result<Self> {
        Self::compile_with_entropy(sql, &mut |bytes| {
            getrandom::getrandom(bytes).map_err(|_| Error::Entropy)
        })
    }
    fn compile_with_entropy(
        sql: &str,
        fill: &mut impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Self> {
        let QueryPlan::LockingSelect {
            predicate,
            projection,
            window,
            locking,
        } = sql_plan::parse_sql(sql).map_err(|_| Error::Shape)?
        else {
            return Err(Error::Shape);
        };
        let projection = match projection {
            Projection::Age => 1,
            Projection::Amount => 2,
            Projection::AgeAmount => 3,
            Projection::AmountAge => return Err(Error::Shape),
        };
        if window.offset > 4 || window.limit.is_some_and(|v| v > 4) {
            return Err(Error::Shape);
        }
        let mode = match locking.strength {
            LockStrength::KeyShare => 1,
            LockStrength::Share => 2,
            LockStrength::NoKeyUpdate => 3,
            LockStrength::Update => 4,
        };
        let wait = match locking.wait {
            LockWait::Wait => 0,
            LockWait::NoWait => 1,
            LockWait::SkipLocked => 2,
        };
        let mut blind = Zeroizing::new([0u8; 32]);
        fill(&mut *blind)?;
        if *blind == [0; 32] {
            return Err(Error::Entropy);
        }
        let mut salt = Zeroizing::new([0u64; 4]);
        for word in salt.iter_mut() {
            let mut accepted = false;
            for _ in 0..8 {
                let mut bytes = Zeroizing::new([0u8; 8]);
                fill(&mut *bytes)?;
                let candidate = u64::from_le_bytes(*bytes);
                if candidate < Val::ORDER_U64 {
                    *word = candidate;
                    accepted = true;
                    break;
                }
            }
            if !accepted {
                return Err(Error::Entropy);
            }
        }
        if *salt == [0; 4] {
            return Err(Error::Entropy);
        }
        let mut hash = Sha256::new();
        hash.update(b"DCS/WORD-SQL/exact-private-query/v1");
        hash.update((sql.len() as u64).to_le_bytes());
        hash.update(sql.as_bytes());
        hash.update(*blind);
        Ok(Self {
            sql: Zeroizing::new(hash.finalize().into()),
            mask: Zeroizing::new(predicate.age_mask()),
            policy: Zeroizing::new([
                mode,
                wait,
                window.offset as u8,
                window.limit.unwrap_or(4) as u8,
                projection,
            ]),
            salt,
        })
    }
    pub fn blinded_sql(&self) -> [Val; 8] {
        fields(&self.sql)
    }
    pub fn prepare(
        self,
        domain: word::StatementDomain,
        mut material: Material,
    ) -> Result<PreparedQuery> {
        let c = self.prepare_command(material.actor, &mut material.walk, &material.salts)?;
        let inputs = word::PrivateInputs::new(
            material.source,
            material.registry,
            c,
            material.walk,
            self.mask.clone(),
            material.salts.map(|row| row.map(Val::from_u64)),
        );
        self.finish(domain, inputs)
    }
    pub fn prepare_current(
        self,
        draft: &word::Expected,
        mut material: CurrentMaterial,
    ) -> Result<PreparedCurrentQuery> {
        if draft.role() != word::Role::Predicate || draft.claims().blind_sql != self.blinded_sql() {
            return Err(Error::Binding);
        }
        let command = self.prepare_command(material.actor, &mut material.walk, &material.salts)?;
        let transition = word::prepare_transition(
            draft,
            word::TransitionMaterial {
                source: material.source,
                registry: material.registry,
                command,
                walk: material.walk,
                mask: self.mask.clone(),
                salts: material.salts.map(|row| row.map(Val::from_u64)),
            },
        )
        .map_err(Error::Word)?;
        let (expected, inputs, opening) = transition.into_parts();
        let query = self.finish(draft.statement_domain(), inputs)?;
        if query.root != expected.claims().statement {
            return Err(Error::Binding);
        }
        Ok(PreparedCurrentQuery {
            query,
            expected,
            opening,
        })
    }
    fn prepare_command(
        &self,
        a: Actor,
        w: &mut word::WalkInput,
        salts: &[[u64; 4]; 3],
    ) -> Result<word::CommandInput> {
        if a.slot >= 2
            || !(1..=2).contains(&a.principal)
            || a.transaction == 0
            || w.cursor != 0
            || w.micro != 0
            || w.holder != 0
            || w.mode != 0
            || w.revision != 0
            || w.old_salt != [Val::ZERO; 4]
            || w.sql != [Val::ZERO; 8]
            || w.statement_salt != [Val::ZERO; 4]
            || w.visited != [false; 4]
            || w.selected != [false; 4]
        {
            return Err(Error::Shape);
        }
        if salts.iter().flatten().any(|v| *v >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        w.sql = self.blinded_sql();
        w.statement_salt = self.salt.map(Val::from_u64);
        Ok(word::CommandInput {
            op: 1,
            actor: Some(a.slot),
            principal: a.principal as usize,
            id: a.transaction,
            mode: self.policy[0],
            wait: self.policy[1],
            offset: self.policy[2],
            limit: self.policy[3],
            projection: self.policy[4],
            ..Default::default()
        })
    }
    fn finish(
        self,
        domain: word::StatementDomain,
        inputs: word::PrivateInputs,
    ) -> Result<PreparedQuery> {
        let opening = inputs.statement_opening(&domain).map_err(Error::Word)?;
        let root = opening.root();
        let words = opening.into_words();
        Ok(PreparedQuery {
            compiled: self,
            domain,
            inputs,
            words,
            root,
        })
    }
}
fn fields(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4]
                .try_into()
                .expect("fixed four bytes"),
        ))
    })
}
fn public_words(words: &[u64]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (out, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *out = (*word as u32).to_le_bytes();
    }
    bytes
}
pub struct PreparedQuery {
    compiled: CompiledLockingSelect,
    domain: word::StatementDomain,
    inputs: word::PrivateInputs,
    words: Zeroizing<[u64; 96]>,
    root: [Val; 4],
}
impl PreparedQuery {
    pub fn statement_root(&self) -> [Val; 4] {
        self.root
    }
    pub fn blinded_sql(&self) -> [Val; 8] {
        self.compiled.blinded_sql()
    }
    /// Consume this exact private preparation into one original encrypted input.
    pub fn originate(
        self,
        owner: &Owner,
        scope: InputScope,
        expected: &word::Expected,
        data: &installed::Expected,
    ) -> Result<PendingQuery> {
        let source = expected.source().statement();
        let claim = data.source().expected.source_claim();
        let call = self.words[41] | self.words[42] << 32;
        let transaction = self.words[43] | self.words[44] << 32;
        let context: [u8; 32] = Sha256::digest(expected.binding()).into();
        if expected.role() != word::Role::Predicate
            || expected.statement_domain() != self.domain
            || expected.claims().statement != self.root
            || expected.claims().blind_sql != self.blinded_sql()
            || source.values() != claim.values()
            || source.heads != claim.heads
            || source.packets != claim.packets
            || scope.context != context
            || scope.statement != encode_digest(self.root)
            || scope.command != encode_digest(expected.claims().command)
            || scope.application != word::profile_digest()
            || scope.rules != word::wire_profile_digest()
            || scope.genesis != expected.genesis()
            || scope.parent != expected.parent()
            || scope.call != call
            || scope.transaction != transaction
            || u64::from(scope.principal) != self.words[45]
            || scope.client != public_words(&self.words[33..41])
            || scope.controller != public_words(&self.words[46..54])
            || scope.snapshot != public_words(&self.words[70..78])
            || scope.attempt != public_words(&self.words[54..62])
            || scope.source_version != expected.source().version_id()
            || scope.database != source.heads[0][8..24]
            || scope.data_admission
                != <[u8; 32]>::from(Sha256::digest(data.core_expected().binding()))
        {
            return Err(Error::Binding);
        }
        let binding = InputBinding::checked(scope).map_err(Error::Input)?;
        let original = owner
            .originate(
                Mask256::new(*self.compiled.mask),
                binding,
                data.core_expected(),
            )
            .map_err(Error::Input)?;
        Ok(PendingQuery {
            original,
            inputs: Some(self.inputs),
            words: Some(self.words),
            expected: expected.binding(),
        })
    }
}
/// One actual original input and single-use private Word witness. No result grant.
/// ```compile_fail
/// fn forge(){let _=storage_client::word_query::PendingQuery {};}
/// ```
pub struct PendingQuery {
    original: gold::OriginatingQuery,
    inputs: Option<word::PrivateInputs>,
    words: Option<Zeroizing<[u64; 96]>>,
    expected: [u8; 64],
}
impl PendingQuery {
    pub fn public_request(&self) -> &gold::PublicRequest {
        self.original.public_request()
    }
    /// After the expectation guard, an attempt consumes private material even on failure.
    pub fn prove<'q>(
        &'q mut self,
        owner: &Owner,
        prover: &word::Prover,
        expected: &word::Expected,
    ) -> Result<ProvedQuery<'q>> {
        if expected.binding() != self.expected {
            return Err(Error::Binding);
        }
        let words = self.words.take().ok_or(Error::Consumed)?;
        let inputs = self.inputs.take().ok_or(Error::Consumed)?;
        let input = owner
            .bind_statement(&self.original, words)
            .map_err(Error::Input)?;
        let word = prover
            .produce(expected, inputs)
            .map_err(Error::Word)?
            .into_bytes();
        Ok(ProvedQuery { input, word })
    }
}
/// Actual unverified Word argument plus originating private premise; not a SQL receipt.
/// ```compile_fail
/// fn copy<'q>(x:&storage_client::word_query::ProvedQuery<'q>)->storage_client::word_query::ProvedQuery<'q>{x.clone()}
/// ```
pub struct ProvedQuery<'q> {
    input: gold::OriginatingStatement<'q>,
    word: Vec<u8>,
}
impl ProvedQuery<'_> {
    pub fn input(&self) -> &gold::OriginatingStatement<'_> {
        &self.input
    }
    pub fn word(&self) -> &[u8] {
        &self.word
    }
}
