use super::{cryptography, invalid, random_salt};
use bfv_query_core::CoefficientRow;
use compact_query::{PlainRow, ReadHeads, RowIds, Table, TableId, storage};
use compact_store::{AuditWorkers, Limits, Owner};
use p3_field::PrimeCharacteristicRing;
use peer_runtime::{CheckedObject, RawBundle};
use registry200_proof::{
    Val,
    source::{self, Relation, Statement, commitment},
};
use zeroize::Zeroizing;

mod locking;
mod state;
pub use locking::{
    CompiledLockingSelect, CompletedJointAcquire, CompletedJointRow, EncryptedJointRecovery,
    JOINT_RECOVERY_BYTES, JOINT_RECOVERY_HEADER_BYTES, JointLockingCandidates, JointLockingParent,
    JointLockingPreparation, JointRecovery, JointRecoveryIdentity, JointRecoveryInputs,
    JointRecoveryKey, JointSqlCall, JointSqlClient, JointSqlClientBinding, JointSqlHost,
    JointSqlHostPins, JointSqlPreparation, JointSqlReply, LockingActor, LockingCompletion,
    LockingConflict, LockingControl, LockingParent, LockingPreparation, NonAdmittedJointLocking,
    NonAdmittedLocking, OwnerVaultAcquireCompletion, OwnerVaultAcquireMaterial,
    OwnerVaultAcquirePreparation, OwnerVaultAcquireWork, PreparedJointLockingInputs,
    PreparedLockingInputs, RecoverableJointLockingInputs, RecoverableJointLockingPreparation,
    RecoveredJointComputePrepared, StagedLockingTransition, joint_sql_host_profile_digest,
};
pub use locking::{CompletedJointBootstrap, JointBootstrapCandidate, PreparedJointBootstrap};
pub use locking::{
    CompletedJointControl, JointControlCandidate, JointControlIntent, JointControlOutcome,
    JointControlParent, JointEndDisposition, JointOwnedLockingControl, JointOwnedRecovery,
    JointRegistryOpening, PreparedJointControl,
};
pub use locking::{
    OWNER_VAULT_MAX_BODY_BYTES, OWNER_VAULT_MAX_FILE_BYTES, OWNER_VAULT_MAX_RECORD_BYTES,
    OwnerVault, OwnerVaultAuthority, OwnerVaultCompletion, OwnerVaultCursor, OwnerVaultDraft,
    OwnerVaultError, OwnerVaultIdentity, OwnerVaultPhase, OwnerVaultPins, OwnerVaultReplay,
    OwnerVaultSubmission, VaultResult, owner_vault_profile_digest,
};
pub use state::{
    EncryptedSourceState, SOURCE_STATE_BYTES, SOURCE_STATE_HEADER_BYTES, SourceStateAuthority,
    SourceStateIdentity,
};

/// Real fetched ciphertext with object, TableId and both heads pinned independently.
/// These are caller expectations, never values adopted from the supplied bundle.
pub struct FetchedSource<'a> {
    pub object: [u8; 32],
    pub bundle: &'a RawBundle,
    pub heads: &'a ReadHeads,
}

/// Owner-side AEAD authority plus its explicit guarded proof copy and stable Ckey salt.
/// The caller supplies fresh random key material and owns domain uniqueness/custody.
/// No key getter, serialization, callback, BFV key or plaintext row cache is exposed.
pub struct SourceOwner {
    sealer: Owner,
    key: Zeroizing<[u8; 32]>,
    key_salt: Zeroizing<[u64; 4]>,
}
impl SourceOwner {
    pub fn new(
        database: [u8; 16],
        key_domain: [u8; 16],
        key: Zeroizing<[u8; 32]>,
    ) -> crate::Result<Self> {
        let key_salt = Zeroizing::new(random_salt()?);
        let sealer = Owner::from_key(database, key_domain, Zeroizing::new(*key));
        Ok(Self {
            sealer,
            key,
            key_salt,
        })
    }

    /// Real canonical ingest of ALL four caller originals, using the shared writer.
    /// Store/replicate the returned encrypted images through the ordinary custody API.
    pub fn seal_partition(
        &self,
        table_id: &TableId,
        rows: &[PlainRow; 4],
        ids: RowIds,
    ) -> crate::Result<Table> {
        storage::seal_partition(&self.sealer, table_id, rows, ids, 256, Limits::default())
            .map_err(cryptography)
    }

    pub(super) fn load(&self, fetched: FetchedSource<'_>) -> crate::Result<LoadedSource> {
        let raw = fetched.bundle;
        // Enforce exact public N4 geometry before cloning/auditing any supplied Vec.
        if raw.data_head.len() != 112
            || raw.index_head.len() != 112
            || raw.data.len() != 172
            || raw.index.len() != 2496
        {
            return Err(invalid(
                "Private predicate inputs require exact canonical N4 images",
            ));
        }
        let target = raw.target_version().map_err(cryptography)?;
        if target.object() != &fetched.object
            || target.data_head() != fetched.heads.data()
            || target.index_head() != fetched.heads.index()
        {
            return Err(invalid(
                "Fetched source differs from the independently pinned object/heads",
            ));
        }
        let checked = CheckedObject::audit(raw.clone()).map_err(cryptography)?;
        if checked.version() != &target {
            return Err(invalid("Audited source changed its target version"));
        }
        let raw = checked.into_raw();
        let table = storage::restore(
            &self.sealer,
            (&raw.data, &raw.index),
            fetched.heads.table_id(),
            fetched.heads.data(),
            fetched.heads.index(),
            Limits::default(),
            AuditWorkers::One,
        )
        .map_err(cryptography)?;
        if table.commitment().layout().row_count != 4 {
            return Err(invalid(
                "Private predicate inputs require all four original rows",
            ));
        }

        let limits = Limits::default();
        let data_page = table
            .snapshot()
            .lookup(0, limits)
            .map_err(cryptography)?
            .verify(fetched.heads.data(), 0, limits)
            .map_err(cryptography)?;
        let index_page = table
            .lookup_index_page(0)
            .map_err(cryptography)?
            .verify(fetched.heads.index(), 0, limits)
            .map_err(cryptography)?;
        let data_plain = self.sealer.decrypt(&data_page).map_err(cryptography)?;
        let index_plain = self.sealer.decrypt(&index_page).map_err(cryptography)?;
        if data_plain.as_bytes().len() != 12 || index_plain.as_bytes().len() != 2336 {
            return Err(invalid(
                "Private predicate source opening has invalid N4 length",
            ));
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(2348));
        plain.extend_from_slice(data_plain.as_bytes());
        plain.extend_from_slice(index_plain.as_bytes());
        let mut originals = Zeroizing::new([CoefficientRow { age: 0, amount: 0 }; 4]);
        for (ordinal, original) in originals.iter_mut().enumerate() {
            let row = Zeroizing::new(
                storage::row(&self.sealer, &table, ordinal as u64, limits).map_err(cryptography)?,
            );
            *original = CoefficientRow {
                age: row.age,
                amount: row.amount,
            };
        }
        let key = commitment::digest(&commitment::key_fields(
            &fetched.heads.data().encode(),
            *self.key,
            self.key_salt.map(Val::from_u64),
        ));
        let draft = Statement::checked_relation(
            Relation::CanonicalIndex,
            [&raw.data, &raw.index],
            [fetched.heads.data(), fetched.heads.index()],
            [0; 32],
            source::statement::encode_digest(key),
            [0; 32],
        )
        .map_err(cryptography)?;
        Ok(LoadedSource {
            draft,
            plain,
            originals,
        })
    }

    pub(super) fn source_witness(
        &self,
        opening_salt: [Val; 4],
        originals: &[CoefficientRow; 4],
    ) -> source::circuit::Witness {
        source::circuit::Witness::new(
            *self.key,
            self.key_salt.map(Val::from_u64),
            opening_salt,
            originals.map(|row| row.age),
        )
    }
}

pub(super) struct LoadedSource {
    pub(super) draft: Statement,
    pub(super) plain: Zeroizing<Vec<u8>>,
    pub(super) originals: Zeroizing<[CoefficientRow; 4]>,
}
