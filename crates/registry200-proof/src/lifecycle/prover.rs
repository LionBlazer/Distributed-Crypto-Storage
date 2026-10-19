//! Fixed Source-first lifecycle production. No Journal, signer or SQL policy.
use super::{
    circuit::{
        Witness,
        model::{Command, Registry},
    },
    statement::Statement,
};
use crate::{admission, fixed::Backend, source, wire};
use bfv_hiding_stark::codec;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::Zeroizing;

/// A consumed private mathematical opening associated with one complete checked
/// Expected. No Clone/Debug/serialization or private-data getter is provided.
/// ```compile_fail
/// fn clone<T: Clone>() {} fn forbidden() { clone::<registry200_proof::lifecycle::PreparedWitness>(); }
/// ```
/// ```compile_fail
/// fn forbidden(witness: registry200_proof::lifecycle::PreparedWitness) { let _ = witness.plain; }
/// ```
pub struct PreparedWitness {
    expected: admission::Expected,
    statement: Statement,
    plain: Zeroizing<[u8; 2348]>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 6]>,
    old: Zeroizing<Registry>,
    command: Option<Zeroizing<Command>>,
}
impl PreparedWitness {
    /// Reconstruct all openings before capturing them; this alone verifies no
    /// Source, lifecycle proof, controller possession or application permission.
    pub fn new(
        expected: &admission::Expected,
        mut mathematical: Witness,
    ) -> Result<Self, wire::Error> {
        let expected = admission::Expected::checked_claim(expected.claim())?;
        if mathematical.controllers.contains(&[0; 32]) {
            return Err(crate::BackendError::Shape.into());
        }
        mathematical.require_source(expected.claim())?;
        let statement = mathematical.statement(expected.claim())?;
        statement.require_expected(expected.claim())?;
        let salts = Zeroizing::new(
            mathematical
                .salts
                .map(|salt| salt.map(|v| v.as_canonical_u64())),
        );
        Ok(Self {
            expected,
            statement,
            salts,
            plain: Zeroizing::new(core::mem::replace(&mut mathematical.plain, [0; 2348])),
            controllers: Zeroizing::new(core::mem::take(&mut mathematical.controllers)),
            old: Zeroizing::new(core::mem::take(&mut mathematical.old)),
            command: mathematical.command.take().map(Zeroizing::new),
        })
    }
    fn require_expected(&self, expected: &admission::Expected) -> Result<(), wire::Error> {
        self.statement.require_expected(expected.claim())?;
        self.statement.require_expected(self.expected.claim())?;
        let _ = admission::Expected::checked_claim(expected.claim())?;
        Ok(())
    }
    fn trace(&self) -> Result<RowMajorMatrix<crate::Val>, crate::BackendError> {
        // Only transient native fields are reconstructed, after mandatory Source
        // verification and fixed child assessment. Persistent private banks are guarded.
        let mathematical = Witness {
            plain: *self.plain,
            controllers: *self.controllers,
            salts: (*self.salts).map(|salt| salt.map(crate::Val::from_u64)),
            old: (*self.old).clone(),
            command: self.command.as_ref().map(|c| (**c).clone()),
        };
        mathematical.trace(&self.statement)
    }
}

/// Complete public claim and unchanged bounded DCSLFPW1 bytes. Not a Journal,
/// authorization, ownership, agreed freshness or finality token.
pub struct Evidence {
    statement: Statement,
    bytes: Vec<u8>,
}
impl Evidence {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_parts(self) -> (Statement, Vec<u8>) {
        (self.statement, self.bytes)
    }
}

/// Captured full-Expected matching precedes Source backend creation. Source is
/// genuinely verified and dropped before child assessment, trace and proving.
pub fn prove(
    expected: &admission::Expected,
    witness: &PreparedWitness,
    source_bytes: &[u8],
) -> Result<Evidence, wire::Error> {
    witness.require_expected(expected)?;
    source::verification::verify(&expected.claim().source, source_bytes)?;
    let statement = witness.statement.clone();
    let bytes = {
        let backend = Backend::child(&statement)?;
        let proof = backend.prove(witness.trace()?)?;
        backend.verify(&proof)?;
        let child = codec::serialize(&proof, &backend.shape, wire::frame::MAX_CHILD_BYTES)?;
        let mut roots = vec![source::statement::encode_digest(statement.next)];
        if !expected.claim().is_bootstrap() {
            roots.push(source::statement::encode_digest(statement.result));
        }
        wire::frame::join(wire::role(expected.claim()), &roots, source_bytes, &child)?
    };
    Ok(Evidence { statement, bytes })
}
