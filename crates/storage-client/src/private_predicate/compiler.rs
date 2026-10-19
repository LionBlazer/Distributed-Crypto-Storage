//! Private exact-SQL compiler. No stored row is read and no SQL answer is calculated.
use p3_field::PrimeField64;
use registry200_proof::{
    BackendError as Error, Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        Role, commitment,
        statement::{BfvBinding, Expected},
    },
    source::statement as source,
};
use sha2::{Digest, Sha256};
use sql_plan::{Projection, QueryPlan, RowWindow};
use zeroize::Zeroizing;

/// Caller-owned private blind must be high entropy and must never be a public nonce.
pub struct CompiledPrivatePredicate {
    identity: [u8; 32],
    public_nonce: [u8; 32],
    mask: Zeroizing<[u8; 32]>,
}
impl CompiledPrivatePredicate {
    pub fn compile(
        sql: &str,
        private_blind: Zeroizing<[u8; 32]>,
        public_nonce: [u8; 32],
    ) -> Result<Self, Error> {
        if *private_blind == public_nonce || *private_blind == [0; 32] {
            return Err(Error::Shape);
        }
        let QueryPlan::Select {
            predicate,
            projection,
            window,
        } = sql_plan::parse_sql(sql).map_err(|_| Error::Shape)?
        else {
            return Err(Error::Shape);
        };
        if projection != Projection::AgeAmount || window != RowWindow::default() {
            return Err(Error::Shape);
        }
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-COEFFICIENT-PREDICATE/exact-SQL-private-blind/v1");
        h.update((sql.len() as u64).to_le_bytes());
        h.update(sql.as_bytes());
        h.update(*private_blind);
        Ok(Self {
            identity: h.finalize().into(),
            public_nonce,
            mask: Zeroizing::new(predicate.age_mask()),
        })
    }
    /// Stable prequery KeyExpected29 only: fresh CsHat cannot create a q/basis-job cycle.
    /// Copen, Cmask and Cw are excluded. Their complete bindings follow AFTER Source.
    pub fn query(&self, s: &source::Statement, bfv: &BfvBinding) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-COEFFICIENT-PREDICATE/pre-Source-q/stableKeyExpected29/v1");
        h.update(self.identity);
        h.update(self.public_nonce);
        h.update(bfv.full_setup());
        for head in &s.heads {
            h.update((head.len() as u64).to_le_bytes());
            h.update(head);
        }
        for v in s
            .key_commitment
            .into_iter()
            .chain(bfv.key().public_values().into_iter().take(29))
        {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        h.finalize().into()
    }
    pub fn bind(
        &self,
        s: &CanonicalSource,
        bfv: BfvBinding,
        salt: [Val; 4],
    ) -> Result<(Expected, Expected, Zeroizing<[u8; 32]>), Error> {
        if s.claim().request != self.query(s.claim(), &bfv) {
            return Err(Error::Shape);
        }
        let source = Expected::source(s, bfv.clone())?;
        let draft =
            Expected::private_mask(s, bfv.clone(), self.identity, self.public_nonce, [0; 32])?;
        assert_eq!(draft.role(), Role::PrivateMask);
        let root =
            commitment::command_digest(&commitment::command_fields(&draft, *self.mask, salt));
        let query = Expected::private_mask(
            s,
            bfv,
            self.identity,
            self.public_nonce,
            source::encode_digest(root),
        )?;
        Ok((source, query, Zeroizing::new(*self.mask)))
    }
}
