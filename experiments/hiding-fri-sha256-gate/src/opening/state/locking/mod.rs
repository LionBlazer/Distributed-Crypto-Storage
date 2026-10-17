//! Query-specific private locking over an ACTUALLY admitted version certificate.
//! The lease is the source authority; this module has no direct accepting path.
#[cfg(test)]
mod sql_tests;
#[cfg(test)]
mod tests;

use super::{
    StateStatement,
    certificate::{Candidate, CertificateCache},
    salt,
};
use crate::backend::{Backend, Error, Val, profile_digest};
use crate::opening::{
    commitment,
    locking::{
        statement as locked,
        trace::{Plan, Registry, Transaction, Witness},
    },
};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use sha2::{Digest, Sha256};

pub(in crate::opening) const PLAN_DOMAIN: [u8; 16] = *b"DCS/VLPLAN/N4/v1";
pub(in crate::opening) const RETURN_DOMAIN: [u8; 16] = *b"DCS/VLRET/N4/v1!";
pub(in crate::opening) const OWNED_DOMAIN: [u8; 16] = *b"DCS/VLOWN/N4/v1!";

/// Independently expected state and fresh control/query context. Its private
/// typed source contract cannot be constructed by relabeling a canonical query.
#[derive(Clone)]
pub(super) struct Expected {
    inner: locked::Expected,
}
impl Expected {
    pub(super) fn checked(
        state: &StateStatement,
        request: [u8; 32],
        genesis: [u8; 32],
        parent: [u8; 32],
        old: [u8; 32],
        plan: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: locked::Expected::for_state(state, request, genesis, parent, old, plan)?,
        })
    }
    pub(super) fn require_state(&self, state: &StateStatement) -> Result<(), Error> {
        if self.inner.kind() != Kind::VersionLockingSelection || !state.matches(&self.inner.source)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}

/// Output commitments are untrusted until StateLease::verify_lock succeeds.
#[derive(Clone)]
pub(super) struct Statement {
    inner: locked::Statement,
}
impl Statement {
    pub(super) fn checked(
        expected: &Expected,
        returned: [u8; 32],
        owned: [u8; 32],
        next: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: locked::Statement::checked(&expected.inner, returned, owned, next)?,
        })
    }
    pub(super) fn proposed(expected: &Expected, witness: &Witness) -> Result<Self, Error> {
        let proposed = locked::proposed(&expected.inner, witness)?;
        Self::checked(
            expected,
            locked::encoded(proposed.returned),
            locked::encoded(proposed.owned),
            locked::encoded(proposed.next),
        )
    }
    pub(super) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        if self.kind() != Kind::VersionLockingSelection {
            return Err(Error::Shape);
        }
        self.inner.require_expected(&expected.inner)
    }
    pub(super) fn require_state(&self, state: &StateStatement) -> Result<(), Error> {
        if self.kind() != Kind::VersionLockingSelection
            || !state.matches(&self.inner.expected.source)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn source(&self) -> &locked::Statement {
        &self.inner
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        self.inner.kind()
    }
    fn air(&self) -> PrimitiveAir {
        self.inner.air()
    }
    fn public_values(&self) -> Vec<Val> {
        self.inner.public_values()
    }
}

pub(crate) fn profile(hash: &mut Sha256) {
    hash.update(b"DCS/experimental/version-locking-selection/N4-T2/v1/no-live-grant");
    hash.update(profile_digest(Kind::StateCertificate));
    hash.update(profile_digest(Kind::LockingSelection));
    hash.update(PLAN_DOMAIN);
    hash.update(RETURN_DOMAIN);
    hash.update(OWNED_DOMAIN);
    hash.update(b"actual-verified-StateLease/exact-full-StateStatement/independent-query-request");
    hash.update(b"source=STATE87+587+6/version-tag-not-query/same-stable-Registry112");
    hash.update(b"same-six-stream-locking1948/PV116/plan144/outputs168/no-source-reprove");
}

/// PUBLIC NONSECRET client fixture. Computing native anchors here does not make
/// those anchors authoritative: prove/verify always receive independent Expected.
fn fixture(
    state: &StateStatement,
    plain: [u8; 2348],
    state_salt: [Val; 4],
    request: [u8; 32],
    parent: [u8; 32],
    empty: bool,
) -> Result<(Expected, Witness), Error> {
    let plan = Plan::checked(
        [0x31; 32],
        if empty { [0; 32] } else { [255; 32] },
        0,
        4,
        2,
        (0, Some(if empty { 0 } else { 2 })),
        2,
    )?;
    let witness = Witness {
        plain,
        old: Registry {
            revision: 2,
            tx: core::array::from_fn(|t| Transaction {
                id: t as u32 + 1,
                controller: [0x41 + t as u8; 32],
                sequence: 1,
                failed: false,
                held: [0; 4],
            }),
        },
        plan,
        salts: [state_salt, salt()?, salt()?, salt()?, salt()?, salt()?],
    };
    let mut expected = Expected::checked(state, request, [0xA1; 32], parent, [0; 32], [0; 32])?;
    pin(&mut expected, &witness);
    Ok((expected, witness))
}
fn pin(expected: &mut Expected, witness: &Witness) {
    expected.inner.old = commitment::digest(&locked::registry_fields(
        &expected.inner,
        witness,
        &witness.old,
        witness.salts[1],
    ));
    expected.inner.plan = commitment::digest(&locked::plan_fields(&expected.inner, witness));
}

/// Same real fixture, with the plan supplied by the client SQL compiler.
fn sql_fixture(
    state: &StateStatement,
    plain: [u8; 2348],
    state_salt: [Val; 4],
    compiled: &crate::opening::locking::sql::CompiledLockPlan,
    parent: [u8; 32],
) -> Result<(Expected, Witness), Error> {
    let (mut expected, mut witness) =
        fixture(state, plain, state_salt, compiled.request(), parent, false)?;
    witness.plan = compiled.plan(witness.plan.table, witness.plan.actor)?;
    pin(&mut expected, &witness);
    Ok((expected, witness))
}

/// Numeric mode constructs bounded native fixture metadata only. Prove mode
/// performs ONE cold source proof/admission and TWO fresh warm lock proofs.
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    use std::time::Instant;
    let (state, source_witness, plain, state_salt) = super::fixture()?;
    let first_sql = crate::opening::locking::sql::CompiledLockPlan::fresh(
        "SELECT amount FROM records FOR UPDATE SKIP LOCKED LIMIT 2",
    )?;
    let (first_expected, first_witness) =
        sql_fixture(&state, plain, state_salt, &first_sql, [0xB1; 32])?;
    let first = Statement::proposed(&first_expected, &first_witness)?;
    crate::security(&first, "version-bound-private-locking-N4-T2")?;
    if mode == "security" {
        return Ok(());
    }
    if mode != "prove" {
        return Err(Error::Shape);
    }
    let (proof, proving) = {
        let cold_witness = source_witness;
        let source_backend = Backend::new(&state)?;
        let started = Instant::now();
        let proof =
            source_backend.prove_with_trace(&state, || cold_witness.trace(state.source()))?;
        (proof, started.elapsed())
    };
    // Source witness, key and Backend were scoped out before any warm call.
    let mut cache = CertificateCache::new(super::CACHE_BYTES)?;
    let candidate = Candidate::new(state.clone(), Some(proof))?;
    let started = Instant::now();
    cache.admit(&state, candidate)?;
    println!(
        "{{\"stage\":\"verified_experimental_lock_state_certificate\",\"proving_ms\":{},\"verification_ms\":{},\"cache_owned_bytes\":{}}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0,
        cache.owned_bytes()
    );
    let second_sql = crate::opening::locking::sql::CompiledLockPlan::fresh(
        "SELECT amount FROM records WHERE FALSE LIMIT 0 FOR SHARE NOWAIT",
    )?;
    let (mut second_expected, mut second_witness) =
        sql_fixture(&state, plain, state_salt, &second_sql, [0xB2; 32])?;
    second_witness.old = first_witness.walk()?.next;
    second_witness.salts[1] = first_witness.salts[3];
    pin(&mut second_expected, &second_witness);
    assert_eq!(second_expected.inner.old, first.inner.next);
    let second = Statement::proposed(&second_expected, &second_witness)?;
    for (index, (expected, statement, witness)) in [
        (first_expected, first, first_witness),
        (second_expected, second, second_witness),
    ]
    .into_iter()
    .enumerate()
    {
        let lease = cache.lease(&state)?;
        let started = Instant::now();
        let proof = lease.prove_lock(&expected, &statement, &witness)?;
        let proving = started.elapsed();
        let started = Instant::now();
        lease.verify_lock(&expected, &statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_experimental_version_locking_selection\",\"query_index\":{},\"proving_ms\":{},\"verification_ms\":{},\"source_proof_degree_bits\":{},\"live_sql_grant\":false}}",
            index + 1,
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0,
            lease.source_proof_degree_bits()
        );
    }
    cache.clear();
    Ok(())
}
