//! Experimental VERSION certificate and request-specific private selection.
//! No network/SQL accepting API, freshness cache or key-custody API.
pub(in crate::opening) mod certificate;
pub(crate) mod locking;
mod query;
#[cfg(test)]
mod tests;

use super::{Relation, fixture, statement as source, trace};
use crate::backend::{Backend, Error, Val, profile_digest};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use certificate::{Candidate, CertificateCache};
use compact_store::Commitment;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};

pub(super) const STATE_DOMAIN: [u8; 16] = *b"DCS/STATE/N4/v1!";
pub(super) const PLAN_DOMAIN: [u8; 16] = *b"DCS/VPLAN/N4/v1!";
pub(super) const SELECT_DOMAIN: [u8; 16] = *b"DCS/VSEL/N4/v1!!";
const CACHE_BYTES: usize = 64 * 1024 * 1024;

/// PUBLIC canonical state only. Clone duplicates no proof or private witness.
/// Callers must independently authorize both heads and C_key before construction.
#[derive(Clone)]
pub(in crate::opening) struct StateStatement {
    source: source::Statement,
}
impl StateStatement {
    fn checked(
        images: [&[u8]; 2],
        expected: [&Commitment; 2],
        key: [u8; 32],
        state: [u8; 32],
    ) -> Result<Self, Error> {
        let mut source = source::Statement::checked_relation(
            Relation::StateCertificate,
            images,
            expected,
            [0; 32],
            key,
            state,
        )?;
        source.request = version_tag(&source);
        Ok(Self { source })
    }
    pub(in crate::opening) fn source(&self) -> &source::Statement {
        &self.source
    }
    fn matches(&self, other: &source::Statement) -> bool {
        self.source.relation == Relation::StateCertificate
            && other.relation == Relation::StateCertificate
            && self.source.request == other.request
            && self.source.heads == other.heads
            && self.source.packets == other.packets
            && self.source.key_commitment == other.key_commitment
            && self.source.open_commitment == other.open_commitment
    }
}
impl PublicStatement for StateStatement {
    fn kind(&self) -> Kind {
        Kind::StateCertificate
    }
    fn air(&self) -> PrimitiveAir {
        self.source.air()
    }
    fn public_values(&self) -> Vec<Val> {
        self.source.public_values()
    }
}

/// Deterministic public version tag, NOT a query request or freshness attestation.
/// Fixed profile + complete canonical public images + independently fixed C_key.
/// C_state is excluded to avoid a circular commitment definition.
pub(super) fn version_tag(statement: &source::Statement) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/experimental/version-state-tag/N4/v1");
    hash.update(profile_digest(Kind::StateCertificate));
    for (head, packet) in statement.heads.iter().zip(&statement.packets) {
        hash.update(((head.len() + packet.len()) as u64).to_le_bytes());
        hash.update(head);
        hash.update(packet);
    }
    hash.update(source::encode_digest(statement.key_commitment));
    hash.finalize().into()
}
pub(crate) fn certificate_profile(hash: &mut Sha256) {
    hash.update(b"DCS/experimental/state-certificate/N4/v1/no-freshness-SQL-acceptance");
    hash.update(profile_digest(Kind::PackedCanonicalIndexOpening));
    hash.update(STATE_DOMAIN);
    hash.update(b"version-tag=SHA256(profile/full-canonical-images/C_key)/no-query-request");
    hash.update(b"same-packed-AEAD-canonical-index/independent-C_key/state87+587+6");
}
pub(crate) fn query_profile(hash: &mut Sha256) {
    hash.update(b"DCS/experimental/version-selection/N4/v1/no-freshness-SQL-acceptance");
    hash.update(profile_digest(Kind::StateCertificate));
    hash.update(profile_digest(Kind::SelectionOpening));
    hash.update(PLAN_DOMAIN);
    hash.update(SELECT_DOMAIN);
    hash.update(b"actual-verified-owned-certificate/exact-full-state/separate-query-request");
    hash.update(b"same-selection957/plan107+5/selected82+6/open680/no-source-reprove");
}
fn salt() -> Result<[Val; 4], Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    Ok(core::array::from_fn(|_| rng.random::<Val>()))
}

/// PUBLIC NONSECRET fixture, separate from all product/Owner APIs.
fn fixture() -> Result<(StateStatement, trace::Witness, [u8; 2348], [Val; 4]), Error> {
    let open_salt = salt()?;
    let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let suffix = fixture::canonical_suffix();
    let (public, witness) = fixture::from_suffix(
        Relation::StateCertificate,
        core::array::from_fn(|i| i as u8),
        (salt()?, open_salt),
        [0; 32],
        data,
        &suffix,
    )?;
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        public.heads[i]
            .iter()
            .chain(&public.packets[i])
            .copied()
            .collect()
    });
    let heads: [Commitment; 2] =
        core::array::from_fn(|i| Commitment::decode(&public.heads[i], source::limits()).unwrap());
    let state = StateStatement::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::encode_digest(public.key_commitment),
        source::encode_digest(public.open_commitment),
    )?;
    assert_eq!(state.public_values(), public.public_values());
    let mut plain = [0; 2348];
    plain[..12].copy_from_slice(&data);
    plain[12..124].copy_from_slice(&public.heads[0]);
    plain[124..].copy_from_slice(&suffix);
    Ok((state, witness, plain, open_salt))
}

/// Security mode never generates a trace. Prove mode remains a nonaccepting gate.
pub(crate) fn gate(mode: &str, selection: bool) -> Result<(), Error> {
    use std::time::Instant;
    let (state, witness, plain, state_salt) = fixture()?;
    let (first, first_witness) = query::fixture(&state, plain, state_salt, [0x11; 32], false)?;
    if selection {
        crate::security(&first, "version-bound-private-selection")?;
    } else {
        crate::security(&state, "version-state-certificate")?;
    }
    if mode == "security" {
        return Ok(());
    }
    if mode != "prove" {
        return Err(Error::Shape);
    }
    let (proof, proving) = {
        let source_witness = witness;
        let backend = Backend::new(&state)?;
        let started = Instant::now();
        let proof = backend.prove_with_trace(&state, || source_witness.trace(state.source()))?;
        (proof, started.elapsed())
    }; // Neither source Backend nor source witness survives into warm queries.
    let candidate = Candidate::new(state.clone(), Some(proof))?;
    let mut cache = CertificateCache::new(CACHE_BYTES)?;
    let started = Instant::now();
    cache.admit(&state, candidate)?;
    let verification = started.elapsed();
    if !selection {
        println!(
            "{{\"stage\":\"verified_experimental_state_certificate\",\"proving_ms\":{},\"verification_ms\":{},\"cache_owned_bytes\":{}}}",
            proving.as_secs_f64() * 1000.0,
            verification.as_secs_f64() * 1000.0,
            cache.owned_bytes()
        );
        cache.clear();
        return Ok(());
    }
    // One actual source proof and actual admission above; no source witness,
    // Backend, prover data, key or trace is an input to either warm query path.
    let (second, second_witness) = query::fixture(&state, plain, state_salt, [0x22; 32], true)?;
    for (index, (statement, witness)) in [(first, first_witness), (second, second_witness)]
        .into_iter()
        .enumerate()
    {
        let lease = cache.lease(&state)?;
        let started = Instant::now();
        let proof = lease.prove_query(&statement, &witness)?;
        let proving = started.elapsed();
        let started = Instant::now();
        lease.verify_query(&statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_experimental_version_selection\",\"query_index\":{},\"proving_ms\":{},\"verification_ms\":{},\"source_proof_degree_bits\":{}}}",
            index + 1,
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0,
            lease.source_proof_degree_bits()
        );
    }
    cache.clear();
    Ok(())
}
