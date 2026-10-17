//! Successful private lock originals -> actual full8192 BFV formation, no live grant.
pub(crate) mod job;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
use super::encoding as returned;
use crate::backend::{Backend, Config, Error, Val};
use crate::opening::{
    basis_convolution as basis, key_transform,
    local_formation::{self, air, trace::Witness},
    selection::encoding,
};
use crate::primitive::Kind;
pub(super) use local_formation::{DELTA, N, Q};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use statement::{Expected, Statement};
const NOISE_DOMAIN: &[u8] = b"DCS/BFV-LOCK-RETURNED-FORMATION-NOISE/v1";
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"DCS/BFV-lock-returned-formation/full8192/signed-integer/v1/no-live-grant");
    h.update(crate::backend::profile_digest(Kind::LockReturnedEncoding));
    h.update(crate::backend::profile_digest(Kind::BfvBasisConvolution));
    h.update(NOISE_DOMAIN);
    h.update(
        b"sealed-fullPV128/canonical-or-actual-StateLease/real-all-prerequisites-before-Backend",
    );
    h.update(
        b"exact-CR/rawGold/exact-Return-Cenc/rawW/new-Ce/rawsignedGold/fresh-query-not-versiontag",
    );
    h.update(b"R=z63-2^62/k=z20-2^19/e=z6-20+slack40/W17+slack114688/shared-e-all5");
    h.update(b"7streams/21unconditional-P2/row0-prefix+0..7-carry8..15/row1carry+16..31/last-g1");
    for value in Q.into_iter().chain(DELTA).chain([
        N as u64,
        512,
        air::WIDTH as u64,
        44,
        592,
        5,
        114689,
        78307,
    ]) {
        h.update(value.to_le_bytes());
    }
}
/// Completed proofs only. Parent evidence is freshly borrowed for every call.
pub(in crate::opening) struct Prerequisites {
    pub(in crate::opening) encoding: Option<Proof<Config>>,
    pub(in crate::opening) key: Option<Proof<Config>>,
    pub(in crate::opening) bases: Vec<Proof<Config>>,
}
fn verify_inputs(
    e: &Expected,
    parent: Option<returned::Evidence<'_, '_>>,
    p: &Prerequisites,
) -> Result<(), Error> {
    e.validate()?;
    returned::verify(
        e.producer(),
        e.encoding(),
        parent,
        p.encoding.as_ref().ok_or(Error::Shape)?,
    )?;
    let key = p.key.as_ref().ok_or(Error::Shape)?;
    key_transform::verify(
        &e.bases[0].expected.key().expected,
        e.bases[0].expected.key(),
        key,
    )?;
    if p.bases.len() != 5 {
        return Err(Error::Shape);
    }
    for (s, p) in e.bases.iter().zip(&p.bases) {
        basis::verify_child(&s.expected, s, key, p)?;
    }
    Ok(())
}
pub(in crate::opening) fn prove_with_trace(
    e: &Expected,
    s: &Statement,
    parent: Option<returned::Evidence<'_, '_>>,
    p: &Prerequisites,
    factory: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    s.require_expected(e)?;
    verify_inputs(e, parent, p)?;
    Backend::new(s)?.prove_with_trace(s, factory)
}
pub(in crate::opening) fn verify(
    e: &Expected,
    s: &Statement,
    parent: Option<returned::Evidence<'_, '_>>,
    p: &Prerequisites,
    proof: &Proof<Config>,
) -> Result<(), Error> {
    s.require_expected(e)?;
    verify_inputs(e, parent, p)?;
    Backend::new(s)?.verify(s, proof)
}
pub(in crate::opening) fn proposed(expected: Expected, w: &Witness) -> Statement {
    let mut s = Statement {
        expected,
        noise: [Val::ZERO; 4],
    };
    s.noise = key_transform::trace::digest(
        s.noise_context(),
        w.salts[6],
        &w.error
            .iter()
            .map(|&e| local_formation::trace::signed(i128::from(e)))
            .collect::<Vec<_>>(),
    );
    s
}
pub(in crate::opening) struct Fixture {
    pub(in crate::opening) statement: Statement,
    pub(in crate::opening) local: Witness,
    pub(in crate::opening) encoded: encoding::trace::Witness,
    pub(in crate::opening) key: key_transform::trace::Witness,
    pub(in crate::opening) bases: [basis::trace::Witness; 5],
}
fn salt(rng: &mut StdRng) -> [Val; 4] {
    core::array::from_fn(|_| rng.random())
}
/// Creates only an explicitly PUBLIC NONSECRET upstream key/ciphertext fixture.
/// The actual returned originals, never an owner answer or OWNED set, supply SIMD.
pub(in crate::opening) fn from_encoding(
    producer: returned::statement::Expected,
    es: returned::statement::Statement,
    encoded: encoding::trace::Witness,
    noise_seed: [u8; 32],
) -> Result<Fixture, Error> {
    es.require_expected(&producer)?;
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let rs: [[Val; 4]; 5] = core::array::from_fn(|_| salt(&mut rng));
    let lock = producer.lock();
    let input = basis::PublicFixtureInput {
        original: encoded.original(),
        descriptor: key_transform::statement::SetupDescriptor {
            database: lock.expected.source.heads[0][8..24].try_into().unwrap(),
            key_domain: [0x71; 16],
            public_setup_digest: basis::ciphertext::setup_digest(),
            key_epoch: 1,
        },
        request: *lock.expected.request(),
        caller_noise_seed: noise_seed,
    };
    let (first, _, key) =
        basis::public_fixture_from_original(input, rs[0], [salt(&mut rng), salt(&mut rng)], 0)?;
    let bw: [basis::trace::Witness; 5] =
        core::array::from_fn(|i| basis::trace::Witness::new(&key, rs[i]));
    let mut bs = Vec::new();
    for (i, w) in bw.iter().enumerate() {
        let e = basis::statement::Expected::new(
            first.expected.key().clone(),
            first.expected.ciphertext().parameter_bytes(),
            first.expected.ciphertext().bytes(),
            *lock.expected.request(),
            i,
        )?;
        bs.push(w.statement(e));
    }
    let expected = Expected::new(producer, es, bs.try_into().map_err(|_| Error::Shape)?)?;
    // Caller RNG controls CBD e only; upstream A has its own independent OS seed.
    let mut noise = <rand09::rngs::StdRng as rand09::SeedableRng>::from_seed(noise_seed);
    let error = fhe_util::sample_vec_cbd(N, 10, &mut noise)
        .map_err(|_| Error::Shape)?
        .into_iter()
        .map(i8::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Shape)?;
    let local = Witness::returned(&expected, &key, &encoded, error, rs, salt(&mut rng))?;
    let statement = proposed(expected, &local);
    Ok(Fixture {
        statement,
        local,
        encoded,
        key,
        bases: bw,
    })
}
pub(in crate::opening) fn prove_bases(
    f: &Fixture,
    encoding: Proof<Config>,
) -> Result<Prerequisites, Error> {
    let e = &f.statement.expected;
    let key = {
        let s = e.bases[0].expected.key();
        let b = Backend::new(s)?;
        let proof = b.prove_with_trace(s, || f.key.trace(s))?;
        b.verify(s, &proof)?;
        proof
    };
    let mut bases = Vec::with_capacity(5);
    for (s, w) in e.bases.iter().zip(&f.bases) {
        bases.push(basis::prove_child(&s.expected, s, &key, || w.trace(s))?);
    }
    Ok(Prerequisites {
        encoding: Some(encoding),
        key: Some(key),
        bases,
    })
}
pub(in crate::opening) struct CanonicalFixture {
    pub(in crate::opening) f: Fixture,
    parent: super::statement::Expected,
    source: crate::opening::trace::Witness,
    lock: super::trace::Witness,
}
pub(in crate::opening) fn canonical_fixture(empty: bool) -> Result<CanonicalFixture, Error> {
    let sql = if empty {
        "SELECT age,amount FROM records WHERE FALSE LIMIT 0 FOR UPDATE"
    } else {
        "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED"
    };
    let compiled = super::sql::CompiledLockPlan::fresh(sql)?;
    let (mut expected, source, mut lock) = super::sql_fixture(&compiled)?;
    lock.old.tx[1].held[0] = 4;
    expected.old = crate::opening::commitment::digest(&super::statement::registry_fields(
        &expected,
        &lock,
        &lock.old,
        lock.salts[1],
    ));
    expected.plan =
        crate::opening::commitment::digest(&super::statement::plan_fields(&expected, &lock));
    let parent = super::statement::proposed(&expected, &lock)?;
    let ee = returned::statement::Expected::canonical(&expected, &parent)?;
    let shape = returned::statement::Statement::new(ee.clone(), [Val::ZERO; 4]);
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let ew = encoding::trace::Witness::from_lock(&shape, &lock, salt(&mut rng))?;
    let es = ew.returned_statement(ee.clone());
    let f = from_encoding(ee, es, ew, [0x45; 32])?;
    Ok(CanonicalFixture {
        f,
        parent: expected,
        source,
        lock,
    })
}
fn prove_canonical(f: &CanonicalFixture) -> Result<(super::CompositeProof, Prerequisites), Error> {
    let (_, parent) = super::prove_composite(&f.parent, &f.source, &f.lock)?;
    let e = &f.f.statement.expected;
    let p = returned::prove_with_trace(
        &e.producer,
        &e.encoding,
        Some(returned::Evidence::Canonical(&parent)),
        || f.f.encoded.trace_returned(&e.encoding),
    )?;
    Ok((parent, prove_bases(&f.f, p)?))
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    let f = canonical_fixture(false)?;
    crate::security(
        &f.f.statement,
        "public-nonsecret-successful-lock-return-formation",
    )?;
    if mode == "security" {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let (parent, p) = prove_canonical(&f)?;
    let s = &f.f.statement;
    let proof = prove_with_trace(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
        || f.f.local.trace_returned(s),
    )?;
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    verify(
        &s.expected,
        s,
        Some(returned::Evidence::Canonical(&parent)),
        &p,
        &proof,
    )?;
    println!(
        "{{\"stage\":\"verified_experimental_bfv_lock_returned_formation\",\"proving_ms\":{},\"verification_ms\":{}}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
