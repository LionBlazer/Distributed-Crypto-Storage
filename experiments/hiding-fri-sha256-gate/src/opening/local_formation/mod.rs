//! Nonaccepting owner-local composition. Public fixtures never substitute for peer FHE.
pub(crate) mod air;
#[cfg(test)]
mod returned_replay_tests;
mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;

use crate::backend::{Backend, Config, Error, Val};
use crate::opening::{
    basis_convolution as basis, key_transform,
    selection::{self, encoding},
    trace as source_trace,
};
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use statement::{Expected, Statement};
use trace::Witness;

pub(in crate::opening) const N: usize = 8192;
pub(in crate::opening) const STREAMS: usize = 7;
pub(in crate::opening) const Q: [u64; 5] = [
    8796092858369,
    8796092792833,
    17592186028033,
    17592185438209,
    17592184717313,
];
pub(in crate::opening) const DELTA: [u64; 5] = [
    2868552913433,
    2398181390884,
    1315015483772,
    5109279048220,
    8726683229755,
];
pub(super) const NOISE_DOMAIN: &[u8] = b"DCS/BFV-LOCAL-FORMATION-NOISE/v1";
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"DCS/BFV-local-formation/full8192/signed-integer/v1/no-SQL-acceptance");
    h.update(crate::backend::profile_digest(
        crate::primitive::Kind::BfvBasisConvolution,
    ));
    h.update(crate::backend::profile_digest(
        crate::primitive::Kind::SelectedEncoding,
    ));
    h.update(NOISE_DOMAIN);
    h.update(b"exact-old-CR-context/rawGold/exact-old-Cenc-context/rawW/new-Ce/raw-signedGold");
    h.update(b"R=z63-2^62/k=z20-2^19/e=z6-20+slack40/W17+slack114688/shared-e-all5");
    h.update(b"7streams/21unconditional-P2/row0-prefix+0..7-carry8..15/row1carry+16..31/last-g1");
    for v in Q.into_iter().chain(DELTA).chain([
        N as u64,
        512,
        air::WIDTH as u64,
        44,
        592,
        5,
        114689,
        78307,
    ]) {
        h.update(v.to_le_bytes());
    }
}
struct Prerequisites {
    encoding: Option<encoding::CompositeProof>,
    key: Option<Proof<Config>>,
    bases: Vec<Proof<Config>>,
}
fn verify_inputs(e: &Expected, p: &Prerequisites) -> Result<(), Error> {
    e.validate()?;
    encoding::verify_composite(
        &e.source,
        &e.selection,
        &e.encoding,
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
fn prove_with_trace(
    e: &Expected,
    s: &Statement,
    p: &Prerequisites,
    factory: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    s.require_expected(e)?;
    verify_inputs(e, p)?; // All genuine prerequisites BEFORE local Backend/trace.
    Backend::new(s)?.prove_with_trace(s, factory)
}
fn verify(
    e: &Expected,
    s: &Statement,
    p: &Prerequisites,
    proof: &Proof<Config>,
) -> Result<(), Error> {
    s.require_expected(e)?;
    verify_inputs(e, p)?;
    Backend::new(s)?.verify(s, proof)
}
struct Fixture {
    statement: Statement,
    local: Witness,
    source: source_trace::Witness,
    selected: selection::trace::Witness,
    encoded: encoding::trace::Witness,
    key: key_transform::trace::Witness,
    bases: [basis::trace::Witness; 5],
}
fn salt(rng: &mut StdRng) -> [Val; 4] {
    core::array::from_fn(|_| rng.random::<Val>())
}
fn public_fixture() -> Result<Fixture, Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let mut mask = [0u8; 32];
    mask[0] = 1;
    mask[31] = 128;
    let (src, source, selected, sw) = selection::fixture(mask, Some(2))?;
    let ew = encoding::trace::Witness::from_selection(&selected, &sw, salt(&mut rng))?;
    let es = ew.statement(&selected);
    let rs: [[Val; 4]; 5] = core::array::from_fn(|_| salt(&mut rng));
    let descriptor = key_transform::statement::SetupDescriptor {
        database: src.heads[0][8..24].try_into().unwrap(),
        key_domain: [0x71; 16],
        public_setup_digest: basis::ciphertext::setup_digest(),
        key_epoch: 1,
    };
    let input = basis::PublicFixtureInput {
        original: ew.original(),
        descriptor,
        request: selected.request(),
        caller_noise_seed: [0x45; 32],
    };
    let (first, _, key) =
        basis::public_fixture_from_original(input, rs[0], [salt(&mut rng), salt(&mut rng)], 0)?;
    let bw: [basis::trace::Witness; 5] =
        core::array::from_fn(|i| basis::trace::Witness::new(&key, rs[i]));
    let mut bs = Vec::new();
    for (i, witness) in bw.iter().enumerate() {
        let expected = basis::statement::Expected::new(
            first.expected.key().clone(),
            first.expected.ciphertext().parameter_bytes(),
            first.expected.ciphertext().bytes(),
            selected.request(),
            i,
        )?;
        bs.push(witness.statement(expected));
    }
    let expected = Expected::new(src, selected, es, bs.try_into().map_err(|_| Error::Shape)?)?;
    // Exact upstream encrypt_poly consumes one sample_vec_cbd from this caller RNG;
    // the independent internal A seed is read from actual ciphertext, never replayed.
    let mut noise = <rand09::rngs::StdRng as rand09::SeedableRng>::from_seed([0x45; 32]);
    let error = fhe_util::sample_vec_cbd(N, 10, &mut noise)
        .map_err(|_| Error::Shape)?
        .into_iter()
        .map(i8::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Shape)?;
    let local = Witness::new(&expected, &key, &ew, error, rs, salt(&mut rng))?;
    let statement = local.statement(expected);
    Ok(Fixture {
        statement,
        local,
        source,
        selected: sw,
        encoded: ew,
        key,
        bases: bw,
    })
}
fn prove_inputs(f: &Fixture) -> Result<Prerequisites, Error> {
    let e = &f.statement.expected;
    let encoded = encoding::prove_composite(
        &e.source,
        &f.source,
        &e.selection,
        &f.selected,
        &e.encoding,
        &f.encoded,
    )?;
    encoding::verify_composite(&e.source, &e.selection, &e.encoding, &encoded)?;
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
        encoding: Some(encoded),
        key: Some(key),
        bases,
    })
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    let f = public_fixture()?;
    crate::security(&f.statement, "public-nonsecret-full8192-local-formation")?;
    if mode == "security" {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let p = prove_inputs(&f)?;
    let proof = prove_with_trace(&f.statement.expected, &f.statement, &p, || {
        f.local.trace(&f.statement)
    })?;
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    verify(&f.statement.expected, &f.statement, &p, &proof)?;
    println!(
        "{{\"stage\":\"verified_experimental_bfv_local_formation\",\"proving_ms\":{},\"verification_ms\":{}}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
