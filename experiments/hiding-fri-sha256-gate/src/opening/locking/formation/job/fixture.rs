//! PUBLIC NONSECRET owner/client fixture. Keys never enter a peer argument.
use super::*;
use crate::opening::locking::{sql::CompiledLockPlan, statement::PlanOpening};
#[cfg(test)]
pub(super) use crate::opening::peer_process::PublicPeer;
use crate::opening::{
    basis_convolution as basis, key_transform, local_formation, selection::encoding,
};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
pub(super) const SQL: &str =
    "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED";

pub(super) struct Fixture {
    pub(super) expected: Expected,
    pub(super) formed: super::super::Fixture,
    pub(super) source: returned::Fixture,
    pub(super) client: basis::PublicFixtureClient,
    pub(super) bundle: peer_runtime::RawBundle,
}
pub(super) fn plan_opening(source: &returned::Fixture) -> PlanOpening {
    let tx = &source.lock.old.tx[usize::from(source.lock.plan.actor)];
    PlanOpening {
        table: source.lock.plan.table,
        transaction: tx.id,
        controller: tx.controller,
        sequence: tx.sequence,
        revision: source.lock.old.revision,
        salt: source.lock.salts[2],
    }
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
        let compiled = CompiledLockPlan::compile(SQL, [0x81; 32])?;
        let source = returned::fixture_for_compiled(&compiled)?;
        let bound = compiled.bind_returned(&source.encoding_expected, &plan_opening(&source))?;
        let encoded = encoding::trace::Witness::from_lock(
            &source.statement,
            &source.lock,
            source.witness.encoding_salt,
        )?;
        let (formed, client) = form_returned_fixture(
            source.encoding_expected.clone(),
            source.statement.clone(),
            encoded,
        )?;
        let raw = &source.expected.source;
        let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
            raw.heads[i]
                .iter()
                .chain(&raw.packets[i])
                .copied()
                .collect()
        });
        let data = compact_store::EncryptedSnapshot::decode(
            &images[0],
            crate::opening::statement::limits(),
        )
        .map_err(|_| InputError::Shape)?;
        let index = compact_store::EncryptedSnapshot::decode(
            &images[1],
            crate::opening::statement::limits(),
        )
        .map_err(|_| InputError::Shape)?;
        let bundle = peer_runtime::RawBundle::from_snapshots(&data, &index)
            .map_err(|_| InputError::Shape)?;
        let target = bundle.target_version().map_err(|_| InputError::Shape)?;
        let setup_bytes = client.setup().to_bytes()?;
        let binding = Binding {
            request: *source.expected.request(),
            query_id: [0x21; 16],
            parent: source.expected.parent,
            target,
            setup_id: Sha256::digest(&setup_bytes).into(),
            parameters: client.setup().update_parameters()?.to_bytes()?,
        };
        let expected = Expected::new(
            formed.statement.expected.clone(),
            formed.statement.clone(),
            binding,
            bound,
            &setup_bytes,
        )?;
        Ok(Self {
            expected,
            formed,
            source,
            client,
            bundle,
        })
    }
    pub(super) fn prove(
        &self,
    ) -> Result<(
        crate::opening::locking::CompositeProof,
        Prerequisites,
        Proof<Config>,
    )> {
        let (_, parent) = crate::opening::locking::prove_composite(
            &self.source.expected,
            &self.source.source,
            &self.source.lock,
        )?;
        let es = self.formed.statement.expected.encoding();
        let encoding = returned::prove_with_trace(
            &self.source.encoding_expected,
            es,
            Some(returned::Evidence::Canonical(&parent)),
            || self.formed.encoded.trace_returned(es),
        )?;
        let prerequisites = super::super::prove_bases(&self.formed, encoding)?;
        let statement = &self.formed.statement;
        let proof = super::super::prove_with_trace(
            &statement.expected,
            statement,
            Some(returned::Evidence::Canonical(&parent)),
            &prerequisites,
            || self.formed.local.trace_returned(statement),
        )?;
        Ok((parent, prerequisites, proof))
    }
}
pub(super) fn gate(peer_executable: &std::path::Path) -> Result<()> {
    let fixture = Fixture::new()?;
    let started = std::time::Instant::now();
    let (parent, prerequisites, proof) = fixture.prove()?;
    let prepared = prepare(
        &fixture.expected,
        Some(returned::Evidence::Canonical(&parent)),
        &prerequisites,
        &proof,
    )?;
    // No child launch or network I/O precedes real prerequisite admission.
    // The independent daemon receives only its own TLS bootstrap, encrypted
    // images, full PUBLIC setup and ciphertext job; never a BFV key/witness.
    let mut peer = super::process::ProcessPeer::start(peer_executable, &fixture.bundle)?;
    let verified = prepared.run_remote(&fixture.expected, &peer.remote)?;
    let decoded = fixture
        .client
        .decrypt_product_unverified(verified.canonical_output())?;
    let mut expected = vec![0u64; super::super::N];
    expected[4096] = fixture.formed.encoded.original()[4];
    expected[512] = 1;
    if decoded != expected {
        return Err(Error::Binding);
    }
    let identity = verified
        .identity()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let request_id = peer.last_request_id()?;
    let peer_pid = peer.pid();
    let completion = peer.finish().map_err(Error::from)?;
    println!(
        "{}",
        serde_json::json!({
            "stage": "verified_experimental_certified_projection_job",
            "worker": "independent_dcs_peer_process", "elapsed_ms": started.elapsed().as_secs_f64()*1000.0,
            "input_binding": identity, "rpc_request_id": request_id, "peer_pid": peer_pid,
            "peer_exit_code": completion.code, "peer_stdout": completion.stdout,
            "peer_stderr": completion.stderr, "encrypted_response_bytes": verified.encrypted_response().len(),
            "operation": format!("{:?}", verified.checked().operation()), "public_projection": true,
            "live_sql_grant": false, "resource_scope": "owner_and_peer_are_separate_processes"
        })
    );
    Ok(())
}

#[cfg(test)]
impl Fixture {
    pub(super) fn expected_with_binding(&self, binding: Binding) -> Result<Expected> {
        let compiled = CompiledLockPlan::compile(SQL, [0x81; 32])?;
        let query =
            compiled.bind_returned(&self.source.encoding_expected, &plan_opening(&self.source))?;
        Expected::new(
            self.formed.statement.expected.clone(),
            self.formed.statement.clone(),
            binding,
            query,
            &self.expected.setup_bytes,
        )
    }
}

/// PUBLIC NONSECRET fresh encryption/setup from the SAME returned originals and
/// fixed fixture key. No source-kind relabel and no caller secret/key import.
pub(in crate::opening) fn form_returned_fixture(
    producer: returned::statement::Expected,
    encoded_statement: returned::statement::Statement,
    encoded: encoding::trace::Witness,
) -> Result<(super::super::Fixture, basis::PublicFixtureClient)> {
    encoded_statement.require_expected(&producer)?;
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| InputError::Randomness)?;
    let salts = core::array::from_fn(|_| super::super::salt(&mut rng));
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
        caller_noise_seed: [0x45; 32],
    };
    let (first, _, key, client) = basis::public_fixture_with_setup(
        input,
        salts[0],
        [super::super::salt(&mut rng), super::super::salt(&mut rng)],
        0,
    )?;
    let bases: [basis::trace::Witness; 5] =
        core::array::from_fn(|i| basis::trace::Witness::new(&key, salts[i]));
    let mut statements = Vec::with_capacity(5);
    for (i, witness) in bases.iter().enumerate() {
        let e = basis::statement::Expected::new(
            first.expected.key().clone(),
            first.expected.ciphertext().parameter_bytes(),
            first.expected.ciphertext().bytes(),
            *lock.expected.request(),
            i,
        )?;
        statements.push(witness.statement(e));
    }
    let expected = formation::Expected::new(
        producer,
        encoded_statement,
        statements.try_into().map_err(|_| InputError::Shape)?,
    )?;
    use rand09::SeedableRng as _;
    let mut noise = rand09::rngs::StdRng::from_seed([0x45; 32]);
    let error = fhe_util::sample_vec_cbd(super::super::N, 10, &mut noise)
        .map_err(|_| InputError::Shape)?
        .into_iter()
        .map(i8::try_from)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| InputError::Shape)?;
    let local = local_formation::trace::Witness::returned(
        &expected,
        &key,
        &encoded,
        error,
        salts,
        super::super::salt(&mut rng),
    )?;
    let statement = super::super::proposed(expected, &local);
    Ok((
        super::super::Fixture {
            statement,
            local,
            encoded,
            key,
            bases,
        },
        client,
    ))
}
