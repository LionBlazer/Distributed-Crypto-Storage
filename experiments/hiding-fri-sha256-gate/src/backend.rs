//! Experimental Kind/public-statement policy around the shared fixed hiding engine.
use crate::primitive::{Kind, PrimitiveAir, PrimitiveStatement, PublicStatement};
use crate::{chacha, poly1305};
pub(crate) use bfv_hiding_stark::{
    AllocationEstimate, Config, Error, PROOF_DEGREE_BITS, QUERIES, RANDOM_CODEWORDS,
    SecurityReport, TRACE_HEIGHT, Val, config,
};
#[cfg(test)]
pub(crate) use bfv_hiding_stark::{Challenge, Challenger, LOG_BLOWUP, Pcs};
use p3_air::BaseAir;
use p3_sha256_air::NUM_SHA256_COLS;
use p3_uni_stark::{Proof, StarkSecurityParams};
use sha2::Digest;
const _: () = assert!(NUM_SHA256_COLS == 7728);
pub(crate) fn analyze(air: &PrimitiveAir) -> Result<(StarkSecurityParams, SecurityReport), Error> {
    bfv_hiding_stark::analyze(air)
}
pub(crate) fn profile_digest(kind: Kind) -> [u8; 32] {
    let mut hash = bfv_hiding_stark::profile_start(
        b"dcs/experiment/hiding-source-primitive-profile/v1",
        kind.name().as_bytes(),
    );
    let (width, opening_points) = match kind {
        Kind::FactorizedPackedCanonicalIndexOpening => {
            crate::opening::factorized::profile(&mut hash);
            (crate::opening::PACKED_WIDTH, 2)
        }
        Kind::StateCertificate => {
            crate::opening::state::certificate_profile(&mut hash);
            (crate::opening::PACKED_WIDTH, 2)
        }
        Kind::VersionSelection => {
            crate::opening::state::query_profile(&mut hash);
            (crate::opening::selection::air::WIDTH, 2)
        }
        Kind::BfvCiphertextFormation => {
            bfv_ciphertext_formation::profile(&mut hash);
            (bfv_ciphertext_formation::circuit::WIDTH, 2)
        }
        Kind::BfvKeyTransform => {
            crate::opening::key_transform::profile(&mut hash);
            (crate::opening::key_transform::air::WIDTH, 2)
        }
        Kind::BfvLockReturnedFormation => {
            crate::opening::locking::formation::profile(&mut hash);
            (crate::opening::local_formation::air::WIDTH, 2)
        }
        Kind::BfvLocalFormation => {
            crate::opening::local_formation::profile(&mut hash);
            (crate::opening::local_formation::air::WIDTH, 2)
        }
        Kind::BfvBasisConvolution => {
            crate::opening::basis_convolution::profile(&mut hash);
            (crate::opening::basis_convolution::air::WIDTH, 2)
        }
        Kind::VersionLockingSelection => {
            crate::opening::state::locking::profile(&mut hash);
            (crate::opening::locking::air::WIDTH, 2)
        }
        Kind::RegistryLifecycleBootstrap => {
            crate::opening::registry_lifecycle::profile(&mut hash, true);
            (crate::opening::registry_lifecycle::bootstrap::WIDTH, 2)
        }
        Kind::RegistryLifecycleEncoding => {
            crate::opening::registry_lifecycle::encoding::profile(&mut hash);
            (crate::opening::registry_lifecycle::encoding::air::WIDTH, 2)
        }
        Kind::RegistryLifecycle => {
            crate::opening::registry_lifecycle::profile(&mut hash, false);
            (crate::opening::registry_lifecycle::air_width(), 2)
        }
        Kind::RegistryBootstrap => {
            crate::opening::registry_bootstrap::profile(&mut hash);
            (crate::opening::registry_bootstrap::air::WIDTH, 2)
        }
        Kind::LockingSelection => {
            crate::opening::locking::profile(&mut hash);
            (crate::opening::locking::air::WIDTH, 2)
        }
        Kind::LockReturnedEncoding => {
            crate::opening::locking::encoding::profile(&mut hash);
            (crate::opening::locking::encoding::air::WIDTH, 2)
        }
        Kind::SelectedEncoding => {
            crate::opening::selection::encoding::profile(&mut hash);
            (crate::opening::selection::encoding::air::WIDTH, 2)
        }
        Kind::SelectionOpening => {
            crate::opening::selection::profile(&mut hash);
            (crate::opening::selection::air::WIDTH, 2)
        }
        Kind::PackedCanonicalIndexOpening => {
            crate::opening::packed_index_profile(&mut hash);
            (crate::opening::PACKED_WIDTH, 2)
        }
        Kind::CanonicalIndexOpening => {
            crate::opening::index_profile(&mut hash);
            (crate::opening::canonical::WIDTH, 2)
        }
        Kind::PairOpening => {
            crate::opening::profile(&mut hash);
            (crate::opening::air::WIDTH, 2)
        }
        Kind::Sha256 => {
            hash.update(b"SHA256-compression/one-public-case/repeat512/u32-big-endian");
            (NUM_SHA256_COLS, 1)
        }
        Kind::HChaCha20 | Kind::ChaCha20 => {
            hash.update(b"ChaCha20/20rounds/80quarter-rounds/u32-little-endian/bit-carry-v1");
            hash.update(b"input-constants-fixed/state512-next-columns/full-width-next-opening");
            hash.update(b"HChaCha-extract0..4,12..16-no-feedforward/ChaCha-feedforward16");
            for value in chacha::SCHEDULE
                .into_iter()
                .flatten()
                .chain(chacha::HCHACHA_OUTPUT)
                .chain([
                    16,
                    12,
                    8,
                    7,
                    chacha::QUARTER_ROUNDS,
                    chacha::air::PERIODIC_COLUMNS,
                ])
            {
                hash.update((value as u64).to_le_bytes());
            }
            for word in chacha::CONSTANTS {
                hash.update(word.to_le_bytes());
            }
            for row in 0..TRACE_HEIGHT {
                for step in 0..chacha::SCHEDULE.len() {
                    hash.update([u8::from(row < chacha::QUARTER_ROUNDS && row % 8 == step)]);
                }
            }
            (chacha::air::WIDTH, 2)
        }
        Kind::Poly1305Raw | Kind::Poly1305Padded => {
            hash.update(b"Poly1305/radix26/canonical-every-state/cyclic-carry32/v1");
            hash.update(b"public-raw-key-clamp-every-row/LE128-tag-plus-S/mod2^128");
            hash.update(b"raw-tail-append8L/padded-segments-zero-tail-full-hibit/no-empty-block");
            hash.update(
                b"segment-count-and-original-lengths-bound/first-H0/final-tag/degree-bound3",
            );
            hash.update(poly1305::CLAMP);
            for value in [
                poly1305::LIMBS,
                poly1305::LIMB_BITS,
                poly1305::MAX_BLOCKS,
                poly1305::MAX_SEGMENTS,
                poly1305::MAX_BYTES,
                poly1305::air::WIDTH,
                poly1305::statement::PUBLIC_VALUES,
            ] {
                hash.update((value as u64).to_le_bytes());
            }
            for row in 0..TRACE_HEIGHT {
                for block in 0..poly1305::MAX_BLOCKS {
                    hash.update([u8::from(row == block)]);
                }
            }
            (poly1305::air::WIDTH, 2)
        }
    };
    bfv_hiding_stark::profile_finish(hash, width, opening_points)
}

/// Independent test-only adversarial SDK construction for the unchanged r5/r4 scenarios.
#[cfg(test)]
pub(crate) fn contract_pcs(random_codewords: usize) -> Result<Pcs, Error> {
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_fri::FriParameters;
    use p3_goldilocks::default_goldilocks_poseidon2_12;
    use rand::{
        SeedableRng,
        rngs::{StdRng, SysRng},
    };
    let rng = || StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness);
    let mmcs = || {
        let permutation = default_goldilocks_poseidon2_12();
        Ok::<_, Error>(bfv_hiding_stark::Mmcs::new(
            bfv_hiding_stark::Hash::new(permutation.clone()),
            bfv_hiding_stark::Compress::new(permutation),
            0,
            rng()?,
        ))
    };
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ExtensionMmcs::new(mmcs()?),
    };
    Ok(Pcs::new(
        Radix2DitParallel::default(),
        mmcs()?,
        fri,
        random_codewords,
        rng()?,
    ))
}

/// One typed public statement owns this backend's analytical parameters.
/// Exact public values bind its lifetime; another statement requires a new
/// backend even when kind/width match (empty and nonempty degrees may differ).
/// The same immutable, public AIR is analyzed, proved and verified throughout.
pub(crate) struct Backend {
    pub(crate) config: Config,
    pub(crate) parameters: StarkSecurityParams,
    pub(crate) report: SecurityReport,
    kind: Kind,
    public_values: Vec<Val>,
    air: PrimitiveAir,
}
impl Backend {
    pub(crate) fn new(statement: &impl PublicStatement) -> Result<Self, Error> {
        let air = statement.air();
        let (parameters, report) = analyze(&air)?;
        let report = report.require_target()?;
        let public_values = statement.public_values();
        if public_values.len() != air.num_public_values() {
            return Err(Error::Shape);
        }
        Ok(Self {
            config: config()?,
            parameters,
            report,
            kind: statement.kind(),
            public_values,
            air,
        })
    }

    /// Read-only public context already analyzed for this exact Backend.
    /// This does not expose configuration, witness data or an unchecked report.
    pub(crate) fn checked_public_air(&self) -> (Kind, &PrimitiveAir) {
        (self.kind, &self.air)
    }

    pub(crate) fn prove(
        &self,
        statement: &impl PrimitiveStatement,
    ) -> Result<Proof<Config>, Error> {
        self.prove_with_trace(statement, || Ok(statement.trace()))
    }

    /// A witness factory is invoked only after exact public-statement binding.
    /// It receives no owner key or key-export callback; this backend is experiment-private.
    pub(crate) fn prove_with_trace(
        &self,
        statement: &impl PublicStatement,
        trace: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
    ) -> Result<Proof<Config>, Error> {
        let public_values = statement.public_values();
        if statement.kind() != self.kind || public_values != self.public_values {
            return Err(Error::Shape);
        }
        let trace = trace()?;
        bfv_hiding_stark::prove_with_config(&self.config, &self.air, trace, &public_values)
    }

    pub(crate) fn verify(
        &self,
        statement: &impl PublicStatement,
        proof: &Proof<Config>,
    ) -> Result<(), Error> {
        let public_values = statement.public_values();
        if statement.kind() != self.kind || public_values != self.public_values {
            return Err(Error::Shape);
        }
        bfv_hiding_stark::verify_with_assessment(
            &self.config,
            &self.air,
            &self.parameters,
            self.report,
            proof,
            &public_values,
        )
    }
}
