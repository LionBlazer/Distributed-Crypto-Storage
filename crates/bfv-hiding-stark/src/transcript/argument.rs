//! Fixed one-AIR hiding-PCS geometry, not proof validation or an accepted policy.
use super::{SeedBinding, inspect_separator};
use crate::{Challenge, EXTENSION_DEGREE, Error, LOG_BLOWUP, RANDOM_CODEWORDS, SALT_ELEMENTS, Val};
use p3_air::BaseAir;
use p3_field::PrimeField64;
use p3_fri::{FriShape, PcsShape};
use p3_uni_stark::StarkSecurityParams;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct MatrixGeometry {
    width: usize,
    opening_points: usize,
}
impl MatrixGeometry {
    /// Base-field columns after hiding codewords, before Merkle salts.
    pub fn width(&self) -> usize {
        self.width
    }
    pub fn opening_points(&self) -> usize {
        self.opening_points
    }
}

#[derive(Clone, Debug)]
pub struct CommitmentGeometry {
    matrices: Vec<MatrixGeometry>,
    salted_leaf_width: usize,
}
impl CommitmentGeometry {
    pub fn matrices(&self) -> &[MatrixGeometry] {
        &self.matrices
    }
    /// Concatenated equal-height rows, including one salt per matrix.
    pub fn salted_leaf_width(&self) -> usize {
        self.salted_leaf_width
    }
}

/// Actual SDK separator observations plus caller-associated one-AIR geometry.
/// This is a freely clonable diagnostic, not mathematical or admission evidence.
#[derive(Clone, Debug)]
pub struct ArgumentManifest {
    stark: SeedBinding,
    pcs: SeedBinding,
    fri: SeedBinding,
    pcs_shape: PcsShape,
    fri_shape: FriShape,
    commitments: Vec<CommitmentGeometry>,
    lde_log: usize,
}
impl ArgumentManifest {
    pub fn stark(&self) -> &SeedBinding {
        &self.stark
    }
    pub fn pcs(&self) -> &SeedBinding {
        &self.pcs
    }
    pub fn fri(&self) -> &SeedBinding {
        &self.fri
    }
    pub fn pcs_shape(&self) -> &PcsShape {
        &self.pcs_shape
    }
    pub fn fri_shape(&self) -> &FriShape {
        &self.fri_shape
    }
    /// Native opening order: randomization, MAIN, quotient, optional PP/AUX.
    pub fn commitments(&self) -> &[CommitmentGeometry] {
        &self.commitments
    }
    pub fn lde_log(&self) -> usize {
        self.lde_log
    }
    /// Every binary FRI row contains two extension elements plus base salts.
    pub fn fri_salted_leaf_width(&self) -> usize {
        2 * EXTENSION_DEGREE + SALT_ELEMENTS
    }
    /// Heights of the actual binary FRI commitment matrices, in round order.
    pub fn fri_matrix_logs(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.fri_shape.log_arities.len()).map(|i| self.lde_log - i - 1)
    }
    /// Reproducibility fingerprint only; this authenticates no setup or proof.
    pub fn snapshot_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"DCS/fixed-hiding-argument-manifest/v1/no-admission\0");
        for seed in [&self.stark, &self.pcs, &self.fri] {
            hash.update(seed.protocol_id());
            hash.update(seed.pattern_hash());
            hash.update((seed.instance_label().len() as u64).to_le_bytes());
            hash.update(seed.instance_label());
            hash.update((seed.observed_fields().len() as u64).to_le_bytes());
            for field in seed.observed_fields() {
                hash.update(field.as_canonical_u64().to_le_bytes());
            }
        }
        for n in [
            self.lde_log,
            self.commitments.len(),
            self.fri_salted_leaf_width(),
        ] {
            hash.update((n as u64).to_le_bytes());
        }
        for group in &self.commitments {
            for n in [group.matrices.len(), group.salted_leaf_width] {
                hash.update((n as u64).to_le_bytes());
            }
            for matrix in &group.matrices {
                hash.update((matrix.width as u64).to_le_bytes());
                hash.update((matrix.opening_points as u64).to_le_bytes());
            }
        }
        hash.finalize().into()
    }
}

/// Inspect the existing fixed suite's one-AIR opening geometry without PP or RNG.
///
/// The owner must derive the AIR, parameters, complete STARK separator and the
/// already BASE-flattened AUX width from the same native instance. In particular,
/// AUX must not be multiplied by the extension dimension a second time. This
/// function checks internal dimensions and opening counts, not that association.
/// Only the current no-lookup uni and single-lookup-instance batch shapes apply.
pub fn inspect_argument<A: BaseAir<Val>>(
    air: &A,
    parameters: &StarkSecurityParams,
    committed_log: usize,
    aux_width: usize,
    stark: SeedBinding,
) -> Result<ArgumentManifest, Error> {
    // Reuse the suite/precondition validator and its actual public FRI builder.
    // No algebraic report is exported: original lookup association is not known here.
    let bound = crate::classical::analyze(parameters, committed_log, None)?;
    let main = air.width();
    let pp = air.preprocessed_width();
    if main == 0
        || main > 20_000
        || pp > 20_000
        || aux_width > 20_000
        || !aux_width.is_multiple_of(EXTENSION_DEGREE)
        || (aux_width == 0) != (pp == 0)
    {
        return Err(Error::Shape);
    }
    let private = |w: usize| w.checked_add(RANDOM_CODEWORDS).ok_or(Error::Shape);
    let point_count = |next: bool| 1 + usize::from(next);
    let mut groups = vec![
        vec![(private(EXTENSION_DEGREE)?, 1)],
        vec![(
            private(main)?,
            point_count(!air.main_next_row_columns().is_empty()),
        )],
        vec![(private(EXTENSION_DEGREE)?, 1); parameters.num_quotient_chunks],
    ];
    if pp != 0 {
        groups.push(vec![(
            pp,
            point_count(!air.preprocessed_next_row_columns().is_empty()),
        )]);
    }
    if aux_width != 0 {
        groups.push(vec![(private(aux_width)?, 2)]);
    }
    let mut total = 0usize;
    let mut commitments = Vec::with_capacity(groups.len());
    let mut counts = Vec::with_capacity(groups.len());
    for group in groups {
        let mut matrices = Vec::with_capacity(group.len());
        let mut matrix_counts = Vec::with_capacity(group.len());
        let mut salted_leaf_width = 0usize;
        for (width, points) in group {
            total = width
                .checked_mul(points)
                .and_then(|n| total.checked_add(n))
                .ok_or(Error::Shape)?;
            salted_leaf_width = width
                .checked_add(SALT_ELEMENTS)
                .and_then(|n| salted_leaf_width.checked_add(n))
                .ok_or(Error::Shape)?;
            matrices.push(MatrixGeometry {
                width,
                opening_points: points,
            });
            matrix_counts.push(vec![width; points]);
        }
        commitments.push(CommitmentGeometry {
            matrices,
            salted_leaf_width,
        });
        counts.push(matrix_counts);
    }
    if total != parameters.num_batched_functions {
        return Err(Error::Shape);
    }
    let pcs_shape = PcsShape {
        claimed_evaluation_counts: counts,
        batch_pow_bits: 0,
    };
    let fri_shape = bound.fri_shape().clone();
    if fri_shape.log_arities != vec![1; committed_log] {
        return Err(Error::Shape);
    }
    Ok(ArgumentManifest {
        stark,
        pcs: inspect_separator(&pcs_shape.domain_separator::<Val, Challenge>()),
        fri: inspect_separator(&fri_shape.domain_separator::<Val, Challenge>()),
        pcs_shape,
        fri_shape,
        commitments,
        lde_log: committed_log.checked_add(LOG_BLOWUP).ok_or(Error::Shape)?,
    })
}
