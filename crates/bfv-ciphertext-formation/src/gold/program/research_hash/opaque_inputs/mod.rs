//! Private program-owned research hash child. Opaque PRIVATE INPUT commitments only.
//! Real native MMCS verifies every returned proof; this creates no verdict.
//! Public PP remains ordinary native ProverData and has no role in this enum.
use super::config::Mmcs as ResearchMmcs;
use super::ro::{Oracle, Programmer, leaf_input};
use bfv_hiding_stark::Val as F;
use p3_fri::BatchMultiOpening;
use p3_matrix::Dimensions;
use p3_merkle_tree::PrunedMerklePaths;
use p3_symmetric::MerkleCap;
use rand_public_pp::{CryptoRng, RngExt};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

type Digest = [u8; 32];
type Rows = Vec<Vec<F>>;
type Result<T> = core::result::Result<T, Error>;
const HEIGHT: usize = 32768;
const MAX_OPENED: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gold::program) enum Error {
    Shape,
    ConflictingRow,
    DisclosureLimit,
    ProgrammingConflict,
    FailedAttempt,
}

/// Closed owning layouts only. Incoming frames cannot supply dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gold::program) enum DenseFamily {
    Query,
    Data,
}
impl DenseFamily {
    fn widths(self, role: PrivateInput) -> Vec<usize> {
        match (self, role) {
            (_, PrivateInput::Random) => vec![10],
            (Self::Query, PrivateInput::Main) => vec![421],
            (Self::Data, PrivateInput::Main) => vec![517],
            (_, PrivateInput::Quotient) => vec![10; 8],
            (Self::Query, PrivateInput::Aux) => vec![425],
            (Self::Data, PrivateInput::Aux) => vec![415],
        }
    }
    fn max_width(self) -> usize {
        match self {
            Self::Query => 425,
            Self::Data => 517,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gold::program) enum PrivateInput {
    Random,
    Main,
    Quotient,
    Aux,
}
impl PrivateInput {
    fn index(self) -> usize {
        match self {
            Self::Random => 0,
            Self::Main => 1,
            Self::Quotient => 2,
            Self::Aux => 3,
        }
    }
}

/// Four private commitments in one closed family. No PP or geometry override.
pub(in crate::gold::program) struct OpaqueInputs {
    trees: [Tree; 4],
    failed: bool,
}
impl OpaqueInputs {
    pub(in crate::gold::program) fn new(
        family: DenseFamily,
        programmer: Programmer,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let roles = [
            PrivateInput::Random,
            PrivateInput::Main,
            PrivateInput::Quotient,
            PrivateInput::Aux,
        ];
        let mut trees = Vec::with_capacity(4);
        for role in roles {
            trees.push(Tree::sample(
                family,
                HEIGHT,
                family.widths(role),
                programmer.clone(),
                rng,
            )?);
        }
        let trees = trees.try_into().map_err(|_| Error::Shape)?;
        Ok(Self {
            trees,
            failed: false,
        })
    }
    pub(in crate::gold::program) fn commitment(&self, role: PrivateInput) -> MerkleCap<F, Digest> {
        self.trees[role.index()].commitment()
    }
    pub(in crate::gold::program) fn dimensions(&self, role: PrivateInput) -> Vec<Dimensions> {
        self.trees[role.index()].dimensions()
    }
    /// Public rows come from V, in actual query/matrix/column order.
    /// Repeated indices must reuse precisely the same rows and four salts.
    pub(in crate::gold::program) fn opening(
        &mut self,
        role: PrivateInput,
        indices: &[usize],
        rows: &[Rows],
        rng: &mut impl CryptoRng,
    ) -> Result<BatchMultiOpening<F, ResearchMmcs>> {
        if self.failed {
            return Err(Error::FailedAttempt);
        }
        if indices.len() != MAX_OPENED {
            return Err(Error::Shape);
        }
        let result = self.trees[role.index()].opening(indices, rows, rng);
        if matches!(&result, Err(Error::ProgrammingConflict)) {
            self.failed = true;
        }
        result
    }
}

struct Opened {
    rows: Rows,
    salts: Rows,
}
struct Tree {
    height: usize,
    widths: Vec<usize>,
    // level0=opaque combined leaves, last level=one root. The layout contains
    // actual digests only, not unobserved data polynomials or fixture values.
    levels: Vec<Vec<Digest>>,
    programmer: Programmer,
    opened: BTreeMap<usize, Opened>,
}
impl Tree {
    fn sample(
        family: DenseFamily,
        height: usize,
        widths: Vec<usize>,
        programmer: Programmer,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        if height == 0
            || height > HEIGHT
            || !height.is_power_of_two()
            || widths.is_empty()
            || widths.len() > 8
            || widths
                .iter()
                .any(|&width| width == 0 || width > family.max_width())
        {
            return Err(Error::Shape);
        }
        let mut labels = vec![[0; 32]; height];
        for label in &mut labels {
            rng.fill_bytes(label);
        }
        Self::from_labels(family, height, widths, programmer, labels)
    }
    fn from_labels(
        family: DenseFamily,
        height: usize,
        widths: Vec<usize>,
        programmer: Programmer,
        labels: Vec<Digest>,
    ) -> Result<Self> {
        if height == 0
            || height > HEIGHT
            || !height.is_power_of_two()
            || labels.len() != height
            || widths.is_empty()
            || widths.len() > 8
            || widths
                .iter()
                .any(|&width| width == 0 || width > family.max_width())
        {
            return Err(Error::Shape);
        }
        let oracle = programmer.oracle();
        let mut levels = vec![labels];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|children| {
                    // NORMAL shared-oracle NODE query, never a programmed digest.
                    normal_node(&oracle, children[0], children[1])
                })
                .collect();
            levels.push(next);
        }
        Ok(Self {
            height,
            widths,
            levels,
            programmer,
            opened: BTreeMap::new(),
        })
    }
    fn commitment(&self) -> MerkleCap<F, Digest> {
        MerkleCap::new(vec![self.levels.last().unwrap()[0]])
    }
    fn dimensions(&self) -> Vec<Dimensions> {
        self.widths
            .iter()
            .map(|&width| Dimensions {
                width,
                height: self.height,
            })
            .collect()
    }

    fn opening(
        &mut self,
        indices: &[usize],
        rows: &[Rows],
        rng: &mut impl CryptoRng,
    ) -> Result<BatchMultiOpening<F, ResearchMmcs>> {
        if indices.is_empty()
            || indices.len() > MAX_OPENED
            || rows.len() != indices.len()
            || indices.iter().any(|&index| index >= self.height)
            || rows.iter().any(|query| {
                query.len() != self.widths.len()
                    || query
                        .iter()
                        .zip(&self.widths)
                        .any(|(row, &width)| row.len() != width)
            })
        {
            return Err(Error::Shape);
        }
        // Preflight ALL contradictions and total disclosure limits before any
        // salt sampling/programming. Extents are pinned above, not wire-chosen.
        let mut unique = BTreeMap::new();
        for (&index, row) in indices.iter().zip(rows) {
            if self.opened.get(&index).is_some_and(|old| &old.rows != row)
                || unique.get(&index).is_some_and(|old: &&Rows| *old != row)
            {
                return Err(Error::ConflictingRow);
            }
            unique.entry(index).or_insert(row);
        }
        let fresh = unique
            .keys()
            .filter(|&&index| !self.opened.contains_key(&index))
            .count();
        if self.opened.len() + fresh > MAX_OPENED {
            return Err(Error::DisclosureLimit);
        }
        for (index, row) in unique {
            if self.opened.contains_key(&index) {
                continue;
            }
            let salts: Rows = self
                .widths
                .iter()
                .map(|_| (0..4).map(|_| rng.random::<F>()).collect())
                .collect();
            let raw = leaf_input(
                row.iter()
                    .zip(&salts)
                    .flat_map(|(data, salt)| data.iter().chain(salt).copied()),
            );
            // The ONLY programming operation: one exact canonical salted LEAF.
            self.programmer
                .plant256(raw, self.levels[0][index])
                .map_err(|_| Error::ProgrammingConflict)?;
            self.opened.insert(
                index,
                Opened {
                    rows: row.clone(),
                    salts,
                },
            );
        }
        let opened_values = indices
            .iter()
            .map(|index| self.opened[index].rows.clone())
            .collect();
        let salts = indices
            .iter()
            .map(|index| self.opened[index].salts.clone())
            .collect();
        Ok(BatchMultiOpening {
            opened_values,
            opening_proof: (
                salts,
                PrunedMerklePaths {
                    sibling_hashes: self.frontier(indices),
                },
            ),
        })
    }

    fn frontier(&self, indices: &[usize]) -> Vec<Digest> {
        let mut frontier = indices.to_vec();
        frontier.sort_unstable();
        frontier.dedup();
        let mut boundary = Vec::new();
        // Native canonical order: level first, ascending parent, then ascending
        // missing child. Membership is a sorted unique frontier, not query order.
        for level in 0..self.levels.len() - 1 {
            let mut parents = Vec::new();
            let mut at = 0;
            while at < frontier.len() {
                let parent = frontier[at] / 2;
                for child in [2 * parent, 2 * parent + 1] {
                    if at < frontier.len() && frontier[at] == child {
                        at += 1;
                    } else {
                        boundary.push(self.levels[level][child]);
                    }
                }
                parents.push(parent);
            }
            frontier = parents;
        }
        boundary
    }
}

fn normal_node(oracle: &Oracle, left: Digest, right: Digest) -> Digest {
    let mut raw = bfv_hiding_stark::hash::NODE_DOMAIN.to_vec();
    raw.extend(left);
    raw.extend(right);
    oracle.h256(raw)
}
