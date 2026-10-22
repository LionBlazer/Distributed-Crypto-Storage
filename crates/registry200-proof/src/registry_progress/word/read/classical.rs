//! Conditional classical composition diagnostics over the five actual closed AIRs.
//!
//! No evidence is accepted here. In particular, applying the displayed BCS
//! expression to the actual shared Poseidon transcript remains a premise, not a
//! conclusion of this calculator. See `CLASSICAL.md` beside this module.
use super::Expected;
use crate::fixed::Backend;
use bfv_hiding_stark::classical::AlgebraicBound;
use bfv_unrelinearized_product as product;
use p3_security::ErrorBits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Budget,
    Metadata,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "conditional classical diagnostic unavailable: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

/// A fixed relation label associated with actual code, never a submitted report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    SourceVersion,
    VersionEncoding,
    DataFormation,
    PredicateWord,
    QueryFormation,
}

#[derive(Debug, Clone)]
pub struct Component {
    relation: Relation,
    bound: AlgebraicBound,
}
impl Component {
    pub fn relation(&self) -> Relation {
        self.relation
    }
    pub fn bound(&self) -> &AlgebraicBound {
        &self.bound
    }
}

/// Conditional error accounting, not a cryptographic security assessment.
/// No constructor accepts caller-generated component reports or an accepted flag.
#[derive(Debug, Clone)]
pub struct Report {
    components: [Component; 5],
    log2_query_budget: u32,
    bcs_algebraic_bits: f64,
    bcs_collision_bits: f64,
    pit_single_bits: usize,
    pit_budget_bits: f64,
    conditional_error_bits: f64,
}
impl Report {
    pub fn components(&self) -> &[Component; 5] {
        &self.components
    }
    /// Each component's complete classical oracle-query budget is at most 2^b.
    /// The PIT budget Q_H + V is separately bounded by that same numerical limit.
    pub fn log2_query_budget(&self) -> u32 {
        self.log2_query_budget
    }
    pub fn bcs_algebraic_bits(&self) -> f64 {
        self.bcs_algebraic_bits
    }
    pub fn bcs_collision_bits(&self) -> f64 {
        self.bcs_collision_bits
    }
    pub fn pit_single_bits(&self) -> usize {
        self.pit_single_bits
    }
    pub fn pit_budget_bits(&self) -> f64 {
        self.pit_budget_bits
    }
    /// Minus-log2 of a conservative probability ceiling for the included terms,
    /// CONDITIONAL on the unfinished joint-oracle/RBR/transcript correspondence.
    /// External binding/instantiation/privacy/freshness failures are not included.
    /// This is neither workbits nor a measured operation/admission result.
    pub fn conditional_error_bits(&self) -> f64 {
        self.conditional_error_bits
    }
}

/// Derive all five AIR inventories without proofs, private witnesses, PP or RNG.
///
/// `log2_query_budget` is an explicit analytical hypothesis in 0..=120. It must
/// include offline grinding, failed/retried attempts and shared-primitive queries
/// required by a reduction. A timeout does not enforce it. Each of the five BCS
/// terms uses that entire budget, so shared-oracle work is never divided by five.
///
/// The formula assumes an applicable classical BCS reduction with effective
/// range at least 2^255, correctly associated RBR bounds, and the product's ideal
/// SHA512 transcript model. It does not prove any of those premises for the
/// concrete primitives. In particular, Goldilocks^4 having that many values is
/// not a proof of the required random-oracle model. Native configuration, wire
/// profiles, hiding guarantees and unconditional SQL rejection are unchanged.
pub fn analyze(expected: &Expected, log2_query_budget: u32) -> Result<Report> {
    if log2_query_budget > 120 {
        return Err(Error::Budget);
    }
    let source =
        Backend::source_version_classical(expected.word.source()).map_err(|_| Error::Metadata)?;
    let encoding =
        Backend::two_lane_classical(expected.data.source()).map_err(|_| Error::Metadata)?;
    let data =
        bfv_ciphertext_formation::gold::data::dense_classical_bound(expected.data.core_expected())
            .map_err(|_| Error::Metadata)?;
    let word = super::super::probe::classical_bound(expected.word.role().predicate())
        .map_err(|_| Error::Metadata)?;
    let query = bfv_ciphertext_formation::gold::query::classical_bound(&expected.query)
        .map_err(|_| Error::Metadata)?;
    compose(
        [
            Component {
                relation: Relation::SourceVersion,
                bound: source,
            },
            Component {
                relation: Relation::VersionEncoding,
                bound: encoding,
            },
            Component {
                relation: Relation::DataFormation,
                bound: data,
            },
            Component {
                relation: Relation::PredicateWord,
                bound: word,
            },
            Component {
                relation: Relation::QueryFormation,
                bound: query,
            },
        ],
        log2_query_budget,
    )
}

// Private arithmetic helper: no caller-supplied report can reach the public API.
fn compose(components: [Component; 5], budget: u32) -> Result<Report> {
    if budget > 120 {
        return Err(Error::Budget);
    }
    let b = f64::from(budget);
    let algebraic: Vec<_> = components
        .iter()
        .map(|c| ErrorBits::from_log2(c.bound.union_bits() - b))
        .collect();
    // One complete BCS expression per AIR, no independence assumption. Use a
    // conservative 255-bit range hypothesis, not the SDK's 128 workbit cap.
    let collision = ErrorBits::from_log2(
        255.0 - 3.0f64.log2() - 2.0 * b - 2.0f64.powf(-2.0 * b).ln_1p() / std::f64::consts::LN_2,
    );
    let collisions = [collision; 5];
    let pit_single_bits = product_single_bits()?;
    let pit = ErrorBits::from_log2(pit_single_bits as f64 - b);
    let all: Vec<_> = algebraic
        .iter()
        .copied()
        .chain(collisions)
        .chain([pit])
        .collect();
    Ok(Report {
        bcs_algebraic_bits: conservative(ErrorBits::sum(&algebraic).bits())?,
        bcs_collision_bits: conservative(ErrorBits::sum(&collisions).bits())?,
        pit_single_bits,
        pit_budget_bits: pit.bits(),
        conditional_error_bits: conservative(ErrorBits::sum(&all).bits())?,
        components,
        log2_query_budget: budget,
    })
}

fn conservative(bits: f64) -> Result<f64> {
    if !bits.is_finite() || bits <= 1.0 {
        return Err(Error::Metadata);
    }
    Ok(bits.floor() - 1.0)
}

// Integer proof of the coarser <2^-306 single-transcript bound in product/MODEL.
// Let t=2^b. If d(t+1)<=p and dt(t+1)<2^128<2^512, then
// d/p+d/2^512 < 1/(t+1)+1/[t(t+1)] = 1/t.
// This derives d, fields and number of points from the actual product geometry.
fn product_single_bits() -> Result<usize> {
    let degree = product::N
        .checked_mul(2)
        .and_then(|v| v.checked_sub(2))
        .ok_or(Error::Metadata)? as u128;
    let prime = u128::from(*product::QP.iter().min().ok_or(Error::Metadata)?);
    let quotient = prime.checked_div(degree).ok_or(Error::Metadata)?;
    let bits = quotient.checked_ilog2().ok_or(Error::Metadata)?;
    let t = 1u128.checked_shl(bits).ok_or(Error::Metadata)?;
    let next = t.checked_add(1).ok_or(Error::Metadata)?;
    if degree.checked_mul(next).ok_or(Error::Metadata)? > prime
        || degree
            .checked_mul(t)
            .and_then(|v| v.checked_mul(next))
            .is_none()
    {
        return Err(Error::Metadata);
    }
    product::POINTS
        .checked_mul(bits as usize)
        .ok_or(Error::Metadata)
}

#[cfg(test)]
mod tests;
