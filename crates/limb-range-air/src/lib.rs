//! Fixed Goldilocks range supports and prover histograms, never proof authority.
#![forbid(unsafe_code)]
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// Trusted composition namespace. Equality deliberately shares range support;
/// different jobs must choose distinct namespaces unless sharing is intentional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Namespace([u8; 32]);
impl Namespace {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Supported integer widths only; no caller-defined support table is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Range {
    R2,
    R9,
    R13,
    R14,
    R15,
    R16,
}
impl Range {
    pub const fn bits(self) -> usize {
        match self {
            Self::R2 => 2,
            Self::R9 => 9,
            Self::R13 => 13,
            Self::R14 => 14,
            Self::R15 => 15,
            Self::R16 => 16,
        }
    }
    pub const fn domain_size(self) -> usize {
        1 << self.bits()
    }
    /// R2 repeats 0..3 four times; only its first copy receives multiplicities.
    pub const fn height(self) -> usize {
        if self.bits() < 4 {
            16
        } else {
            self.domain_size()
        }
    }
}
/// Prefix-free fixed bus ABI: domain, 64 lowercase hexadecimal namespace bytes,
/// slash, then the fixed bit width. Consumers bind the namespace in their transcript.
pub fn bus(namespace: Namespace, range: Range) -> String {
    use core::fmt::Write;
    let mut name = String::from("dcs/limb-range-air/v1/");
    for byte in namespace.0 {
        write!(&mut name, "{byte:02x}").expect("writing to String");
    }
    write!(&mut name, "/{}", range.bits()).expect("writing to String");
    name
}
/// One unit lookup query. Public fixed support is supplied by exactly one RangeAir.
pub fn query<AB: InteractionBuilder<F = Val>>(
    builder: &mut AB,
    namespace: Namespace,
    range: Range,
    value: AB::Expr,
) {
    builder.push_interaction(&bus(namespace, range), [value], 1);
}
#[derive(Clone)]
pub struct RangeAir {
    namespace: Namespace,
    range: Range,
    public: Option<RowMajorMatrix<Val>>,
}
impl RangeAir {
    pub fn shape(namespace: Namespace, range: Range) -> Self {
        Self {
            namespace,
            range,
            public: None,
        }
    }
    /// Only the exact complete support can become preprocessing.
    pub fn prepare(namespace: Namespace, range: Range) -> Self {
        Self {
            namespace,
            range,
            public: Some(RowMajorMatrix::new(
                (0..range.height())
                    .map(|i| Val::from_usize(i % range.domain_size()))
                    .collect(),
                1,
            )),
        }
    }
    pub fn namespace(&self) -> Namespace {
        self.namespace
    }
    pub fn range(&self) -> Range {
        self.range
    }
    pub fn height(&self) -> usize {
        self.range.height()
    }
    pub fn is_prepared(&self) -> bool {
        self.public.is_some()
    }
}
impl BaseAir<Val> for RangeAir {
    fn width(&self) -> usize {
        2
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.public.clone()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn num_constraints(&self) -> Option<usize> {
        Some(1)
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for RangeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let value: AB::Expr = main.current(0).unwrap().into();
        let multiplicity: AB::Expr = main.current(1).unwrap().into();
        let fixed: AB::Expr = builder.preprocessed().current(0).unwrap().into();
        builder.assert_zero(value.clone() - fixed);
        builder.push_interaction(
            &bus(self.namespace, self.range),
            [value],
            Count::provided(-multiplicity),
        );
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    DuplicateRange,
    MissingRange,
    OutOfRange,
    MultiplicityOverflow,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "limb range rejected {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;
/// Prover-only checked frequency accounting. This is not a checked proof/result.
#[derive(Clone)]
pub struct Histogram {
    entries: Vec<(Range, Vec<u64>)>,
}
impl Histogram {
    pub fn new(ranges: &[Range]) -> Result<Self> {
        let mut entries = Vec::with_capacity(ranges.len());
        for &range in ranges {
            if entries.iter().any(|(r, _)| *r == range) {
                return Err(Error::DuplicateRange);
            };
            entries.push((range, vec![0; range.domain_size()]));
        }
        Ok(Self { entries })
    }
    pub fn ranges(&self) -> impl Iterator<Item = Range> + '_ {
        self.entries.iter().map(|(r, _)| *r)
    }
    pub fn add(&mut self, range: Range, value: u64) -> Result<()> {
        let counts = &mut self
            .entries
            .iter_mut()
            .find(|(r, _)| *r == range)
            .ok_or(Error::MissingRange)?
            .1;
        let index = usize::try_from(value).map_err(|_| Error::OutOfRange)?;
        let count = counts.get_mut(index).ok_or(Error::OutOfRange)?;
        *count = count
            .checked_add(1)
            .filter(|&n| n < Val::ORDER_U64)
            .ok_or(Error::MultiplicityOverflow)?;
        Ok(())
    }
    /// Merge subsets into this support atomically. A missing range or any overflow
    /// leaves every original count unchanged; no field reduction is permitted.
    pub fn merge(&mut self, other: &Self) -> Result<()> {
        for (range, add) in &other.entries {
            let counts = &self
                .entries
                .iter()
                .find(|(r, _)| r == range)
                .ok_or(Error::MissingRange)?
                .1;
            for (&x, &y) in counts.iter().zip(add) {
                x.checked_add(y)
                    .filter(|&n| n < Val::ORDER_U64)
                    .ok_or(Error::MultiplicityOverflow)?;
            }
        }
        for (range, add) in &other.entries {
            let counts = &mut self
                .entries
                .iter_mut()
                .find(|(r, _)| r == range)
                .ok_or(Error::MissingRange)?
                .1;
            for (x, &y) in counts.iter_mut().zip(add) {
                *x += y;
            }
        }
        Ok(())
    }
    pub fn count(&self, range: Range, value: usize) -> Option<u64> {
        self.entries
            .iter()
            .find(|(r, _)| *r == range)?
            .1
            .get(value)
            .copied()
    }
    /// MAIN is (value, multiplicity); the fixed support belongs to RangeAir.
    pub fn trace(&self, range: Range) -> Result<RowMajorMatrix<Val>> {
        let counts = &self
            .entries
            .iter()
            .find(|(r, _)| *r == range)
            .ok_or(Error::MissingRange)?
            .1;
        let mut values = Vec::with_capacity(range.height() * 2);
        for index in 0..range.height() {
            let value = index % range.domain_size();
            let count = if index < range.domain_size() {
                counts[value]
            } else {
                0
            };
            values.extend([Val::from_usize(value), Val::from_u64(count)]);
        }
        Ok(RowMajorMatrix::new(values, 2))
    }
}
#[cfg(test)]
mod tests;
