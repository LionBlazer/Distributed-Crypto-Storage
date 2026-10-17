//! Fixed eight-word consumer-profile suffix around an unchanged arithmetic AIR.
use crate::Val;
use p3_air::{Air, AirBuilder, BaseAir, BoundaryPublic};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Cow;

pub const PROFILE_WORDS: usize = 8;

/// Declares a fixed eight-word public suffix while preserving the inner AIR.
/// Consumers supply their own profile and require prepared data before setup.
/// This wrapper adds no arithmetic assertions or verification authority.
pub struct ProfileAir<A> {
    inner: A,
}
impl<A> ProfileAir<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
    pub const fn inner(&self) -> &A {
        &self.inner
    }
}

/// The existing profile32 encoding: eight little-endian u32 field words.
/// The caller appends these after its unchanged arithmetic public values.
pub fn profile_words(profile: [u8; 32]) -> [Val; PROFILE_WORDS] {
    let words = profile.as_chunks::<4>().0;
    core::array::from_fn(|i| Val::from_u32(u32::from_le_bytes(words[i])))
}

impl<A: BaseAir<Val>> BaseAir<Val> for ProfileAir<A> {
    fn width(&self) -> usize {
        self.inner.width()
    }
    fn preprocessed_width(&self) -> usize {
        self.inner.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.inner.preprocessed_trace()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.inner.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.inner.preprocessed_next_row_columns()
    }
    fn num_public_values(&self) -> usize {
        self.inner.num_public_values() + PROFILE_WORDS
    }
    fn num_constraints(&self) -> Option<usize> {
        self.inner.num_constraints()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }
    fn num_periodic_columns(&self) -> usize {
        self.inner.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        self.inner.periodic_columns()
    }
    fn periodic_values(&self, row_index: usize) -> Vec<Val> {
        self.inner.periodic_values(row_index)
    }
    fn periodic_columns_matrix(&self) -> Option<RowMajorMatrix<Val>> {
        self.inner.periodic_columns_matrix()
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        self.inner.public_boundary_io()
    }
    fn assumes_boolean_trace(&self) -> bool {
        self.inner.assumes_boolean_trace()
    }
}
impl<AB, A> Air<AB> for ProfileAir<A>
where
    AB: AirBuilder<F = Val>,
    A: Air<AB>,
{
    fn eval(&self, builder: &mut AB) {
        self.inner.eval(builder);
    }
}
