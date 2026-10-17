use super::*;
use p3_air::{AirBuilder, BaseAir, WindowAccess};

struct RequiresBooleanTrace;
impl BaseAir<Val> for RequiresBooleanTrace {
    fn width(&self) -> usize {
        1
    }
    fn assumes_boolean_trace(&self) -> bool {
        true
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for RequiresBooleanTrace {
    fn eval(&self, builder: &mut AB) {
        let value = builder.main().current(0).unwrap();
        builder.assert_bool(value);
    }
}

#[test]
fn air_requiring_a_boolean_trace_assumption_cannot_obtain_the_checked_configuration() {
    assert!(checked_config(&RequiresBooleanTrace).is_none());
}

struct MetadataAir {
    periodic_value_calls: std::sync::atomic::AtomicUsize,
    periodic_matrix_calls: std::sync::atomic::AtomicUsize,
}
impl BaseAir<Val> for MetadataAir {
    fn width(&self) -> usize {
        2
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<Val>> {
        Some(p3_matrix::dense::RowMajorMatrix::new(
            vec![Val::from_u8(10), Val::from_u8(11)],
            1,
        ))
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![0]
    }
    fn num_public_values(&self) -> usize {
        32
    }
    fn num_constraints(&self) -> Option<usize> {
        Some(1)
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> std::borrow::Cow<'_, [Vec<Val>]> {
        std::borrow::Cow::Owned(vec![vec![Val::from_u8(3), Val::from_u8(4)]])
    }
    fn periodic_values(&self, row_index: usize) -> Vec<Val> {
        self.periodic_value_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![Val::from_u8(if row_index.is_multiple_of(2) {
            3
        } else {
            4
        })]
    }
    fn periodic_columns_matrix(&self) -> Option<p3_matrix::dense::RowMajorMatrix<Val>> {
        self.periodic_matrix_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(p3_matrix::dense::RowMajorMatrix::new(
            vec![Val::from_u8(3), Val::from_u8(4)],
            1,
        ))
    }
    fn public_boundary_io(&self) -> &[p3_air::BoundaryPublic] {
        const CELLS: [p3_air::BoundaryPublic; 1] = [p3_air::BoundaryPublic::new(
            1,
            p3_air::BoundaryEnd::First,
            31,
        )];
        &CELLS
    }
    fn assumes_boolean_trace(&self) -> bool {
        true
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for MetadataAir {
    fn eval(&self, builder: &mut AB) {
        let value = builder.main().current(0).unwrap();
        builder.assert_zero(value);
    }
}

#[test]
fn profile_suffix_preserves_inner_metadata_periodic_overrides_and_original_public_prefix() {
    let wrapped = ProfileAir::new(MetadataAir {
        periodic_value_calls: std::sync::atomic::AtomicUsize::new(0),
        periodic_matrix_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    assert_eq!(wrapped.width(), 2);
    assert_eq!(wrapped.preprocessed_width(), 1);
    assert_eq!(
        wrapped.preprocessed_trace().unwrap().values,
        [Val::from_u8(10), Val::from_u8(11)]
    );
    assert_eq!(wrapped.main_next_row_columns(), [1]);
    assert_eq!(wrapped.preprocessed_next_row_columns(), [0]);
    assert_eq!(wrapped.inner().num_public_values(), 32);
    assert_eq!(wrapped.num_public_values(), 40);
    assert_eq!(wrapped.num_constraints(), Some(1));
    assert_eq!(wrapped.max_constraint_degree(), Some(1));
    assert_eq!(wrapped.num_periodic_columns(), 1);
    assert_eq!(
        wrapped.periodic_columns().as_ref(),
        [vec![Val::from_u8(3), Val::from_u8(4)]]
    );
    assert_eq!(wrapped.periodic_values(3), [Val::from_u8(4)]);
    assert_eq!(
        wrapped.periodic_columns_matrix().unwrap().values,
        [Val::from_u8(3), Val::from_u8(4)]
    );
    assert_eq!(
        wrapped
            .inner()
            .periodic_value_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        wrapped
            .inner()
            .periodic_matrix_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        wrapped.public_boundary_io(),
        [p3_air::BoundaryPublic::new(
            1,
            p3_air::BoundaryEnd::First,
            31
        )]
    );
    assert!(wrapped.assumes_boolean_trace());
    assert!(checked_config(&wrapped).is_none());

    let profile = core::array::from_fn(|i| i as u8);
    let mut public = vec![Val::from_u8(71); 32];
    public.extend(profile_words(profile));
    assert_eq!(&public[..32], &[Val::from_u8(71); 32]);
    assert_eq!(
        &public[32..],
        &[
            Val::from_u32(0x03020100),
            Val::from_u32(0x07060504),
            Val::from_u32(0x0b0a0908),
            Val::from_u32(0x0f0e0d0c),
            Val::from_u32(0x13121110),
            Val::from_u32(0x17161514),
            Val::from_u32(0x1b1a1918),
            Val::from_u32(0x1f1e1d1c),
        ]
    );
}
