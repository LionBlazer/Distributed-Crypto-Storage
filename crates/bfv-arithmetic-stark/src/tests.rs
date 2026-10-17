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
