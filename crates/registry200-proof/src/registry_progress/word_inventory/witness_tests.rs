//! Honest trace and actual native diagnostic negatives, never proof/SQL credit.
use super::*;
use p3_field::PrimeCharacteristicRing;
use plan::*;
#[test]
fn public_owner_inputs_fill_complete_honest_main_for_both_roles() {
    use p3_matrix::Matrix;
    for predicate in [false, true] {
        let (m, input) = owner::public_case(predicate);
        let public = public_values::Expected::checked(&m).unwrap();
        let (air, trace) = witness::prepare(&m, &input).expect("complete private recipes and MAIN");
        assert_eq!(trace.0.height(), 512);
        check::all(&air, &trace, &public).expect("actual BASE plus every original lookup balances");
        let built = complete_build(&m).unwrap();
        assert!(core::mem::size_of::<recipes::Recipe>() <= 256);
        assert!(
            built.origins.primary.len() + built.origins.targets.len() <= built.pool.nodes.len()
        );
        if predicate {
            assert_eq!(
                input.banks[1][107..111],
                [Val::from_u8(4), Val::from_u8(4), Val::from_u8(4), Val::ZERO]
            );
        }
        eprintln!(
            "word_witness role={} rows={} actual_BASE_lookup_diagnostic=true proof=false SQL=false",
            if predicate { "predicate" } else { "control" },
            air.plan.rows.len()
        );
    }
}
#[test]
fn repaired_add_passes_actual_base_and_fails_actual_wire_lookup() {
    use evaluate::Error;
    let (m, input) = owner::public_case(true);
    let public = public_values::Expected::checked(&m).unwrap();
    let (air, mut trace) = witness::prepare(&m, &input).unwrap();
    check::all(&air, &trace, &public).unwrap();
    let (r, slot) = air
        .plan
        .rows
        .iter()
        .enumerate()
        .find_map(|(r, row)| {
            row.ops.iter().enumerate().find_map(|(s, op)| {
                (*op == expr::Op::Add
                    && row.ports[3 * s].constant.is_none()
                    && row.ports[3 * s + 2].constant.is_none())
                .then_some((r, s))
            })
        })
        .expect("actual nonconstant Add");
    trace.0.values[r * WIDTH + 248 + 3 * slot] += Val::ONE;
    trace.0.values[r * WIDTH + 248 + 3 * slot + 2] += Val::ONE;
    assert_eq!(
        check::base(&air, &trace, &public),
        Ok(()),
        "local equation repaired"
    );
    assert_eq!(check::lookups(&air, &trace, &public), Err(Error::Lookup));
}
#[test]
fn native_diagnostics_reject_permutation_range_and_repaired_mask_frequency() {
    use evaluate::Error;
    let (m, input) = owner::public_case(true);
    let public = public_values::Expected::checked(&m).unwrap();
    let (air, mut trace) = witness::prepare(&m, &input).unwrap();
    let hash = air.plan.rows.iter().position(|r| r.hash.is_some()).unwrap();
    trace.0.values[hash * WIDTH + 12] += Val::ONE;
    assert_eq!(check::base(&air, &trace, &public), Err(Error::Base));
    trace.0.values[hash * WIDTH + 12] -= Val::ONE;
    let (r, bit) = air
        .plan
        .rows
        .iter()
        .enumerate()
        .find_map(|(r, row)| {
            if row.range {
                row.bits.iter().position(|b| *b).map(|bit| (r, bit))
            } else {
                None
            }
        })
        .unwrap();
    let cell = r * WIDTH + 248 + PORTS + bit;
    let saved = trace.0.values[cell];
    trace.0.values[cell] = Val::ONE - saved;
    assert_eq!(check::base(&air, &trace, &public), Err(Error::Base));
    trace.0.values[cell] = saved;
    // age0 has one actual physical read, age2 has none. Swap the frequencies and
    // repair their exact 3-bit decompositions; only the actual lookup may reject.
    let row = air
        .plan
        .rows
        .iter()
        .position(|r| r.mask == Some(0))
        .unwrap();
    let a = row * WIDTH + 248 + 8;
    trace.0.values.swap(a, a + 2);
    let start = row * WIDTH + 248 + PORTS;
    for slot in [0usize, 2] {
        for bit in 0..3 {
            trace.0.values[start + 3 * slot + bit] = Val::from_bool(slot == 2 && bit == 0);
        }
    }
    assert_eq!(check::base(&air, &trace, &public), Ok(()));
    assert_eq!(check::lookups(&air, &trace, &public), Err(Error::Lookup));
}
#[test]
fn missing_origins_cycles_private_overflow_and_foreign_claim_fail_closed() {
    use evaluate::{Error, Evaluator};
    let (mut m, mut input) = owner::public_case(true);
    let public = public_values::Expected::checked(&m).unwrap();
    let mut built = complete_build(&m).unwrap();
    let target = *built.origins.targets.keys().next().unwrap();
    built.origins.targets.remove(&target);
    assert!(matches!(
        Evaluator::new(&built.pool, &built.origins, &input, &public),
        Err(Error::Origin)
    ));
    let mut built = complete_build(&m).unwrap();
    let (index, target) = built
        .origins
        .recipes
        .iter()
        .enumerate()
        .find_map(|(i, r)| {
            if let recipes::Recipe::Nonzero { out, .. } = r {
                Some((i, *out))
            } else {
                None
            }
        })
        .unwrap();
    built.origins.recipes[index] = recipes::Recipe::Nonzero {
        out: target,
        sum: target,
        gate: target,
    };
    assert!(matches!(
        Evaluator::new(&built.pool, &built.origins, &input, &public)
            .unwrap()
            .finish(),
        Err(Error::Cycle)
    ));
    input.banks[0][80] = Val::from_u64(1u64 << 32);
    assert!(matches!(
        witness::prepare(&m, &input),
        Err(Error::Arithmetic)
    ));
    let (_, input) = owner::public_case(true);
    m.result[0] += Val::ONE;
    assert!(matches!(witness::prepare(&m, &input), Err(Error::Binding)));
}
