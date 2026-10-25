//! Owning Query PUBLIC frame factory shared by its two-session and mixed gates.
//! No original witness/config/fixture getter; every attempt drops all producers.
use super::super::public_image::{QueryCoins, QueryFoldProgram, public_disclosures};
use super::native_fri::{Inputs, TapePlan};
use super::public_deep::{Column, PublicView};
use super::research_ro::{Event, Programmer, Walk, Walks};
use super::{Expected, Receiver, ResearchFrame, encode, public_deep};
use rand_public_pp::{SeedableRng, rngs::StdRng};

/// Canonical owning PUBLIC Query metadata; no original private trace.
pub(in crate::gold::program) fn public_expected() -> Expected {
    super::super::tests::metadata()
}

fn convert(columns: &[public_disclosures::Column]) -> Vec<Column> {
    columns
        .iter()
        .map(|column| Column {
            rows: column.rows.clone(),
            at_z: column.at_z,
            at_hz: column.at_hz,
        })
        .collect()
}

/// Consumes one attempt and drops all PP/input trees, V/B values and proof data
/// before the next attempt. Only an immutable bounded frame and walk escape.
pub(in crate::gold::program) fn public_frame(
    expected: &Expected,
    programmer: Programmer,
    receiver: &Receiver,
    plan: TapePlan,
    seed_base: u8,
) -> (ResearchFrame, Walk) {
    let inputs = Inputs::new(
        expected,
        programmer,
        StdRng::from_seed([seed_base; 32]),
        StdRng::from_seed([seed_base + 1; 32]),
    )
    .unwrap();
    let pp_coefficients = inputs.public_pp_coefficients();
    let program = QueryFoldProgram::from_expected(expected).unwrap();
    assert_eq!(pp_coefficients.as_slice(), program.public_pp_coefficients());
    let coins = QueryCoins {
        lookup_alpha: plan.lookup_alpha(),
        lookup_beta: plan.lookup_beta(),
        constraint_alpha: plan.constraint_alpha(),
    };
    let disclosures = public_disclosures::sample(
        &program,
        &coins,
        plan.z(),
        plan.positions(),
        &mut StdRng::from_seed([seed_base + 2; 32]),
    )
    .unwrap();
    assert_eq!(disclosures.expected_binding, expected.binding());
    assert_eq!(disclosures.z, plan.z());
    assert_eq!(disclosures.s, plan.positions());
    let r = convert(&disclosures.r);
    let main = convert(&disclosures.main);
    let quotient = disclosures
        .quotient
        .iter()
        .map(|matrix| convert(matrix))
        .collect::<Vec<_>>();
    let pp = convert(&disclosures.pp);
    let aux = convert(&disclosures.aux);
    let view = PublicView {
        s: &disclosures.s,
        z: disclosures.z,
        theta: plan.theta(),
        r: &r,
        main: &main,
        quotient: &quotient,
        pp: &pp,
        pp_coefficients: &pp_coefficients,
        aux: &aux,
    };
    let b_sampler = public_deep::prepare(&view).unwrap();
    let b = b_sampler.sample(&mut StdRng::from_seed([seed_base + 3; 32]));
    assert_eq!(b.len(), 4095);
    drop(b_sampler);
    let produce_walks = Walks::default();
    let proof = inputs
        .prove(plan, &view, &b, produce_walks.clone())
        .unwrap();
    let frame = encode(expected, &proof, &receiver.assessment);
    drop(proof);
    let mut produced = produce_walks.with_draws();
    assert_eq!(produced.len(), 1);
    let walk = produced.pop().unwrap();
    assert_complete_walk(&walk);
    (frame, walk)
}

pub(super) fn assert_complete_walk(walk: &Walk) {
    assert!(
        walk.prefix
            .starts_with(bfv_hiding_stark::hash::TRANSCRIPT_DOMAIN)
    );
    assert_eq!(
        walk.events
            .iter()
            .filter(|event| matches!(event, Event::Sample { .. }))
            .count(),
        277
    );
    assert_eq!(
        walk.events
            .iter()
            .filter(|event| matches!(event, Event::Cap(_)))
            .count(),
        17
    );
    assert!(
        walk.events
            .iter()
            .any(|event| matches!(event, Event::Field(_)))
    );
    assert!(walk.draws.len() >= 277);
    assert!(
        walk.draws
            .iter()
            .all(|draw| draw.prefix_len <= walk.prefix.len())
    );
}
