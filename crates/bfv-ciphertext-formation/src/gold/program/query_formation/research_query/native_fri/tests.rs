//! Genuine native PCS/FRI component checks over explicit PUBLIC algebra inputs.
use super::super::research_ro::Tape;
use super::super::{Receiver, ResearchFrame, decode, encode};
use super::*;
use p3_batch_stark::BatchVerifierTranscript;
use p3_commit::{CommitmentOpening, MatrixOpening, PointOpening, UnivariateStarkPcs};
use p3_field::{TwoAdicField, coset::TwoAdicMultiplicativeCoset};
use p3_uni_stark::StarkGenericConfig;
use rand_public_pp::SeedableRng;

fn literal_tape() -> Tape {
    let mut tape = Tape::new();
    for counter in 0..277u64 {
        let candidate = match counter {
            15 => 2,
            16 => 1,
            17..=19 => 0, // z=u+2, generic nonbase public coin.
            20..=24 => 3 * (counter - 19) + 1,
            85..=276 => {
                let query = counter - 85;
                if query == 191 {
                    17
                } else {
                    (257 * query + 17) & 32767
                }
            }
            _ => 7 * counter + 11,
        };
        let mut digest = [counter as u8; 64];
        digest[..8].copy_from_slice(&candidate.to_le_bytes());
        tape.insert((counter, 0), digest);
    }
    let first = tape.remove(&(0, 0)).unwrap();
    tape.insert((0, 0), [0xff; 64]); // Actual rejected firstLE64 digest retained.
    tape.insert((0, 1), first);
    tape
}

#[test]
fn exact_query_tape_retains_retries_and_duplicates_and_rejects_unused_or_gapped_raw_draws() {
    let tape = literal_tape();
    let plan = TapePlan::checked(tape.clone()).unwrap();
    assert_eq!(plan.accepted().len(), 277);
    assert_eq!(plan.tape.len(), 278);
    assert_eq!(plan.indices().len(), 192);
    assert_eq!(plan.positions().len(), 191);
    assert_eq!(plan.indices()[0], plan.indices()[191]);
    assert_eq!(plan.row_for_query[0], plan.row_for_query[191]);
    assert_eq!(plan.accepted()[0], F::from_u32(11));
    let mut missing = tape.clone();
    missing.remove(&(0, 1));
    assert!(matches!(TapePlan::checked(missing), Err("Query-tape-gap")));
    let mut extra = tape.clone();
    extra.insert((277, 0), [0; 64]);
    assert!(matches!(
        TapePlan::checked(extra),
        Err("Query-tape-unused-raw")
    ));
    let mut early_accepted = tape;
    early_accepted.insert((0, 0), [0; 64]);
    assert!(matches!(
        TapePlan::checked(early_accepted),
        Err("Query-tape-unused-raw")
    ));
    let sampled = TapePlan::sample(&mut StdRng::from_seed([0x81; 32])).unwrap();
    assert_eq!(sampled.accepted().len(), 277);
    assert!(sampled.tape.len() >= 277);
}

fn native_shape(receiver: &Receiver) -> BatchShape {
    let global = receiver.common.preprocessed.as_ref().unwrap();
    BatchShape {
        trace_widths: vec![receiver.air.width()],
        public_value_counts: vec![receiver.air.num_public_values()],
        preprocessed_widths: vec![global.instances[0].as_ref().unwrap().width],
        has_preprocessed_commitment: true,
        num_lookup_instances: receiver
            .common
            .lookups
            .iter()
            .filter(|l| !l.is_empty())
            .count(),
        lookup_pow_bits: 0,
        has_randomization_commitment: true,
        ood_pow_bits: 0,
    }
}

fn native_claims(
    receiver: &Receiver,
    proof: &BatchProof<Config>,
    z: E,
) -> Vec<CommitmentOpening<E, Cap, TwoAdicMultiplicativeCoset<F>>> {
    // Exactly native batch verifier's masked domains: H4096 for R/MAIN/PP/AUX;
    // original quotient chunk height2048 is doubled and normalized to H4096.
    let domain = TwoAdicMultiplicativeCoset::new(F::ONE, 12).unwrap();
    let hz = z * F::two_adic_generator(11);
    let values = &proof.opened_values.instances[0];
    let base = &values.base_opened_values;
    let matrix = |local: &[E], next: Option<&[E]>| {
        let mut points = vec![PointOpening {
            point: z,
            values: local.to_vec(),
        }];
        if let Some(next) = next {
            points.push(PointOpening {
                point: hz,
                values: next.to_vec(),
            });
        }
        MatrixOpening { domain, points }
    };
    vec![
        CommitmentOpening {
            commitment: proof.commitments.random.clone().unwrap(),
            matrices: vec![matrix(base.random.as_ref().unwrap(), None)],
        },
        CommitmentOpening {
            commitment: proof.commitments.main.clone(),
            matrices: vec![matrix(&base.trace_local, base.trace_next.as_deref())],
        },
        CommitmentOpening {
            commitment: proof.commitments.quotient_chunks.clone(),
            matrices: base
                .quotient_chunks
                .iter()
                .map(|values| matrix(values, None))
                .collect(),
        },
        CommitmentOpening {
            commitment: receiver
                .common
                .preprocessed
                .as_ref()
                .unwrap()
                .commitment
                .clone(),
            matrices: vec![matrix(&base.preprocessed.as_ref().unwrap().local, None)],
        },
        CommitmentOpening {
            commitment: proof.commitments.permutation.clone().unwrap(),
            matrices: vec![matrix(
                &values.permutation_local,
                Some(&values.permutation_next),
            )],
        },
    ]
}

/// Component-only receiver: real batch transcript prefix and genuine native
/// HidingFriPcs verifier. It deliberately DOES NOT check AIR/quotient equations.
/// It exists solely inside this test child and is never an admitting callback.
fn native_pcs_component(receiver: &Receiver, proof: &BatchProof<Config>, walks: Walks) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = research_config::config(
            receiver.oracle.clone(),
            ResearchChallenger::receiver(receiver.oracle.clone(), walks),
            StdRng::from_seed([0x82; 32]),
            StdRng::from_seed([0x83; 32]),
            StdRng::from_seed([0x84; 32]),
        );
        let mut challenger = config.initialise_challenger();
        let mut batch =
            BatchVerifierTranscript::<_, F, E, Cap>::new(&mut challenger, native_shape(receiver));
        batch.instance_bindings(&proof.degree_bits);
        batch.main_phase(
            proof.commitments.main.clone(),
            &[receiver.expected.values()],
        );
        batch.preprocessed_phase(Some(
            receiver
                .common
                .preprocessed
                .as_ref()
                .unwrap()
                .commitment
                .clone(),
        ));
        let lookups = receiver
            .common
            .lookups
            .iter()
            .map(|l| &**l)
            .collect::<Vec<_>>();
        if batch
            .lookup_phase(&lookups, &LogUpGadget::new(), proof.lookup_pow_witness)
            .is_err()
        {
            return false;
        }
        let terminals = proof
            .lookup_terminals
            .iter()
            .flatten()
            .map(|t| t.0)
            .collect::<Vec<_>>();
        let _ = batch.permutation_phase(proof.commitments.permutation.clone(), &terminals);
        batch.quotient_phase(
            proof.commitments.quotient_chunks.clone(),
            proof.commitments.random.clone(),
        );
        let z = match batch.ood_phase(proof.ood_pow_witness) {
            Ok(z) => z,
            Err(_) => return false,
        };
        let claims = native_claims(receiver, proof, z);
        let result = batch.delegate(|challenger| {
            config.pcs().verify_with_preprocessing(
                claims,
                &proof.opening_proof,
                challenger,
                Some(3),
            )
        });
        batch.finish();
        result.is_ok()
    }))
    .unwrap_or(false)
}

struct PublicAlgebra {
    s: Vec<F>,
    z: E,
    theta: E,
    r: Vec<Column>,
    main: Vec<Column>,
    quotient: Vec<Vec<Column>>,
    pp: Vec<Column>,
    aux: Vec<Column>,
    pp_coefficients: Arc<Vec<Vec<F>>>,
}
impl PublicAlgebra {
    fn zero_private(inputs: &Inputs, plan: &TapePlan) -> Self {
        let s = plan.positions().to_vec();
        let zero = |next| Column {
            rows: vec![F::ZERO; s.len()],
            at_z: E::ZERO,
            at_hz: if next { Some(E::ZERO) } else { None },
        };
        let pp_coefficients = inputs.public_pp_coefficients();
        let native = inputs.pp.opening(plan.indices());
        let pp = pp_coefficients
            .iter()
            .enumerate()
            .map(|(column, polynomial)| {
                let mut rows = vec![F::ZERO; s.len()];
                for (query, &row) in plan.row_for_query.iter().enumerate() {
                    rows[row] = native.opened_values[query][0][column];
                }
                let at_z = polynomial
                    .iter()
                    .rev()
                    .fold(E::ZERO, |value, &c| value * plan.z() + c);
                Column {
                    rows,
                    at_z,
                    at_hz: None,
                }
            })
            .collect();
        Self {
            s: s.clone(),
            z: plan.z(),
            theta: plan.theta(),
            r: vec![zero(false); 10],
            main: vec![zero(true); 421],
            quotient: vec![vec![zero(false); 10]; 8],
            pp,
            aux: vec![zero(true); 425],
            pp_coefficients,
        }
    }
    fn view(&self) -> PublicView<'_> {
        PublicView {
            s: &self.s,
            z: self.z,
            theta: self.theta,
            r: &self.r,
            main: &self.main,
            quotient: &self.quotient,
            pp: &self.pp,
            pp_coefficients: &self.pp_coefficients,
            aux: &self.aux,
        }
    }
    fn exact_public_pp_deep(&self) -> Vec<E> {
        // Independent literal public polynomial construction: all four private
        // INPUT values/claims are zero. PP starts at native theta exponent932.
        let mut polynomial = vec![E::ZERO; 4096];
        let mut weight = self.theta.exp_u64(932);
        for coefficients in self.pp_coefficients.iter() {
            for (degree, &coefficient) in coefficients.iter().enumerate() {
                polynomial[degree] += weight * coefficient;
            }
            weight *= self.theta;
        }
        let mut quotient = vec![E::ZERO; 4095];
        let mut remainder = *polynomial.last().unwrap();
        for i in (0..quotient.len()).rev() {
            quotient[i] = remainder;
            remainder = polynomial[i] + self.z * remainder;
        }
        let mut weight = self.theta.exp_u64(932);
        let mut disclosed = E::ZERO;
        for column in &self.pp {
            disclosed += weight * column.at_z;
            weight *= self.theta;
        }
        assert_eq!(remainder, disclosed);
        quotient
    }
}

fn copy(frame: &ResearchFrame, receiver: &Receiver) -> BatchProof<Config> {
    decode(frame, &receiver.expected, &receiver.assessment).unwrap()
}

#[test]
#[ignore = "actual Query-height native FRI/5-input MMCS; run alone under owning held-process resource observer"]
fn genuine_native_fri_and_all_five_inputs_accept_public_algebra_without_a_private_trace() {
    let expected = super::super::super::tests::metadata();
    let programmer = Programmer::regression([0x85; 32]);
    let receiver = Receiver::new(&expected, programmer.oracle());
    let plan = TapePlan::checked(literal_tape()).unwrap();
    let inputs = Inputs::new(
        &expected,
        programmer,
        StdRng::from_seed([0x86; 32]),
        StdRng::from_seed([0x87; 32]),
    )
    .unwrap();
    let algebra = PublicAlgebra::zero_private(&inputs, &plan);
    let b = algebra.exact_public_pp_deep();
    let produced = Walks::default();
    let proof = inputs
        .prove(plan, &algebra.view(), &b, produced.clone())
        .unwrap();
    assert_eq!(proof.opening_proof.1.input_openings.len(), 5);
    assert_eq!(proof.opening_proof.1.commit_phase_commits.len(), 12);
    assert!(proof.opening_proof.0[3][0][0].is_empty());
    assert_eq!(
        proof.opened_values.instances[0]
            .base_opened_values
            .random
            .as_ref()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(proof.opening_proof.0[0][0][0].len(), 5);
    let frame = encode(&expected, &proof, &receiver.assessment);
    let received = Walks::default();
    assert!(native_pcs_component(&receiver, &proof, received.clone()));
    assert_eq!(produced.with_draws(), received.with_draws());
    let walk = produced.with_draws();
    assert_eq!(walk.len(), 1);
    assert_eq!(walk[0].draws.len(), 278); // One actual rejected full digest +277 accepted.
    assert_eq!(
        walk[0]
            .events
            .iter()
            .filter(|e| matches!(e, Event::Sample { .. }))
            .count(),
        277
    );
    // This explicit algebra fixture is NOT a valid Query witness/quotient.
    // Genuine complete AIR verification must reject it, despite PCS acceptance.
    assert!(!receiver.receive(&frame, Walks::default()));
    for round in 0..5 {
        let mut omitted = copy(&frame, &receiver);
        omitted.opening_proof.1.input_openings.remove(round);
        assert!(
            !native_pcs_component(&receiver, &omitted, Walks::default()),
            "omitted input round={round}"
        );
    }
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.1.input_openings[3].opening_proof.0[0][0][0] += F::ONE;
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.1.input_openings[3].opened_values[0][0][0] += F::ONE;
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.0[2][0][0][4] += E::ONE;
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.1.final_poly[0] += E::ONE;
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.1.batch_pow_witness = F::ONE;
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.1.input_openings.swap(2, 4);
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    let mut changed = copy(&frame, &receiver);
    changed.opening_proof.1.commit_phase_commits[0] = Cap::new(vec![[0; 32]]);
    assert!(!native_pcs_component(&receiver, &changed, Walks::default()));
    eprintln!(
        "research_query native_fri_public_algebra=true native_PCS_accepted=true native_AIR_rejected=true private_inputs=4 normal_public_PP=true native_input_rounds=5 FRI_rounds=12 samples=277 raw_draws=278 complete_walk_equal=true native_negative=12 full_public_sampler=false admission=false"
    );
}
