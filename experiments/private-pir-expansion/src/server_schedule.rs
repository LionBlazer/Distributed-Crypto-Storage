//! Scheduling-only derivative of Spiral server::process_query at SDK
//! fdb7206517c249603b0c91b65f1f29f95272107c, server.rs:650-748.
//! Copyright (c) 2023, Blyss Inc. MIT license: ../LICENSE-BLYSS.
//! Every ring operation calls the unmodified SDK; the four independent trial
//! tasks execute in parallel and indexed collect preserves the original pack order.
//! CLIENT_TEST is never read, assigned, or copied: no diagnostic owner key enters
//! this public-only evaluator. This wrapper is opt-in research, not a new PIR scheme.
use rayon::prelude::*;
use serde::Serialize;
use spiral_rs::{
    client::{PublicParameters, Query},
    params::Params,
    poly::{PolyMatrix, PolyMatrixNTT, PolyMatrixRaw, from_ntt},
    server::{
        encode, expand_query, fold_ciphertexts, get_v_folding_neg, multiply_reg_by_database, pack,
        process_query,
    },
};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Serialize)]
pub enum Schedule {
    Official,
    ParallelTrials,
}
impl Schedule {
    pub fn pair_order(round: usize) -> [Self; 2] {
        if round.is_multiple_of(2) {
            [Self::Official, Self::ParallelTrials]
        } else {
            [Self::ParallelTrials, Self::Official]
        }
    }
}
#[derive(Serialize)]
pub struct Stages {
    pub expansion_ms: f64,
    pub folding_neg_ms: f64,
    pub trial_wall_ms: f64,
    pub pack_ms: f64,
    pub encode_ms: f64,
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// Fail closed if this scheduling probe is accidentally used for a different
/// profile. This is the already measured native 512x8192B profile, unchanged.
pub fn profile_gate(params: &Params, db_words: usize) {
    assert_eq!(params.poly_len, 2048);
    assert_eq!(params.crt_count, 2);
    assert_eq!(&params.moduli[..2], &[268369921, 249561089]);
    assert_eq!(params.n, 2);
    assert_eq!(params.instances, 1);
    assert_eq!(params.db_dim_1, 7);
    assert_eq!(params.db_dim_2, 2);
    assert_eq!(params.pt_modulus, 256);
    assert_eq!(params.q2_bits, 20);
    assert_eq!(params.noise_width, 6.4);
    assert_eq!(params.t_conv, 4);
    assert_eq!(params.t_gsw, 8);
    assert_eq!(params.t_exp_left, 8);
    assert_eq!(params.t_exp_right, 56);
    assert!(params.expand_queries);
    assert_eq!(params.db_item_size, 8192);
    assert_eq!(params.version, 0);
    assert_eq!(db_words, 4 * 512 * 2048);
}

pub fn evaluate(
    params: &Params,
    public: &PublicParameters,
    query: &Query,
    db: &[u64],
    schedule: Schedule,
) -> Vec<u8> {
    match schedule {
        Schedule::Official => process_query(params, public, query, db),
        Schedule::ParallelTrials => parallel_trials(params, public, query, db).0,
    }
}

pub fn parallel_trials(
    params: &Params,
    public: &PublicParameters,
    query: &Query,
    db: &[u64],
) -> (Vec<u8>, Stages) {
    profile_gate(params, db.len());
    let dim0 = 1 << params.db_dim_1;
    let num_per = 1 << params.db_dim_2;
    let db_slice_words = dim0 * num_per * params.poly_len;
    let start = Instant::now();
    let (v_reg_reoriented, v_folding) = expand_query(params, public, query);
    let expansion_ms = elapsed(start);
    let start = Instant::now();
    let v_folding_neg = get_v_folding_neg(params, &v_folding);
    let folding_neg_ms = elapsed(start);
    let start = Instant::now();
    let v_ct: Vec<PolyMatrixRaw> = (0..params.n * params.n)
        .into_par_iter()
        .map(|trial| {
            let mut intermediate = (0..num_per)
                .map(|_| PolyMatrixNTT::zero(params, 2, 1))
                .collect::<Vec<_>>();
            let mut intermediate_raw = (0..num_per)
                .map(|_| PolyMatrixRaw::zero(params, 2, 1))
                .collect::<Vec<_>>();
            let offset = trial * db_slice_words;
            multiply_reg_by_database(
                &mut intermediate,
                &db[offset..offset + db_slice_words],
                v_reg_reoriented.as_slice(),
                params,
                dim0,
                num_per,
            );
            for (raw, ntt) in intermediate_raw.iter_mut().zip(&intermediate) {
                from_ntt(raw, ntt);
            }
            fold_ciphertexts(params, &mut intermediate_raw, &v_folding, &v_folding_neg);
            intermediate_raw.remove(0)
        })
        .collect();
    let trial_wall_ms = elapsed(start);
    let start = Instant::now();
    let packed = pack(params, &v_ct, &public.v_packing).raw();
    let pack_ms = elapsed(start);
    let start = Instant::now();
    let output = encode(params, &vec![packed]);
    let encode_ms = elapsed(start);
    (
        output,
        Stages {
            expansion_ms,
            folding_neg_ms,
            trial_wall_ms,
            pack_ms,
            encode_ms,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use spiral_rs::util::{CFG_20_256, params_from_json_obj};
    fn profile() -> Params {
        let mut cfg: serde_json::Value =
            serde_json::from_str(&CFG_20_256.replace('\'', "\"")).unwrap();
        cfg["nu_1"] = serde_json::json!(7);
        cfg["nu_2"] = serde_json::json!(2);
        params_from_json_obj(&cfg)
    }
    #[test]
    fn scheduling_gate_accepts_only_the_measured_public_profile_and_exact_database_extent() {
        let params = profile();
        profile_gate(&params, 4 * 512 * 2048);
        assert!(std::panic::catch_unwind(|| profile_gate(&params, 4 * 512 * 2048 - 1)).is_err());
        let mut wrong = params.clone();
        wrong.db_dim_1 = 8;
        assert!(std::panic::catch_unwind(|| profile_gate(&wrong, 4 * 512 * 2048)).is_err());
    }
    #[test]
    fn paired_schedule_order_reverses_on_the_next_round() {
        assert!(matches!(
            Schedule::pair_order(0),
            [Schedule::Official, Schedule::ParallelTrials]
        ));
        assert!(matches!(
            Schedule::pair_order(1),
            [Schedule::ParallelTrials, Schedule::Official]
        ));
    }
}
