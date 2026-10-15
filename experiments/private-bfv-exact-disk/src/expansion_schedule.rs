//! Scheduling derivative of pinned Spiral coefficient_expansion/expand_query and
//! process_query (SDK fdb7206517c249603b0c91b65f1f29f95272107c, server.rs20-120,
//! 525-591,650-748). Copyright(c)2023Blyss Inc. MIT: ../LICENSE-BLYSS.
//! All rounds remain sequential. Only independent local siblings run together,
//! after their old-before-mutation copy. No SDK source or crypto parameter changes.
use crate::server_schedule as baseline;
use rayon::prelude::*;
use serde::Serialize;
use spiral_rs::{
    aligned_memory::AlignedMemory64,
    arith::{barrett_coeff_u64, log2_ceil_usize},
    client::{PublicParameters, Query},
    gadget::gadget_invert_rdim,
    params::Params,
    poly::*,
    server::{
        encode, fold_ciphertexts, get_v_folding_neg, multiply_reg_by_database, pack, regev_to_gsw,
    },
    util::reorient_reg_ciphertexts,
};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Schedule {
    Official,
    TrialsOnly,
    ExpansionOnly,
    Combined,
}
impl Schedule {
    pub fn pair_order(round: usize) -> [Self; 2] {
        if matches!(
            baseline::Schedule::pair_order(round)[0],
            baseline::Schedule::Official
        ) {
            [Self::TrialsOnly, Self::Combined]
        } else {
            [Self::Combined, Self::TrialsOnly]
        }
    }
    pub fn all_order(round: usize) -> [Self; 4] {
        if round.is_multiple_of(2) {
            [
                Self::Official,
                Self::TrialsOnly,
                Self::ExpansionOnly,
                Self::Combined,
            ]
        } else {
            [
                Self::Combined,
                Self::ExpansionOnly,
                Self::TrialsOnly,
                Self::Official,
            ]
        }
    }
}
struct ExpansionKeys<'p, 'k> {
    left: &'k [PolyMatrixNTT<'p>],
    right: &'k [PolyMatrixNTT<'p>],
    neg1: &'k [PolyMatrixNTT<'p>],
}
fn coefficient_expansion_pairs<'a>(
    v: &mut [PolyMatrixNTT<'a>],
    params: &'a Params,
    g: usize,
    stop_round: usize,
    keys: &ExpansionKeys<'a, '_>,
    max_bits_to_gen_right: usize,
) {
    let v_w_left = keys.left;
    let v_w_right = keys.right;
    let v_neg1 = keys.neg1;
    let poly_len = params.poly_len;

    for r in 0..g {
        let num_in = 1 << r;
        let num_out = 2 * num_in;

        let t = (poly_len / (1 << r)) + 1;

        let neg1 = &v_neg1[r];

        let action_expand = |(i, v_i): (usize, &mut PolyMatrixNTT)| {
            if (stop_round > 0 && r > stop_round && (i % 2) == 1)
                || (stop_round > 0
                    && r == stop_round
                    && (i % 2) == 1
                    && (i / 2) >= max_bits_to_gen_right)
            {
                return;
            }

            let mut ct = PolyMatrixRaw::zero(params, 2, 1);
            let mut ct_auto = PolyMatrixRaw::zero(params, 2, 1);
            let mut ct_auto_1 = PolyMatrixRaw::zero(params, 1, 1);
            let mut ct_auto_1_ntt = PolyMatrixNTT::zero(params, 1, 1);
            let mut w_times_ginv_ct = PolyMatrixNTT::zero(params, 2, 1);

            let mut ginv_ct_left = PolyMatrixRaw::zero(params, params.t_exp_left, 1);
            let mut ginv_ct_left_ntt = PolyMatrixNTT::zero(params, params.t_exp_left, 1);
            let mut ginv_ct_right = PolyMatrixRaw::zero(params, params.t_exp_right, 1);
            let mut ginv_ct_right_ntt = PolyMatrixNTT::zero(params, params.t_exp_right, 1);

            let (w, _gadget_dim, gi_ct, gi_ct_ntt) = match (r != 0) && (i % 2 == 0) {
                true => (
                    &v_w_left[r],
                    params.t_exp_left,
                    &mut ginv_ct_left,
                    &mut ginv_ct_left_ntt,
                ),
                false => (
                    &v_w_right[r],
                    params.t_exp_right,
                    &mut ginv_ct_right,
                    &mut ginv_ct_right_ntt,
                ),
            };

            from_ntt(&mut ct, v_i);
            automorph(&mut ct_auto, &ct, t);
            gadget_invert_rdim(gi_ct, &ct_auto, 1);
            to_ntt_no_reduce(gi_ct_ntt, gi_ct);
            ct_auto_1
                .data
                .as_mut_slice()
                .copy_from_slice(ct_auto.get_poly(1, 0));
            to_ntt(&mut ct_auto_1_ntt, &ct_auto_1);
            multiply(&mut w_times_ginv_ct, w, gi_ct_ntt);

            let mut idx = 0;
            for j in 0..2 {
                for n in 0..params.crt_count {
                    for z in 0..poly_len {
                        let sum = v_i.data[idx]
                            + w_times_ginv_ct.data[idx]
                            + j * ct_auto_1_ntt.data[n * poly_len + z];
                        v_i.data[idx] = barrett_coeff_u64(params, sum, n);
                        idx += 1;
                    }
                }
            }
        };

        // Copy each old item into its new sibling before mutating that old item.
        // Both action calls use LOCAL i, matching the two original enumerate()
        // calls. All pairs finish before the next sequential r iteration.
        let (src, dest) = v[..num_out].split_at_mut(num_in);
        src.par_iter_mut()
            .zip(dest.par_iter_mut())
            .enumerate()
            .for_each(|(i, (s, d))| {
                scalar_multiply(d, neg1, s);
                rayon::join(|| action_expand((i, s)), || action_expand((i, d)));
            });
    }
}
pub fn expand_query_pairs<'a>(
    params: &'a Params,
    public_params: &PublicParameters<'a>,
    query: &Query<'a>,
) -> (AlignedMemory64, Vec<PolyMatrixNTT<'a>>) {
    crate::server_schedule::profile_gate(params, 4 * 512 * 2048);
    let dim0 = 1 << params.db_dim_1;
    let further_dims = params.db_dim_2;

    let num_bits_to_gen = params.t_gsw * further_dims + dim0;
    let g = log2_ceil_usize(num_bits_to_gen);
    let right_expanded = params.t_gsw * further_dims;
    let stop_round = log2_ceil_usize(right_expanded);

    let mut v = Vec::new();
    for _ in 0..(1 << g) {
        v.push(PolyMatrixNTT::zero(params, 2, 1));
    }
    v[0].copy_into(&query.ct.as_ref().unwrap().ntt(), 0, 0);

    let v_conversion = &public_params.v_conversion.as_ref().unwrap()[0];
    let v_w_left = public_params.v_expansion_left.as_ref().unwrap();
    let v_w_right = public_params.v_expansion_right.as_ref().unwrap_or(v_w_left);
    let v_neg1 = params.get_v_neg1();
    let keys = ExpansionKeys {
        left: v_w_left,
        right: v_w_right,
        neg1: &v_neg1,
    };

    let mut v_reg_inp = Vec::with_capacity(dim0);
    let mut v_gsw_inp = Vec::with_capacity(right_expanded);
    if further_dims > 0 {
        coefficient_expansion_pairs(
            &mut v,
            params,
            g,
            stop_round,
            &keys,
            params.t_gsw * params.db_dim_2,
        );

        for i in 0..dim0 {
            v_reg_inp.push(v[2 * i].clone());
        }
        for i in 0..right_expanded {
            v_gsw_inp.push(v[2 * i + 1].clone());
        }
    } else {
        coefficient_expansion_pairs(&mut v, params, g, 0, &keys, 0);
        for item in v.iter().take(dim0) {
            v_reg_inp.push(item.clone());
        }
    }

    let v_reg_sz = dim0 * 2 * params.poly_len;
    let mut v_reg_reoriented = AlignedMemory64::new(v_reg_sz);
    reorient_reg_ciphertexts(params, v_reg_reoriented.as_mut_slice(), &v_reg_inp);

    let mut v_folding = Vec::new();
    for _ in 0..params.db_dim_2 {
        v_folding.push(PolyMatrixNTT::zero(params, 2, 2 * params.t_gsw));
    }

    regev_to_gsw(&mut v_folding, &v_gsw_inp, v_conversion, params, 1, 0);

    (v_reg_reoriented, v_folding)
}

#[derive(Serialize)]
pub struct Stages {
    pub expansion_ms: f64,
    pub folding_neg_ms: f64,
    pub trials_wall_ms: f64,
    pub pack_encode_ms: f64,
}
fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
pub fn evaluate(
    params: &Params,
    public: &PublicParameters,
    query: &Query,
    db: &[u64],
    schedule: Schedule,
) -> Vec<u8> {
    match schedule {
        Schedule::Official => {
            baseline::evaluate(params, public, query, db, baseline::Schedule::Official)
        }
        Schedule::TrialsOnly => baseline::evaluate(
            params,
            public,
            query,
            db,
            baseline::Schedule::ParallelTrials,
        ),
        _ => candidate(params, public, query, db, schedule == Schedule::Combined).0,
    }
}
pub fn candidate(
    params: &Params,
    public: &PublicParameters,
    query: &Query,
    db: &[u64],
    parallel_trials: bool,
) -> (Vec<u8>, Stages) {
    baseline::profile_gate(params, db.len());
    let dim0 = 1 << params.db_dim_1;
    let num_per = 1 << params.db_dim_2;
    let stride = dim0 * num_per * params.poly_len;
    let start = Instant::now();
    let (reg, fold) = expand_query_pairs(params, public, query);
    let expansion_ms = elapsed(start);
    let start = Instant::now();
    let neg = get_v_folding_neg(params, &fold);
    let folding_neg_ms = elapsed(start);
    let start = Instant::now();
    let trial = |i| {
        let mut ntt = (0..num_per)
            .map(|_| PolyMatrixNTT::zero(params, 2, 1))
            .collect::<Vec<_>>();
        let mut raw = (0..num_per)
            .map(|_| PolyMatrixRaw::zero(params, 2, 1))
            .collect::<Vec<_>>();
        multiply_reg_by_database(
            &mut ntt,
            &db[i * stride..(i + 1) * stride],
            reg.as_slice(),
            params,
            dim0,
            num_per,
        );
        for (r, n) in raw.iter_mut().zip(&ntt) {
            from_ntt(r, n);
        }
        fold_ciphertexts(params, &mut raw, &fold, &neg);
        raw.remove(0)
    };
    let cts: Vec<PolyMatrixRaw> = if parallel_trials {
        (0..params.n * params.n)
            .into_par_iter()
            .map(trial)
            .collect()
    } else {
        (0..params.n * params.n).map(trial).collect()
    };
    let trials_wall_ms = elapsed(start);
    let start = Instant::now();
    let packed = pack(params, &cts, &public.v_packing).raw();
    let wire = encode(params, &vec![packed]);
    (
        wire,
        Stages {
            expansion_ms,
            folding_neg_ms,
            trials_wall_ms,
            pack_encode_ms: elapsed(start),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_matrix_compares_trial_baseline_to_combined_with_reversed_order() {
        assert_eq!(
            Schedule::pair_order(0),
            [Schedule::TrialsOnly, Schedule::Combined]
        );
        assert_eq!(
            Schedule::pair_order(1),
            [Schedule::Combined, Schedule::TrialsOnly]
        );
    }
    #[test]
    fn boundary_controls_preserve_every_schedule_in_both_orders() {
        let forward = Schedule::all_order(0);
        let reverse = Schedule::all_order(1);
        for (left, right) in forward.iter().zip(reverse.iter().rev()) {
            assert_eq!(left, right);
        }
        assert_eq!(
            forward,
            [
                Schedule::Official,
                Schedule::TrialsOnly,
                Schedule::ExpansionOnly,
                Schedule::Combined
            ]
        );
    }
}
