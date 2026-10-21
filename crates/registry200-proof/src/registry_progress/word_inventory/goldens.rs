//! Mandatory literal regression pins from actual PUBLIC27, not proof authority.
use super::{plan::Plan, tests::full_ir_bytes};
use bfv_hiding_stark::Config;
use p3_batch_stark::ProverData;
use p3_field::PrimeField64;
use sha2::{Digest, Sha512};
struct Pins {
    rows: usize,
    ir_bytes: usize,
    ir: &'static str,
    pp: &'static str,
    commitment: &'static str,
}
fn pins(predicate: bool) -> Pins {
    if predicate {
        Pins {
            rows: 460,
            ir_bytes: 289102,
            ir: "c38940d012da20a48e2e584e349b21e34878963ddd1e5285e98934fd61b89df4e280a335d6a1265a50a466e26a1b19eb68ebfc0cf86eab65681e4e380a321494",
            pp: "483f7cdfd130de258f54297911567a465d8c63f20412021e7a0e30110e29ae209ee53183d8ed8b5984b75a1a510ea9ad74bebbc959340f4285df8730177058df",
            commitment: "640207849aa615f53074df7f0186bea9be37f0d76b5d6d391ddea6cfced489f14aae9fe55a64f3f93a06506b1c8b0049ddecfb10fd5c705072b9c185277cfdb3",
        }
    } else {
        Pins {
            rows: 462,
            ir_bytes: 284117,
            ir: "7989f92e0d8fbb9d46a317710a24a4f29ae13c1f81a0ceda0a76bafa0af83c8f0eadfc83ccdf2020ab5cfd0351be23f5ac1554d6388023f252df0e5871060855",
            pp: "b2c89743d12867594158d0f4a6a9211f34e5686b6c49f0fc8bf5b5acd76b011ec8113d5e41e9faa325993197302b2e55a6a5f17f92e0ea79e6538ed51bd3b8eb",
            commitment: "fb6594efe1a81af6e8738ba9a262d14e79f011ddb4301a2ab6bb9fba3a3fdd81ab48c57a81d0fa5b8098df1d96f9d120e4168a4776342103868c4a9fdafeb77b",
        }
    }
}
/// No capture fallback. Every graph and every PP cell must match actual baseline.
pub(super) fn require_plan(plan: &Plan) -> Result<(), String> {
    let p = pins(plan.pool.predicate);
    if plan.height != 512
        || plan.rows.len() != p.rows
        || super::plan::WIDTH != 568
        || super::plan::PP_WIDTH != 714
    {
        return Err("literal-role-geometry".into());
    }
    let ir = full_ir_bytes(&plan.pool);
    if ir.len() != p.ir_bytes || format!("{:x}", Sha512::digest(&ir)) != p.ir {
        return Err("literal-full-IR-golden".into());
    }
    let mut h = Sha512::new();
    for row in 0..plan.height {
        for x in plan.pp_row(row) {
            h.update(x.as_canonical_u64().to_le_bytes());
        }
    }
    if format!("{:x}", h.finalize()) != p.pp {
        return Err("literal-full-PP-golden".into());
    }
    Ok(())
}
pub(super) fn require_commitment(predicate: bool, data: &ProverData<Config>) -> Result<(), String> {
    let pp = data
        .common
        .preprocessed
        .as_ref()
        .ok_or("missing-public-PP")?;
    let bytes = postcard::to_allocvec(&pp.commitment).map_err(|_| "public-commitment-encoding")?;
    if format!("{:x}", Sha512::digest(bytes)) != pins(predicate).commitment {
        return Err("literal-native-public-commitment".into());
    }
    Ok(())
}
