use bfv_ntt_batch_proof::{Expected, backend, fixture, prove, verify};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || !matches!(args[0].as_str(), "security" | "prove") {
        return Err("usage: bfv-ntt-batch-proof <security|prove> <2|4|8>".into());
    }
    let count = args[1].parse::<usize>()?;
    if !matches!(count, 2 | 4 | 8) {
        return Err("batch must be 2, 4 or 8".into());
    }
    let context = fixture::context();
    let specs = fixture::specs(count);
    println!(
        "{}",
        serde_json::to_string(&backend::analyze(context, &specs)?)?
    );
    if args[0] == "security" {
        return Ok(());
    }
    let requests = fixture::requests(context, &specs)?;
    let generated = prove(context, &requests)?;
    let expected = Expected::new(context, requests, generated.outputs)?;
    let checked = verify(&expected, &generated.frame)?;
    if !checked.matches(&expected) {
        return Err("checked batch mismatch".into());
    }
    println!(
        "{}",
        serde_json::json!({"stage":"verified_batched_ntt","batch":count,"component_count":count/2,"instances_per_component":2,"coefficients_per_instance":8192,"proof_bytes":generated.frame.len(),"generation_ms":generated.generation_ms,"verification_ms":checked.verification_ms,"public_nonsecret":true,"private_aux_in_frame":false,"atomic_complete_batch":true,"whole_mul_relin":false,"sql_grant":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
