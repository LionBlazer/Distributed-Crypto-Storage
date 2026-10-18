use bfv_arithmetic_batch_proof::{Expected, backend, fixture, prove, verify};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("expected security or prove")?;
    let context = fixture::context();
    match mode.as_str() {
        "security" => println!("{}", serde_json::to_string(&backend::analyze(context)?)?),
        "prove" => {
            let requests = fixture::requests(context)?;
            let generated = prove(context, &requests)?;
            let expected = Expected::new(context, requests, generated.outputs)?;
            println!("{}", serde_json::to_string(&generated.report)?);
            let request = expected.request_wire();
            let output = expected.output_wire();
            drop(expected);
            let fresh = Expected::from_wires(&request, &output)?;
            let checked = verify(&fresh, &generated.frame)?;
            if !checked.matches(&fresh) {
                return Err("checked statement mismatch".into());
            }
            println!(
                "{}",
                serde_json::json!({"stage":"prove_arithmetic_batch","verified":true,"relations":17,"proof_bytes":generated.frame.len(),"request_bytes":request.len(),"output_bytes":output.len(),"generation_ms":generated.generation_ms,"fresh_verification_ms":checked.verification_ms,"live_sql_grant":false,"mulrelin_grant":false})
            );
        }
        _ => return Err("expected security or prove".into()),
    }
    Ok(())
}
