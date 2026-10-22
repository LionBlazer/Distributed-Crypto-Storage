//! Finite public-fixture certificate experiment. Never a DCS proof dispatcher.
#![forbid(unsafe_code)]
mod fixture;
mod gold_formation;

use bfv_unrelinearized_product::{
    CERTIFICATE_BYTES, N, POINTS, Q, QP, check_arithmetic, produce, profile_digest,
    wire_profile_digest,
};
use sha2::{Digest, Sha512};
use std::time::Instant;

type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
enum Error {
    Shape,
    Arithmetic,
    Binding,
    Resource,
    Backend,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "public arithmetic experiment rejected {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<bfv_unrelinearized_product::Error> for Error {
    fn from(error: bfv_unrelinearized_product::Error) -> Self {
        match error {
            bfv_unrelinearized_product::Error::Shape => Self::Shape,
            bfv_unrelinearized_product::Error::Arithmetic => Self::Arithmetic,
            bfv_unrelinearized_product::Error::Binding => Self::Binding,
            bfv_unrelinearized_product::Error::Resource => Self::Resource,
            bfv_unrelinearized_product::Error::Backend => Self::Backend,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--show-profile"] {
        println!(
            "{}",
            serde_json::json!({
                "kind":"unassessed_public_arithmetic_certificate_profile", "profile_sha512":hex(&profile_digest()),
                "degree":N, "ordered_qp":QP, "certificate_bytes":CERTIFICATE_BYTES,
                "certificate_wire_profile":hex(&wire_profile_digest()),
                "points_per_basis":POINTS, "cryptographic_security_assessed":false, "sql_accepted":false
            })
        );
        return Ok(());
    }
    if args == ["--private-formation-fixture"] {
        let observation = fixture::audit_private_witness()?;
        let phases = serde_json::json!({
            "preparation_ms":observation.preparation_ms,"sdk_product_ms":observation.sdk_product_ms,
            "witness_build_ms":observation.witness_build_ms,"witness_check_ms":observation.witness_check_ms,
            "whole_local_including_sdk_product_ms":observation.whole_local_ms
        });
        println!(
            "{}",
            serde_json::json!({
                "kind":"owner_private_gold_formation_witness_observation","degree":N,"ordered_q":Q,
                "phases":phases,"private_witness_checked":true,"private_witness_exported":false,
                "coefficient_counts":{"secret":N,"shared_errors":2*N,"signed_quotients":4*N},
                "logical_buffers":{"private_witness_bytes":gold_formation::PRIVATE_WITNESS_BYTES,
                "formation_logical_vectors_upper_bound_bytes":gold_formation::LOGICAL_VECTOR_BYTES,"rss_measured":false},
                "proof_verified":false,"cryptographic_security_assessed":false,"source_authenticated":false,
                "sql_accepted":false,"fresh_head_verified":false,"network_measured":false
            })
        );
        return Ok(());
    }
    if args == ["--private-formation-graph-fixture"] {
        let observation = fixture::audit_private_graph()?;
        let graph = observation.graph;
        println!(
            "{}",
            serde_json::json!({
                "kind":"owner_private_gold_formation_graph_observation",
                "degree":N,"ordered_q":Q,
                "phases":{
                    "preparation_ms":observation.preparation_ms,
                    "sdk_product_ms":observation.sdk_product_ms,
                    "witness_build_ms":observation.witness_build_ms,
                    "precheck_ms":graph.precheck_ms,"public_plan_ms":graph.public_plan_ms,
                    "trace_build_and_audit_ms":graph.trace_build_and_audit_ms,
                    "coefficient_check_ms":graph.coefficient_check_ms,
                    "whole_local_including_sdk_product_ms":observation.whole_local_ms
                },
                "graph":{
                    "gates":graph.gates,"rows":graph.rows,"slots":graph.slots,
                    "nodes":graph.nodes,"trace_bytes":graph.trace_bytes,
                    "logical_vector_upper_bound_bytes":graph.logical_vector_upper_bound_bytes
                },
                "private_graph_checked":true,"private_graph_exported":false,
                "proof_verified":false,"cryptographic_security_assessed":false,
                "source_authenticated":false,"sql_accepted":false,
                "fresh_head_verified":false,"network_measured":false
            })
        );
        return Ok(());
    }
    if args == ["--unverified-formation-air-plan"] {
        println!(
            "{}",
            serde_json::json!({
                "kind":"UNVERIFIED_formation_air_symbolic_plan", "degree":N,
                "proof_verified":false,"cryptographic_security_assessed":false,
                "source_authenticated":false,"key_authenticated":false,
                "sql_accepted":false,"fresh_head_verified":false,"network_measured":false,
                "private_trace_allocated":false,"pp_committed":false
            })
        );
        let example = fixture::example()?;
        gold_formation::inspect_unverified_air(&example.statement)?;
        return Ok(());
    }
    if args != ["--public-fixture"] {
        return Err(Error::Shape.into());
    }
    let began = Instant::now();
    let example = fixture::example()?;
    let produce_start = Instant::now();
    let frame = produce(&example.statement)?.into_bytes();
    let produce_ms = produce_start.elapsed().as_secs_f64() * 1000.;
    let verify_start = Instant::now();
    drop(check_arithmetic(&example.statement, &frame)?);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.;
    let complete_start = Instant::now();
    example.complete()?;
    let completion_ms = complete_start.elapsed().as_secs_f64() * 1000.;
    let total_ms = began.elapsed().as_secs_f64() * 1000.;
    println!(
        "{}",
        serde_json::json!({
            "kind":"public_arithmetic_certificate_observation", "profile_sha512":hex(&profile_digest()),
            "certificate_wire_profile":hex(&wire_profile_digest()),
            "preparation_ms":example.preparation_ms, "sdk_product_ms":example.product_ms,
            "certificate_production_ms":produce_ms, "arithmetic_certificate_check_ms":verify_ms,
            "client_completion_ms":completion_ms,
            "whole_local_experiment_ms":total_ms, "certificate_bytes":frame.len(), "frame_sha512":hex(&Sha512::digest(&frame)),
            "wire_bytes":{"request":example.statement.request_wire().len(),"output":example.statement.output_wire().len(),"certificate":frame.len()},
            "public_fixture_full_decrypted_coefficients_match":true,
            "arithmetic_checks_passed":true, "proof_verified":false, "cryptographic_security_assessed":false,
            "lattice_security_assessed":false, "noise_certified":false, "source_authenticated":false,
            "sql_accepted":false, "fresh_head_verified":false, "network_measured":false
        })
    );
    Ok(())
}
