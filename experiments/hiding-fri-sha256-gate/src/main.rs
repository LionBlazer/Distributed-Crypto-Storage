//! Nonaccepting source-opening research gates. Never used for SQL acceptance.
#![forbid(unsafe_code)]

mod air;
mod backend;
mod chacha;
mod opening;
mod poly1305;
mod primitive;
mod statement;
#[cfg(test)]
mod tests;

use std::time::Instant;

use backend::{AllocationEstimate, Backend, Error, analyze};
use p3_air::BaseAir;
use primitive::{PrimitiveStatement, PublicStatement};

fn run() -> Result<(), Error> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) || !matches!(arguments[0].as_str(), "security" | "prove")
    {
        eprintln!(
            "usage: hiding-fri-source-primitives <security|prove> <sha256|hchacha20|chacha20|poly1305-raw|poly1305-padded|pair-opening|canonical-index-opening> [empty: Poly1305 security only]"
        );
        return Err(Error::Shape);
    }
    let empty = arguments.len() == 3;
    if empty
        && (arguments[0] != "security"
            || arguments[2] != "empty"
            || !matches!(arguments[1].as_str(), "poly1305-raw" | "poly1305-padded"))
    {
        return Err(Error::Shape); // Reject prove+empty before statement/trace creation.
    }
    let case = if empty { "empty" } else { "fixture" };

    match arguments[1].as_str() {
        "pair-opening" => opening::gate(&arguments[0]),
        "canonical-index-opening" => opening::canonical_gate(&arguments[0]),
        "sha256" => gate(&statement::Statement::fixture(), &arguments[0], case),
        "hchacha20" => gate(
            &chacha::statement::Statement::hchacha_fixture(),
            &arguments[0],
            case,
        ),
        "chacha20" => gate(
            &chacha::statement::Statement::chacha_fixture(),
            &arguments[0],
            case,
        ),
        "poly1305-raw" => {
            let statement = if empty {
                poly1305::statement::Statement::raw(poly1305::statement::public_key(), &[])?
            } else {
                poly1305::statement::Statement::raw_fixture()
            };
            gate(&statement, &arguments[0], case)
        }
        "poly1305-padded" => {
            let statement = if empty {
                poly1305::statement::Statement::padded(poly1305::statement::public_key(), &[])?
            } else {
                poly1305::statement::Statement::padded_fixture()
            };
            gate(&statement, &arguments[0], case)
        }
        _ => Err(Error::Shape),
    }
}

fn gate(statement: &impl PrimitiveStatement, mode: &str, case: &str) -> Result<(), Error> {
    security(statement, case)?;
    if mode == "prove" {
        let backend = Backend::new(statement)?;
        let started = Instant::now();
        let proof = backend.prove(statement)?;
        let proving = started.elapsed();
        let started = Instant::now();
        backend.verify(statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_public_primitive\",\"primitive\":\"{}\",\"statement_case\":\"{}\",\"proving_ms\":{},\"verification_ms\":{}}}",
            statement.kind().name(),
            case,
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

fn security(statement: &impl PublicStatement, case: &str) -> Result<(), Error> {
    let air = statement.air();
    let (_, report) = analyze(&air)?;
    let allocation = AllocationEstimate::for_width(air.width());
    let points = 1 + usize::from(!air.main_next_row_columns().is_empty());
    println!(
        "{{\"stage\":\"security\",\"primitive\":\"{}\",\"statement_case\":\"{}\",\"trace_height\":{},\"trace_width\":{},\"proof_degree_bits\":{},\"queries\":{},\"random_codewords\":{},\"opening_points\":{},\"periodic_columns\":{},\"unique_decoding_bits\":{},\"list_decoding_bits\":{},\"constraints\":{},\"degree\":{},\"quotient_chunks\":{},\"batched_functions\":{},\"trace_bytes\":{},\"masked_trace_bytes\":{},\"main_lde_bytes\":{}}}",
        statement.kind().name(),
        case,
        backend::TRACE_HEIGHT,
        air.width(),
        backend::PROOF_DEGREE_BITS,
        backend::QUERIES,
        backend::RANDOM_CODEWORDS,
        points,
        air.num_periodic_columns(),
        report.unique_decoding_bits,
        report.list_decoding_bits,
        report.constraints,
        report.degree,
        report.quotient_chunks,
        report.batched_functions,
        allocation.trace_bytes,
        allocation.masked_trace_bytes,
        allocation.main_lde_bytes,
    );
    report.require_target()?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nonaccepting primitive gate rejected: {error}");
        std::process::exit(1);
    }
}
