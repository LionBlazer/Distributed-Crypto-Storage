//! Finite public-fixture certificate experiment. Never a DCS proof dispatcher.
#![forbid(unsafe_code)]
mod certificate;
mod fixture;
mod geometry;
mod modular;
mod pit;
mod scale;
mod statement;

use sha2::{Digest, Sha512};
use std::time::Instant;
type Polynomial = Vec<Vec<u64>>;
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

fn profile_digest() -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/UNREL-PUBLIC-CERTIFICATE-EXPERIMENT/v1/UNASSESSED/");
    for n in [geometry::N as u64, geometry::T] {
        h.update(n.to_le_bytes());
    }
    for p in geometry::QP {
        h.update(p.to_le_bytes());
    }
    h.update(scale::profile_digest(scale::Role::Extend2To4));
    h.update(scale::profile_digest(scale::Role::Scale4To2));
    h.update(b"unseededCT2+2/CT3;lvl0;NttTagStoredPB;nonce32;ProtoCanonicalAllResidues;Extend4ExactQCopies;RNSProducts3xQP;C0=A0B0,C1=A0B1+A1B0,C2=A1B1;ordinary2N;HlengthN-1;YlengthN;F=AB-Y-(xN+1)H;Scale3Exact;all7CompactIntegerCertificates;allDataBeforeFS;SHA512fullMessagePrefixClone;basisU32LE/sampleU32LE;OS2IP512modp;noNTTverifier;noSDKqueryreplay;fixedPackedWidths30,30,62,62;fullEOF;noProofOrSourceOrSQLOrSecurityGrant;");
    h.update((pit::POINTS as u64).to_le_bytes());
    h.update((certificate::FRAME_BYTES as u64).to_le_bytes());
    h.finalize().into()
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
                "degree":geometry::N, "ordered_qp":geometry::QP, "certificate_bytes":certificate::FRAME_BYTES,
                "points_per_basis":pit::POINTS, "cryptographic_security_assessed":false, "sql_accepted":false
            })
        );
        return Ok(());
    }
    if args != ["--public-fixture"] {
        return Err(Error::Shape.into());
    }
    let began = Instant::now();
    let example = fixture::example()?;
    let produce_start = Instant::now();
    let frame = certificate::produce(&example.statement)?;
    let produce_ms = produce_start.elapsed().as_secs_f64() * 1000.;
    let verify_start = Instant::now();
    certificate::check(&example.statement, &frame)?;
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.;
    let complete_start = Instant::now();
    example.complete()?;
    let completion_ms = complete_start.elapsed().as_secs_f64() * 1000.;
    let total_ms = began.elapsed().as_secs_f64() * 1000.;
    println!(
        "{}",
        serde_json::json!({
            "kind":"public_arithmetic_certificate_observation", "profile_sha512":hex(&profile_digest()),
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
