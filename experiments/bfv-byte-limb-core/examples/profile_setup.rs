//! Public-fixture cold setup comparison; no participant data or secret output.
#[path = "support/profile_memory.rs"]
mod memory;
use compact_bfv_byte_limb_core::{
    Geometry, Owner, PeerEvaluator, Predicate, ProofStatus, PublicSetup, QueryContext,
    SelectedField,
};
use serde_json::json;
use std::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !["catalog", "direct"].contains(&args[0].as_str()) {
        return Err("Use profile_setup <catalog|direct> <16|256>".into());
    }
    let geometry = match args[1].as_str() {
        "16" => Geometry::Rows16,
        "256" => Geometry::Rows256,
        _ => return Err("Only measured geometries16/256 are accepted".into()),
    };
    memory::guard(256 * 1024 * 1024)?;
    let cold = Instant::now();
    let started = Instant::now();
    let (owner, setup) = Owner::generate(geometry)?;
    let generate_ms = ms(started);
    let started = Instant::now();
    let counts = setup.byte_counts()?;
    let wire = setup.to_bytes()?;
    let owner_secret = owner.secret_key_serialized_bytes();
    let public_wire = wire.len();
    drop(setup);
    let serialize_ms = ms(started);
    let started = Instant::now();
    let restored = PublicSetup::from_bytes(&wire)?;
    let setup_decode_ms = ms(started);
    let started = Instant::now();
    let peer = PeerEvaluator::from_public_setup(&restored)?;
    let peer_restore_ms = ms(started);
    drop(restored);
    drop(wire);
    let setup_ms = ms(cold);
    let expected_public = if geometry == Geometry::Rows16 {
        8_930_306
    } else {
        13_395_426
    };
    assert_eq!(public_wire, expected_public);
    assert_eq!(owner_secret, 8195);
    println!(
        "{}",
        json!({"kind":"profile_setup","label":args[0],"rows":geometry.slots(),
        "generate_ms":generate_ms,"serialize_and_count_ms":serialize_ms,
        "public_setup_decode_ms":setup_decode_ms,"peer_key_restore_ms":peer_restore_ms,
        "complete_setup_ms":setup_ms,"public_setup_bytes":public_wire,
        "public_setup_components":counts,"owner_secret_byte_count":owner_secret,
        "profile":owner.profile(),"native_memory":memory::guard(0)?,
        "proof_available":false,"network_measured":false})
    );
    // Explicitly public, non-secret fixture. No plaintext enters PeerEvaluator.
    let fields: Vec<_> = (0..geometry.slots())
        .map(|i| SelectedField {
            age: [17, 18, 42, 255][i % 4],
            amount: [0, 255, 256, 65535][i % 4],
            active: true,
        })
        .collect();
    for sample in 0..3 {
        let started = Instant::now();
        let context = QueryContext::new([sample as u8 + 1; 16], [2; 112], [3; 112]);
        let prepared = owner.prepare(context, &fields, Predicate::AtLeast(18))?;
        let request_bytes = prepared.request.len();
        let answer = peer.evaluate(&prepared.request)?;
        let output_bytes = answer.output.len();
        let actual = owner.decrypt_unverified(prepared.pending, &answer.output)?;
        let query_ms = ms(started);
        let cold_first = if sample == 0 { Some(ms(cold)) } else { None };
        let expected = fields
            .iter()
            .filter(|row| row.age >= 18)
            .fold((0u32, 0u32), |(count, sum), row| {
                (count + 1, sum + u32::from(row.amount))
            });
        assert_eq!((actual.count, actual.sum), expected);
        assert_eq!(actual.proof, ProofStatus::Unavailable);
        println!(
            "{}",
            json!({"kind":"profile_query","label":args[0],"rows":geometry.slots(),
            "sample":sample,"whole_query_ms":query_ms,"setup_and_first_query_ms":cold_first,
            "request_bytes":request_bytes,"response_bytes":output_bytes,"actual":actual,
            "exact":true,"native_memory":memory::guard(0)?})
        );
    }
    Ok(())
}
