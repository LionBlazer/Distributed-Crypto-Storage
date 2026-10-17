//! PUBLIC NONSECRET actual proof-wire examples; no production admission token.
use super::*;
use crate::primitive::PublicStatement;
use p3_field::PrimeCharacteristicRing;
use std::sync::OnceLock;
struct PublicProof {
    expected: Expected,
    statement: Statement,
    bytes: Vec<u8>,
}
fn actual_public_bundle() -> &'static PublicProof {
    static ACTUAL: OnceLock<PublicProof> = OnceLock::new();
    ACTUAL.get_or_init(|| {
        let (expected, source_witness, witness) = fixture().unwrap();
        let (statement, proof) = prove(&expected, &source_witness, &witness).unwrap();
        let bytes = encode(&expected, &statement, &proof).unwrap();
        let decoded = verify(&expected, &bytes).unwrap();
        assert_eq!(decoded.public_values(), statement.public_values());
        PublicProof {
            expected,
            statement,
            bytes,
        }
    })
}
#[test]
fn genuine_registry_bootstrap_pair_retains_every_actual_sdk_byte_after_fresh_decode() {
    let f = actual_public_bundle();
    let checked = verify(&f.expected, &f.bytes).unwrap();
    assert_eq!(checked.public_values(), f.statement.public_values());
    let frame = Frame::parse(Role::Bootstrap, &f.bytes).unwrap();
    let (source, child) = proof_wire::decode_pair(
        &frame,
        &Shape::new(&f.expected.source).unwrap(),
        &Shape::new(&f.statement).unwrap(),
    )
    .unwrap();
    assert_eq!(postcard::to_allocvec(&source).unwrap(), frame.source);
    assert_eq!(postcard::to_allocvec(&child).unwrap(), frame.child);
    let mut proof = CompositeProof {
        source: Some(source),
        bootstrap: child,
    };
    assert_eq!(encode(&f.expected, &f.statement, &proof).unwrap(), f.bytes);
    proof.source = None;
    assert!(encode(&f.expected, &f.statement, &proof).is_err());
    println!(
        "actual registry_bootstrap wire: source={} child={} bundle={}",
        frame.source.len(),
        frame.child.len(),
        f.bytes.len()
    );
    assert!(f.bytes.len() <= proof_wire::MAX_BUNDLE_BYTES);
}
#[test]
fn registry_bootstrap_wire_rejects_wrong_expected_context_outputs_and_genuine_foreign_pair() {
    let f = actual_public_bundle();
    for case in 0..8 {
        let mut wrong = f.expected.clone();
        match case {
            0 => wrong.genesis[31] ^= 1,
            1 => wrong.parent[31] ^= 1,
            2 => wrong.source.request[31] ^= 1,
            3 => wrong.source.heads[1][111] ^= 1,
            4 => wrong.source.key_commitment[0] += crate::backend::Val::ONE,
            5 => wrong.source.open_commitment[0] += crate::backend::Val::ONE,
            6 => wrong.source.packets[1][33] ^= 1,
            7 => wrong.enrollment[0] += crate::backend::Val::ONE,
            _ => unreachable!(),
        }
        assert!(
            verify(&wrong, &f.bytes).is_err(),
            "wrong Expected case {case}"
        );
    }
    let mut changed = f.bytes.clone();
    changed[88] ^= 1;
    assert!(verify(&f.expected, &changed).is_err());
    let mut nonfield = f.bytes.clone();
    nonfield[88..96].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(verify(&f.expected, &nonfield).is_err());
    let altered = proof_wire::tests::alter_child(
        Role::Bootstrap,
        &f.bytes,
        &Shape::new(&f.statement).unwrap(),
        |p| {
            p.opening_proof.1.final_poly[0] += crate::backend::Challenge::ONE;
        },
    );
    assert!(verify(&f.expected, &altered).is_err());
    // The foreign pair must first verify under its own independently constructed
    // public fixture. Its child is then spliced after the original REAL Source.
    let (other, sw, w) = fixture().unwrap();
    let (statement, proof) = prove(&other, &sw, &w).unwrap();
    let foreign = encode(&other, &statement, &proof).unwrap();
    assert!(verify(&other, &foreign).is_ok());
    assert!(verify(&f.expected, &foreign).is_err());
    let splice = proof_wire::tests::foreign_child(Role::Bootstrap, &f.bytes, &foreign);
    assert!(verify(&f.expected, &splice).is_err());
}
#[test]
fn registry_bootstrap_wire_rejects_receipts_and_all_malformed_sdk_container_families() {
    let f = actual_public_bundle();
    proof_wire::tests::check_rejections(
        Role::Bootstrap,
        &Shape::new(&f.expected.source).unwrap(),
        &Shape::new(&f.statement).unwrap(),
        &f.bytes,
        |bytes| {
            assert!(verify(&f.expected, bytes).is_err());
        },
    );
}

#[test]
fn registry_bootstrap_wire_rejects_same_shape_corruption_at_every_sdk_proof_layer() {
    let f = actual_public_bundle();
    proof_wire::tests::check_crypto_rejections(
        Role::Bootstrap,
        &f.bytes,
        &Shape::new(&f.statement).unwrap(),
        |bytes| {
            assert!(verify(&f.expected, bytes).is_err());
        },
    );
}
