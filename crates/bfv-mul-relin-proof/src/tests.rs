//! Composition-specific atomic proof grouping and resource policy.
use crate::*;
#[test]
fn published_full_proof_profile_is_preserved_when_pure_routing_moves_to_core() {
    // Full profile64 from the independently retained pre-extraction public claim
    // header. This pins the accepted proof/wire policy, not a computed result.
    assert_eq!(
        profile_digest(),
        [
            0x20, 0xcc, 0xad, 0x0e, 0x98, 0xd2, 0x73, 0x15, 0x8d, 0x4b, 0xa4, 0xab, 0x6f, 0x31,
            0x4c, 0x5d, 0xed, 0x88, 0x54, 0xf1, 0x17, 0x87, 0xb0, 0x13, 0x5f, 0xac, 0xf6, 0x55,
            0x48, 0xa9, 0xac, 0x4a, 0xd6, 0xbd, 0xac, 0x08, 0x08, 0xe7, 0x30, 0x4e, 0x97, 0x10,
            0xe7, 0x5e, 0x39, 0x6a, 0xec, 0xa2, 0xdb, 0x7a, 0x28, 0x21, 0xf1, 0x2c, 0x66, 0x54,
            0x05, 0x5e, 0x63, 0xf0, 0xba, 0x6a, 0x1a, 0xeb,
        ],
    );
}
#[test]
fn proof_obligations_cover_all_nodes_once_with_one_atomic_arithmetic_block() {
    let mut covered = graph::arithmetic_indices();
    assert_eq!(verifier::packet_node(0), Some(NODES));
    for packet in 1..PROOF_RECORDS {
        covered.push(verifier::packet_node(packet).unwrap());
    }
    covered.sort_unstable();
    assert_eq!(covered, (0..NODES).collect::<Vec<_>>());
    assert_eq!(verifier::packet_node(PROOF_RECORDS), None);
    assert_eq!(MAX_ATTEMPTS, 240);
    const {
        assert!(MAX_SESSION_BYTES > provenance::MAX_INPUT_BYTES + MAX_CLAIMS_BYTES);
    }
}
