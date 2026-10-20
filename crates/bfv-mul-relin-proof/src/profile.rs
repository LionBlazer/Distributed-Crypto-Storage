use crate::{
    DEGREE, MAX_ATTEMPTS, MAX_CLAIMS_BYTES, MAX_PROOF_BYTES, MAX_SESSION_BYTES, NODES,
    PROOF_RECORDS, RECORD_HEADER,
};
use sha2::{Digest, Sha512};
use std::sync::OnceLock;

/// Process-constant public protocol identity, not a cached verification result.
pub fn profile_digest() -> [u8; 64] {
    static PROFILE: OnceLock<[u8; 64]> = OnceLock::new();
    *PROFILE.get_or_init(compute_profile_digest)
}

fn compute_profile_digest() -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/BFV-MUL-RELIN/v1/134-fixed-nodes/native2-PBc2/direct-Embed/exact-PB-wire/");
    h.update(b"raw-claims-before-derived-bindings;initial20inverse,Extend4,Pforward20,Tensor10,QP-inverse30,Down3,Qforward10,Embed,digitsForward25,MAC,finalInverse10;original-pinned-q-setup-CTs-fullEncodingPV;Source-first-input16;no-SQL/no-freshness/no-public-RK-same-secret/no-whole128-claim");
    h.update(b"claims-then-inputs-then-arithmetic-then-ascending-other-nodes;failed-attempts-charge;cancel-and-lifetime-exhaustion-terminal");
    for n in [
        DEGREE,
        NODES,
        MAX_CLAIMS_BYTES,
        PROOF_RECORDS,
        RECORD_HEADER,
        MAX_PROOF_BYTES,
        MAX_ATTEMPTS,
        MAX_SESSION_BYTES,
        crate::provenance::MAX_INPUT_BYTES,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    for direction in [
        bfv_ntt_circuit::Direction::Forward,
        bfv_ntt_circuit::Direction::Inverse,
    ] {
        for b in 0..10 {
            h.update(bfv_ntt_witness_proof::profile_digest(
                direction,
                bfv_ntt_circuit::Basis::new(b).unwrap(),
            ));
        }
    }
    h.update(bfv_arithmetic_batch_proof::profile_digest(
        bfv_arithmetic_batch_proof::Context {
            query: [1; 32],
            setup: [2; 32],
        },
    ));
    for role in [
        bfv_relinearization_circuit::Role::Embed,
        bfv_relinearization_circuit::Role::AccumulateAndAdd,
    ] {
        h.update(bfv_relinearization_multilinear_proof::profile_digest(role));
    }
    h.finalize().into()
}
pub(crate) fn binding(identity: [u8; 64], node: usize) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"DCS/BFV-MUL-RELIN/v1/node-binding/");
    h.update(identity);
    h.update((node as u64).to_le_bytes());
    h.finalize()[..32].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::{compute_profile_digest, profile_digest};
    use std::{sync::mpsc, time::Duration};

    // Independent pre-extraction public-claim header, also pinned by the
    // unchanged owning test in crate::tests. Never derive this from the cache.
    const PUBLISHED: [u8; 64] = [
        0x20, 0xcc, 0xad, 0x0e, 0x98, 0xd2, 0x73, 0x15, 0x8d, 0x4b, 0xa4, 0xab, 0x6f, 0x31, 0x4c,
        0x5d, 0xed, 0x88, 0x54, 0xf1, 0x17, 0x87, 0xb0, 0x13, 0x5f, 0xac, 0xf6, 0x55, 0x48, 0xa9,
        0xac, 0x4a, 0xd6, 0xbd, 0xac, 0x08, 0x08, 0xe7, 0x30, 0x4e, 0x97, 0x10, 0xe7, 0x5e, 0x39,
        0x6a, 0xec, 0xa2, 0xdb, 0x7a, 0x28, 0x21, 0xf1, 0x2c, 0x66, 0x54, 0x05, 0x5e, 0x63, 0xf0,
        0xba, 0x6a, 0x1a, 0xeb,
    ];

    /// Run this case alone with --exact to exercise concurrent process-cold calls.
    #[test]
    fn concurrent_callers_retain_the_published_and_uncached_graph_identity() {
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let callers: Vec<_> = (0..8)
                .map(|_| {
                    let (start_tx, start_rx) = mpsc::sync_channel(1);
                    let ready = ready_tx.clone();
                    let caller = scope.spawn(move || {
                        ready
                            .send(())
                            .expect("profile caller could not announce readiness");
                        start_rx
                            .recv_timeout(Duration::from_secs(30))
                            .expect("profile caller was not released");
                        profile_digest()
                    });
                    (start_tx, caller)
                })
                .collect();
            for _ in 0..8 {
                ready_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("profile callers did not become ready");
            }
            for (start, _) in &callers {
                start
                    .send(())
                    .expect("profile caller stopped before release");
            }
            for (_, caller) in callers {
                assert_eq!(caller.join().expect("profile caller panicked"), PUBLISHED);
            }
        });
        assert_eq!(compute_profile_digest(), PUBLISHED);
        for _ in 0..16 {
            assert_eq!(profile_digest(), PUBLISHED);
        }
    }

    /// Finite identity-hashing observation only; never SQL or proof latency.
    #[test]
    #[ignore = "Opt-in graph-profile hashing observation; no performance assertion"]
    fn observe_uncached_and_warm_cached_profile_hashing() {
        use std::{hint::black_box, time::Instant};
        assert_eq!(profile_digest(), PUBLISHED);
        let started = Instant::now();
        for _ in 0..16 {
            assert_eq!(black_box(compute_profile_digest()), PUBLISHED);
        }
        let uncached_ms = started.elapsed().as_secs_f64() * 1000.;
        let started = Instant::now();
        for _ in 0..65_536 {
            assert_eq!(black_box(profile_digest()), PUBLISHED);
        }
        let cached_ms = started.elapsed().as_secs_f64() * 1000.;
        println!(
            "graph_profile_hashing_only uncached_calls=16 uncached_ms={uncached_ms:.4} warm_cached_calls=65536 warm_cached_ms={cached_ms:.4} proof_verification=false sql_latency=false"
        );
    }
}
