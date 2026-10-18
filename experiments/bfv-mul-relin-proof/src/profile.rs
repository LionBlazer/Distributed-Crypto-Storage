use crate::{
    DEGREE, MAX_ATTEMPTS, MAX_CLAIMS_BYTES, MAX_PROOF_BYTES, MAX_SESSION_BYTES, NODES,
    PROOF_RECORDS, RECORD_HEADER,
};
use sha2::{Digest, Sha512};
pub fn profile_digest() -> [u8; 64] {
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
            h.update(bfv_ntt_witness_proof::backend::profile_digest(
                direction,
                bfv_ntt_circuit::Basis::new(b).unwrap(),
            ));
        }
    }
    h.update(bfv_arithmetic_batch_proof::backend::profile(
        bfv_arithmetic_batch_proof::Context {
            query: [1; 32],
            setup: [2; 32],
        },
    ));
    for role in [
        bfv_relinearization_circuit::Role::Embed,
        bfv_relinearization_circuit::Role::AccumulateAndAdd,
    ] {
        h.update(bfv_relinearization_multilinear_proof::backend::profile_digest(role));
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
