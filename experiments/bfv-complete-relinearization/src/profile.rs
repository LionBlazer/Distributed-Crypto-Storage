//! Composition identity and exact ordering over unchanged primitive proof profiles.
use crate::{DEGREE, Input, MODULI, PreparedKey};
use bfv_ntt_circuit::{Basis, Direction};
use bfv_relinearization_circuit::Role;
use sha2::{Digest, Sha512};

pub fn profile_digest() -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/COMPLETE-RELIN/v1/profile/nativeNTT3-to-nativeNTT2/seeded-level0-0-logbase0/");
    h.update(b"public-key-preprocessing=original-full-setup/seeded-key-source/PB-c0-pure-fixedNTT/seeded-c1;no-query-key-NTT-proofs;32-order=5inverseC2,Embed,25forwardDigits-source-major,MAC;MAC-target-major17;output-transpose2j+c-to5c+j;exact-all8192-edges;no-SQL/no-sameSK/no-finality/no-composed128-claim");
    for q in MODULI {
        h.update(q.to_le_bytes());
    }
    for n in [
        DEGREE,
        crate::COMPONENTS,
        crate::HEADER_BYTES,
        crate::MAX_COMPONENT_BYTES,
        crate::MAX_STREAM_BYTES,
        crate::MAX_ATTEMPTS,
        bfv_relinearization_key_source::MAX_KEY_BYTES,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    for direction in [Direction::Inverse, Direction::Forward] {
        for basis in 0..5 {
            h.update(bfv_ntt_witness_proof::profile_digest(
                direction,
                Basis::new(basis).expect("fixed Q5 basis"),
            ));
        }
    }
    for role in [Role::Embed, Role::AccumulateAndAdd] {
        h.update(bfv_relinearization_multilinear_proof::profile_digest(role));
    }
    h.finalize().into()
}
pub(crate) fn identity(key: &PreparedKey, input: &Input) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/COMPLETE-RELIN/v1/independent-Expected/");
    h.update(profile_digest());
    h.update(key.keyset_id());
    h.update(key.original_setup_digest());
    h.update(input.query());
    h.update(input.digest());
    h.finalize().into()
}
pub(crate) fn stage_binding(identity: [u8; 64], metadata: [u8; 4]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"DCS/COMPLETE-RELIN/v1/unchanged-primitive-binding32/");
    h.update(identity);
    h.update(metadata);
    let digest = h.finalize();
    digest[..32].try_into().expect("fixed digest prefix")
}
