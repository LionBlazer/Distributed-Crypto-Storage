//! Distinct fixed tensor profile; no old multiplication profile is widened.
use crate::{Basis, DEGREE, INPUT_POLYNOMIALS, OUTPUT_POLYNOMIALS};
use sha2::{Digest, Sha256};
pub fn profile_digest(basis: Basis) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-TENSOR-CIRCUIT/v1/fhe0.1.1/NTT-native/full8192");
    h.update([basis.index()]);
    h.update(basis.modulus().to_le_bytes());
    h.update((DEGREE as u64).to_le_bytes());
    h.update([INPUT_POLYNOMIALS as u8, OUTPUT_POLYNOMIALS as u8]);
    h.update(b"input=a0,a1,b0,b1;output=d0=a0b0,d1=a0b1+a1b0,d2=a1b1;all-component-major;canonical-u64LE;quotients64/k0,k2<p/k1<2p;publicAux108B=3k8+3x7d4;d25+2^24;base16/8digits/zero-endpoint-carries;header80/output112/aux144;representation-nativeNTT2;PP61/zero-main/PV32");
    h.finalize().into()
}
