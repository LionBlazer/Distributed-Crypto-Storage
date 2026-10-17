//! Distinct role profiles, fixed level0/0 and exact public source/target order.
use crate::{DEGREE, EMBEDDING_QUOTIENT_BOUNDS, MODULI, Role};
use sha2::{Digest, Sha256};
pub fn profile_digest(role: Role) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-RELINEARIZATION-ARITHMETIC/v1/fhe0.1.1/level0-0/log_base0");
    h.update([role as u8]);
    h.update((DEGREE as u64).to_le_bytes());
    for p in MODULI {
        h.update(p.to_le_bytes());
    }
    for row in EMBEDDING_QUOTIENT_BOUNDS {
        h.update(row);
    }
    h.update(b"header112/output144/aux176;request-binding32/keyset-context32-byte-identity-not-authority;full8192/component-major;Embed-input-ri/output-source-i-target-j/r=E+qj*t/scalar-residual46;Accumulate-target-j-17=original0,original1,D0..4,K00..04,K10..14/output-target-j-component-c;orig+sum5D*K=out+q*k;three16bitlimbs/sixdigits/5carry25+2^24/zero-endpoints;k<5q/u48LE;PP55/365;PV32/mandatory-zero-main");
    h.finalize().into()
}
