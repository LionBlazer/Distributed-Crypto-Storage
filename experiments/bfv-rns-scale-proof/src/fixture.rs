//! Deterministic PUBLIC NONSECRET residues, not SQL rows or secret-key material.
use crate::Error;
use bfv_scale_circuit::{Request, Role, decode_request, encode_request};

pub fn request(role: Role, binding: [u8; 32]) -> Result<Request, Error> {
    // The odd-modulus half patterns are the CRT representatives floor(M/2)
    // and ceil(M/2); together with 0, 1, M-1 and M-2 they exercise both signs.
    let values = role
        .input_moduli()
        .iter()
        .enumerate()
        .flat_map(|(lane, &q)| {
            (0..8192).map(move |coefficient| match coefficient % 8 {
                0 => 0,
                1 => 1,
                2 => q - 1,
                3 => q / 2,
                4 => q / 2 + 1,
                5 => q - 2,
                _ => {
                    ((coefficient as u128 * 0x9e3779b97f4a7c15u128
                        + lane as u128 * 0x100000001b3u128)
                        % u128::from(q)) as u64
                }
            })
        })
        .collect::<Vec<_>>();
    let wire = encode_request(role, binding, &values).map_err(|_| Error::Statement)?;
    decode_request(&wire).map_err(|_| Error::Statement)
}
