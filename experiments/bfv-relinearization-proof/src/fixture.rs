//! PUBLIC NONSECRET arithmetic vectors. These arbitrary key-like vectors are not
//! imported evaluation keys or evidence of ciphertext/key source or same-secret authority.
use crate::Error;
use bfv_relinearization_circuit::{DEGREE, Request, Role, decode_request, encode_request};
pub fn request(role: Role, binding: [u8; 32], keyset_context: [u8; 32]) -> Result<Request, Error> {
    let mut input = Vec::with_capacity(role.input_coefficients());
    for (poly, &p) in role.input_moduli().iter().enumerate() {
        input.extend((0..DEGREE).map(|i| {
            if i == DEGREE - 1 {
                return p - 1;
            }
            match (i + poly * 3) % 9 {
                0 => 0,
                1 => 1,
                2 => p - 1,
                3 => p / 2,
                4 => p / 2 + 1,
                5 => p - 2,
                _ => {
                    ((i as u128 * 0x9e3779b97f4a7c15u128 + poly as u128 * 0x100000001b3u128)
                        % u128::from(p)) as u64
                }
            }
        }));
    }
    let wire =
        encode_request(role, binding, keyset_context, &input).map_err(|_| Error::Statement)?;
    decode_request(&wire).map_err(|_| Error::Statement)
}
