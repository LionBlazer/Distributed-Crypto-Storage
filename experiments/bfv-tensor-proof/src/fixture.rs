//! Deterministic PUBLIC NONSECRET ciphertext-derived residue examples, not owner rows.
use crate::Error;
use bfv_tensor_circuit::{Basis, DEGREE, Request, decode_request, encode_request};
pub fn request(basis: Basis, binding: [u8; 32]) -> Result<Request, Error> {
    let p = basis.modulus();
    let mut input = Vec::with_capacity(4 * DEGREE);
    for component in 0usize..4 {
        input.extend((0..DEGREE).map(|i| {
            if i == DEGREE - 1 {
                return p - 1;
            }
            match (i + component * 3) % 9 {
                0 => 0,
                1 => 1,
                2 => p - 1,
                3 => p / 2,
                4 => p / 2 + 1,
                5 => p - 2,
                _ => {
                    ((i as u128 * 0x9e3779b97f4a7c15u128
                        + component as u128 * 0x100000001b3u128
                        + basis.index() as u128 * 0xd6e8feb86659fd93u128)
                        % u128::from(p)) as u64
                }
            }
        }));
    }
    let bytes = encode_request(basis, binding, &input).map_err(|_| Error::Statement)?;
    decode_request(&bytes).map_err(|_| Error::Statement)
}
