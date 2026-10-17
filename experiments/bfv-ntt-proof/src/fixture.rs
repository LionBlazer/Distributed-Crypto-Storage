//! Deterministic PUBLIC NONSECRET coefficients, never rows or key material.
use crate::Error;
use bfv_ntt_circuit::{Basis, Direction, Request, decode_request, encode_request};
pub fn request(direction: Direction, basis: Basis, binding: [u8; 32]) -> Result<Request, Error> {
    let p = basis.modulus();
    let input = (0..8192)
        .map(|i| match i % 8 {
            0 => 0,
            1 => 1,
            2 => p - 1,
            3 => p / 2,
            4 => p / 2 + 1,
            5 => p - 2,
            _ => {
                ((i as u128 * 0x9e3779b97f4a7c15u128 + basis.index() as u128 * 0x100000001b3u128)
                    % u128::from(p)) as u64
            }
        })
        .collect::<Vec<_>>();
    let encoded =
        encode_request(direction, basis, binding, &input).map_err(|_| Error::Statement)?;
    decode_request(&encoded).map_err(|_| Error::Statement)
}
