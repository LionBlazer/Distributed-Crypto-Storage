//! Deterministic PUBLIC NONSECRET coefficients. Not a database or query answer.
use bfv_ntt_circuit::{
    Basis, DEGREE, Direction, Output, Request, decode_output, decode_request, encode_request,
};
use bfv_ntt_witness_proof::Error;
use sha2::{Digest, Sha256};
pub fn request(direction: Direction, basis: Basis, binding: [u8; 32]) -> Result<Request, Error> {
    let p = basis.modulus();
    let input: Vec<_> = (0..DEGREE)
        .map(|i| {
            if i == DEGREE - 1 {
                p - 1
            } else {
                match i % 8 {
                    0 => 0,
                    1 => 1,
                    2 => p - 1,
                    3 => p / 2,
                    4 => p / 2 + 1,
                    5 => p - 2,
                    _ => {
                        ((i as u128 * 0x9e3779b97f4a7c15u128
                            + basis.index() as u128 * 0x100000001b3u128)
                            % u128::from(p)) as u64
                    }
                }
            }
        })
        .collect();
    decode_request(
        &encode_request(direction, basis, binding, &input).map_err(|_| Error::Statement)?,
    )
    .map_err(|_| Error::Statement)
}
/// Rebuild a canonical public output using the actual library wire decoder.
/// This does not claim the supplied output is mathematically correct.
pub(crate) fn output(input: &Request, coefficients: &[u64]) -> Result<Output, Error> {
    let mut bytes = input.encode()[..80].to_vec();
    bytes[..8].copy_from_slice(b"BFVNTTR1");
    bytes[74] = if input.direction() == Direction::Forward {
        2
    } else {
        1
    };
    bytes.extend(Sha256::digest(input.encode()));
    for &v in coefficients {
        bytes.extend(v.to_le_bytes());
    }
    decode_output(&bytes).map_err(|_| Error::Statement)
}
/// Shape-only valid zero pair: no NTT, quotient, carry, or main trace generation.
pub(crate) fn zero_statement(
    direction: Direction,
    basis: Basis,
) -> Result<(Request, Output), Error> {
    let input = decode_request(
        &encode_request(direction, basis, [0; 32], &vec![0; DEGREE])
            .map_err(|_| Error::Statement)?,
    )
    .map_err(|_| Error::Statement)?;
    let out = output(&input, &vec![0; DEGREE])?;
    Ok((input, out))
}
