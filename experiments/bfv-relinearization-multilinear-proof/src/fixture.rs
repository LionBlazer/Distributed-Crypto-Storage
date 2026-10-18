//! PUBLIC NONSECRET arithmetic vectors. These arbitrary key-like vectors are not
//! imported evaluation keys or evidence of ciphertext/key source or same-secret authority.
use bfv_relinearization_circuit::{DEGREE, Request, Role, decode_request, encode_request};
use bfv_relinearization_multilinear_proof::Error;
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

/// Valid zero statement without evaluating embedding/MAC, quotients or carries.
/// The numerical security path still builds and commits actual public tables.
pub(crate) fn zero_statement(
    role: Role,
) -> Result<
    (
        Request,
        bfv_relinearization_circuit::Output,
        bfv_relinearization_circuit::Aux,
    ),
    Error,
> {
    use bfv_relinearization_circuit::{decode_aux, decode_output};
    use sha2::{Digest, Sha256};
    let r = decode_request(
        &encode_request(role, [0; 32], [0; 32], &vec![0; role.input_coefficients()])
            .map_err(|_| Error::Statement)?,
    )
    .map_err(|_| Error::Statement)?;
    let mut out = r.encode()[..112].to_vec();
    out[..8].copy_from_slice(b"BFVRELR1");
    out.extend(Sha256::digest(r.encode()));
    out.resize(role.output_bytes(), 0);
    let mut aux = r.encode()[..112].to_vec();
    aux[..8].copy_from_slice(b"BFVRELC1");
    aux[105] = 3;
    aux.extend(Sha256::digest(r.encode()));
    aux.extend(Sha256::digest(&out));
    match role {
        Role::Embed => aux.resize(role.aux_bytes(), 0),
        Role::AccumulateAndAdd => {
            for _ in 0..DEGREE {
                aux.extend([0; 60]);
                for _ in 0..50 {
                    aux.extend((1u32 << 24).to_le_bytes());
                }
            }
        }
    }
    Ok((
        r,
        decode_output(&out).map_err(|_| Error::Statement)?,
        decode_aux(&aux).map_err(|_| Error::Statement)?,
    ))
}
