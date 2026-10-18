//! CLI-owned public shape fixtures for analytical reports, never query results.
use sha2::{Digest, Sha256};

pub(super) fn ntt(
    direction: bfv_ntt_circuit::Direction,
    basis: bfv_ntt_circuit::Basis,
) -> Result<(bfv_ntt_circuit::Request, bfv_ntt_circuit::Output), bfv_ntt_witness_proof::Error> {
    use bfv_ntt_circuit::{DEGREE, Direction, decode_output, decode_request, encode_request};
    use bfv_ntt_witness_proof::Error;
    let input = decode_request(
        &encode_request(direction, basis, [0; 32], &vec![0; DEGREE])
            .map_err(|_| Error::Statement)?,
    )
    .map_err(|_| Error::Statement)?;
    let mut bytes = input.encode()[..80].to_vec();
    bytes[..8].copy_from_slice(b"BFVNTTR1");
    bytes[74] = if direction == Direction::Forward {
        2
    } else {
        1
    };
    bytes.extend(Sha256::digest(input.encode()));
    bytes.resize(112 + 8 * DEGREE, 0);
    Ok((input, decode_output(&bytes).map_err(|_| Error::Statement)?))
}

pub(super) fn relinearization(
    role: bfv_relinearization_circuit::Role,
) -> Result<
    (
        bfv_relinearization_circuit::Request,
        bfv_relinearization_circuit::Output,
        bfv_relinearization_circuit::Aux,
    ),
    bfv_relinearization_multilinear_proof::Error,
> {
    use bfv_relinearization_circuit::{
        DEGREE, Role, decode_aux, decode_output, decode_request, encode_request,
    };
    use bfv_relinearization_multilinear_proof::Error;
    let input = decode_request(
        &encode_request(role, [0; 32], [0; 32], &vec![0; role.input_coefficients()])
            .map_err(|_| Error::Statement)?,
    )
    .map_err(|_| Error::Statement)?;
    let mut out = input.encode()[..112].to_vec();
    out[..8].copy_from_slice(b"BFVRELR1");
    out.extend(Sha256::digest(input.encode()));
    out.resize(role.output_bytes(), 0);
    let mut aux = input.encode()[..112].to_vec();
    aux[..8].copy_from_slice(b"BFVRELC1");
    aux[105] = 3;
    aux.extend(Sha256::digest(input.encode()));
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
        input,
        decode_output(&out).map_err(|_| Error::Statement)?,
        decode_aux(&aux).map_err(|_| Error::Statement)?,
    ))
}
