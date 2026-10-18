//! PUBLIC NONSECRET full native-order vectors, not Source data or a query answer.
use crate::{Context, Error, Expected, instance_binding};
use bfv_ntt_circuit::{
    DEGREE, Direction, Output, Request, decode_output, decode_request, encode_request,
    multistark::BatchSpec,
};
use sha2::{Digest, Sha256};
pub fn context() -> Context {
    Context {
        query: [0x51; 32],
        setup: [0x52; 32],
    }
}
pub fn specs(count: usize) -> Vec<BatchSpec> {
    (0..count)
        .map(|i| BatchSpec {
            direction: if i % 2 == 0 {
                Direction::Forward
            } else {
                Direction::Inverse
            },
            basis: bfv_ntt_circuit::Basis::new((i % 10) as u8).unwrap(),
        })
        .collect()
}
pub fn requests(context: Context, specs: &[BatchSpec]) -> Result<Vec<Request>, Error> {
    if !matches!(specs.len(), 2 | 4 | 8) {
        return Err(Error::Statement);
    }
    specs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let p = s.basis.modulus();
            let values = (0..DEGREE)
                .map(|j| {
                    if j == DEGREE - 1 {
                        p - 1
                    } else {
                        ((j as u128 * 0x9e3779b97f4a7c15u128 + i as u128 * 139 + 17)
                            % u128::from(p)) as u64
                    }
                })
                .collect::<Vec<_>>();
            decode_request(
                &encode_request(
                    s.direction,
                    s.basis,
                    instance_binding(context, i, s.direction, s.basis),
                    &values,
                )
                .map_err(|_| Error::Statement)?,
            )
            .map_err(|_| Error::Statement)
        })
        .collect()
}
pub(crate) fn output(request: &Request, values: &[u64]) -> Result<Output, Error> {
    let mut bytes = request.encode()[..80].to_vec();
    bytes[..8].copy_from_slice(b"BFVNTTR1");
    bytes[74] = if request.direction() == Direction::Forward {
        2
    } else {
        1
    };
    bytes.extend(Sha256::digest(request.encode()));
    for v in values {
        bytes.extend(v.to_le_bytes());
    }
    decode_output(&bytes).map_err(|_| Error::Statement)
}
pub(crate) fn zero_statement(context: Context, specs: &[BatchSpec]) -> Result<Expected, Error> {
    if !matches!(specs.len(), 2 | 4 | 8) {
        return Err(Error::Statement);
    }
    let mut requests = Vec::new();
    let mut outputs = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        let r = decode_request(
            &encode_request(
                s.direction,
                s.basis,
                instance_binding(context, i, s.direction, s.basis),
                &vec![0; DEGREE],
            )
            .map_err(|_| Error::Statement)?,
        )
        .map_err(|_| Error::Statement)?;
        outputs.push(output(&r, &vec![0; DEGREE])?);
        requests.push(r);
    }
    Expected::new(context, requests, outputs)
}
