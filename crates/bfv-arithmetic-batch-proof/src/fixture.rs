//! Deterministic PUBLIC NONSECRET ciphertext-residue arithmetic for owning tests.
use crate::{Context, Error, RelationRequest, instance_binding, statement};
use bfv_scale_circuit as scale;
use bfv_tensor_circuit as tensor;

pub fn context() -> Context {
    Context {
        query: [0x61; 32],
        setup: [0x62; 32],
    }
}
pub fn requests(context: Context) -> Result<Vec<RelationRequest>, Error> {
    build(context, false)
}
fn build(context: Context, zero: bool) -> Result<Vec<RelationRequest>, Error> {
    let mut out = Vec::with_capacity(crate::RELATIONS);
    for index in 0..crate::RELATIONS {
        let binding = instance_binding(context, index)?;
        match statement::role(index).unwrap() {
            (2, b) => {
                let basis = tensor::Basis::new(b).unwrap();
                let input = (0..4)
                    .flat_map(|component| {
                        (0..8192).map(move |i| value(basis.modulus(), index, component, i, zero))
                    })
                    .collect::<Vec<_>>();
                out.push(RelationRequest::Tensor(
                    tensor::decode_request(
                        &tensor::encode_request(basis, binding, &input)
                            .map_err(|_| Error::Statement)?,
                    )
                    .map_err(|_| Error::Statement)?,
                ));
            }
            (tag, _) => {
                let role = if tag == 1 {
                    scale::Role::Extend5To10
                } else {
                    scale::Role::Scale10To5
                };
                let input = role
                    .input_moduli()
                    .iter()
                    .enumerate()
                    .flat_map(|(lane, &p)| (0..8192).map(move |i| value(p, index, lane, i, zero)))
                    .collect::<Vec<_>>();
                out.push(RelationRequest::Scale(
                    scale::decode_request(
                        &scale::encode_request(role, binding, &input)
                            .map_err(|_| Error::Statement)?,
                    )
                    .map_err(|_| Error::Statement)?,
                ));
            }
        }
    }
    Ok(out)
}
fn value(p: u64, index: usize, lane: usize, i: usize, zero: bool) -> u64 {
    if zero {
        return 0;
    }
    match (i + index) % 8 {
        0 => 0,
        1 => 1,
        2 => p - 1,
        3 => p / 2,
        4 => p / 2 + 1,
        5 => p - 2,
        _ => {
            ((i as u128 * 0x9e3779b97f4a7c15u128 + (lane + index * 11) as u128 * 0x100000001b3u128)
                % u128::from(p)) as u64
        }
    }
}
