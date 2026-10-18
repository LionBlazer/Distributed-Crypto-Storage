//! Deterministic PUBLIC NONSECRET ciphertext-residue arithmetic, never SQL answers.
use bfv_arithmetic_batch_proof::{
    Context, Error, Expected, RELATIONS, RelationOutput, RelationRequest, instance_binding,
};
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
    let mut out = Vec::with_capacity(RELATIONS);
    for index in 0..RELATIONS {
        let binding = instance_binding(context, index)?;
        match role(index) {
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
fn role(index: usize) -> (u8, u8) {
    match index {
        0..=3 => (1, 255),
        4..=13 => (2, (index - 4) as u8),
        14..=16 => (3, 255),
        _ => unreachable!("fixed seventeen-position fixture"),
    }
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
pub(crate) fn zero_statement(context: Context) -> Result<Expected, Error> {
    let requests = build(context, true)?;
    let outputs = requests
        .iter()
        .map(|r| match r {
            RelationRequest::Scale(r) => {
                let mut b = Vec::new();
                b.extend(b"BFVSCLR1");
                b.extend(scale::profile_digest(r.role()));
                b.extend(r.binding());
                b.extend([r.role() as u8, 1, 0, 0, 0, 0, 0, 0]);
                b.extend(sha256(&r.encode()));
                b.resize(r.role().output_bytes(), 0);
                scale::decode_output(&b)
                    .map(RelationOutput::Scale)
                    .map_err(|_| Error::Statement)
            }
            RelationRequest::Tensor(r) => {
                let mut b = Vec::new();
                b.extend(b"BFVTENR1");
                b.extend(tensor::profile_digest(r.basis()));
                b.extend(r.binding());
                b.extend([r.basis().index(), 2, 4, 3, 0, 0, 0, 0]);
                b.extend(sha256(&r.encode()));
                b.resize(r.basis().output_bytes(), 0);
                tensor::decode_output(&b)
                    .map(RelationOutput::Tensor)
                    .map_err(|_| Error::Statement)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Expected::new(context, requests, outputs)
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
