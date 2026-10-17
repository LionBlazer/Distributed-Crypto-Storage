//! Internal native-equivalent width12 gadget, not a new public primitive API.
use crate::Val;
use p3_air::AirBuilder;
use p3_field::Algebra;
use p3_goldilocks::{
    GOLDILOCKS_POSEIDON2_RC_12_EXTERNAL_FINAL as FINAL,
    GOLDILOCKS_POSEIDON2_RC_12_EXTERNAL_INITIAL as INITIAL,
    GOLDILOCKS_POSEIDON2_RC_12_INTERNAL as INTERNAL,
    GenericPoseidon2LinearLayersGoldilocks as Linear,
};
use p3_poseidon2::GenericPoseidon2LinearLayers;
pub const WIDTH: usize = 12 + 2 * (8 * 12 + 22);

fn walk<E: Algebra<Val>>(mut state: [E; 12], mut sbox: impl FnMut(E) -> E) -> [E; 12] {
    <Linear as GenericPoseidon2LinearLayers<12>>::external_linear_layer(&mut state);
    for round in INITIAL {
        for (word, constant) in state.iter_mut().zip(round) {
            *word = sbox(word.clone() + constant);
        }
        <Linear as GenericPoseidon2LinearLayers<12>>::external_linear_layer(&mut state);
    }
    for constant in INTERNAL {
        state[0] = sbox(state[0].clone() + constant);
        <Linear as GenericPoseidon2LinearLayers<12>>::internal_linear_layer(&mut state);
    }
    for round in FINAL {
        for (word, constant) in state.iter_mut().zip(round) {
            *word = sbox(word.clone() + constant);
        }
        <Linear as GenericPoseidon2LinearLayers<12>>::external_linear_layer(&mut state);
    }
    state
}
pub fn write(row: &mut [Val], input: [Val; 12]) -> [Val; 12] {
    assert_eq!(row.len(), WIDTH);
    row[..12].copy_from_slice(&input);
    let mut offset = 12;
    let result = walk(input, |x| {
        let cube = x * x * x;
        let output = x * cube * cube;
        row[offset] = cube;
        row[offset + 1] = output;
        offset += 2;
        output
    });
    assert_eq!(offset, WIDTH);
    result
}
pub fn evaluate<AB: AirBuilder<F = Val>>(builder: &mut AB, row: &[AB::Var]) -> [AB::Expr; 12] {
    assert_eq!(row.len(), WIDTH);
    let mut offset = 12;
    let result = walk(core::array::from_fn(|i| row[i].into()), |x: AB::Expr| {
        let cube: AB::Expr = row[offset].into();
        let output: AB::Expr = row[offset + 1].into();
        builder.assert_eq(cube.clone(), x.clone() * x.clone() * x.clone());
        builder.assert_eq(output.clone(), x * cube.clone() * cube);
        offset += 2;
        output
    });
    assert_eq!(offset, WIDTH);
    result
}
