//! Test-only rebuilding of coherent false mathematical claims; never an admission API.
use super::Statement;
use crate::backend::Val;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use registry200_proof::coefficient_encoding::{N, Role, air::EncodingAir, commitment, layout::*};
pub(super) fn bits(out: &mut [Val], v: u64) {
    for (i, x) in out.iter_mut().enumerate() {
        *x = Val::from_u64((v >> i) & 1);
    }
}
/// Rebuilt-test helper uses explicit caller-owned W; it cannot authorize a false trace.
pub(super) fn refresh(s: &Statement, trace: &mut RowMajorMatrix<Val>, words: &[u64]) -> [Val; 4] {
    assert_eq!(words.len(), N);
    let air = EncodingAir::new(s);
    let role = s.expected.role();
    let width = role.width();
    let context = s.expected.encoding_context();
    let salt = if role == Role::SourceAllOriginal {
        SOURCE_ENC_SALT
    } else {
        QUERY_ENC_SALT
    };
    let mut open = [Val::ZERO; 12];
    let mut vector = [Val::ZERO; 12];
    let mut carry = [Val::ZERO; 8];
    let mut root = [Val::ZERO; 4];
    for (r, row) in trace.values.chunks_exact_mut(width).enumerate() {
        row[OPEN_CP..OPEN_CP + 12].copy_from_slice(&open);
        let w = core::array::from_fn(|l| Val::from_u64(words[16 * r + l]));
        let enc_salt = row[salt..salt + 4].try_into().unwrap();
        let (result, digest) =
            commitment::write_vector(row, r, context, enc_salt, w, vector, carry);
        vector = result;
        carry = w[8..].try_into().unwrap();
        if r == 511 {
            root = digest;
        }
        row[3 * P2..4 * P2].fill(Val::ZERO);
        if r < (if role == Role::SourceAllOriginal {
            85
        } else {
            6
        }) {
            let mut input = [Val::ZERO; 12];
            for (word, v) in input[..8].iter_mut().enumerate() {
                *v = air.opening_field::<Val, _>(row, 8 * r + word, word);
            }
            input[8..].copy_from_slice(&open[8..]);
            open = bfv_hiding_stark::poseidon::write(&mut row[3 * P2..4 * P2], input);
        }
    }
    root
}
