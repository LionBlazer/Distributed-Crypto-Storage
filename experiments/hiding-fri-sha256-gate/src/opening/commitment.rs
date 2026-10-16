//! Fixed domain/length encodings only; never a variable-length commitment API.
use super::{
    KEY_DOMAIN, OPEN_DOMAIN, VERSION,
    statement::{Statement, words},
};
use crate::backend::{Val, profile_digest};
use crate::primitive::Kind;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_symmetric::Permutation;
pub(super) fn key_fields(head: &[u8; 112], key: [u8; 32], salt: [Val; 4]) -> Vec<Val> {
    words(&KEY_DOMAIN)
        .chain([Val::from_u32(VERSION), Val::from_u8(32)])
        .chain(words(&head[8..40]))
        .chain(words(&key))
        .chain(salt)
        .chain([Val::ZERO; 6])
        .collect()
}
pub(super) fn prefix(statement: &Statement, salt: [Val; 4]) -> Vec<Val> {
    let out: Vec<_> = words(&OPEN_DOMAIN)
        .chain([
            Val::from_u32(VERSION),
            Val::from_u8(12),
            Val::from_u16(2336),
        ])
        .chain(words(&profile_digest(Kind::PairOpening)))
        .chain(words(&statement.request))
        .chain(statement.heads.iter().flat_map(|h| words(h)))
        .chain(statement.key_commitment)
        .chain(salt)
        .collect();
    assert_eq!(out.len(), 87);
    out
}
pub(super) fn opening_fields(statement: &Statement, salt: [Val; 4], plain: &[u8]) -> Vec<Val> {
    assert_eq!(plain.len(), 2348);
    let mut out = prefix(statement, salt);
    out.extend(words(plain));
    out.extend([Val::ZERO; 6]);
    assert_eq!(out.len(), 680);
    out
}
pub(super) fn digest(fields: &[Val]) -> [Val; 4] {
    assert!(matches!(fields.len(), 32 | 680));
    let perm = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        perm.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
