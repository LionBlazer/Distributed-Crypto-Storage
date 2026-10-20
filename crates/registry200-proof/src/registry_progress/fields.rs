//! Exact new fixed preimages; no network, state installation or verification.
use super::{
    BootstrapExpected,
    circuit::{ProgressOpening, State, StatementOpening, Status, Step},
};
use crate::{
    BackendError as Error, Val,
    lifecycle::{circuit::commitment, statement as life},
    source::statement as source,
};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use zeroize::Zeroizing;
pub(super) const REGISTRY_DOMAIN: [u8; 16] = *b"DCS/PREG208/v1!!";
pub(super) const STATEMENT_DOMAIN: [u8; 16] = *b"DCS/PSTMT96/v1!!";
pub(super) const PROGRESS_DOMAIN: [u8; 16] = *b"DCS/PPROG48/v1!!";
pub(super) const RESULT_DOMAIN: [u8; 16] = *b"DCS/PRES160/v1!!";
fn header(domain: &[u8; 16], profile: [u8; 32]) -> Vec<Val> {
    source::words(domain)
        .chain([Val::ONE])
        .chain(source::words(&profile))
        .collect()
}
fn limbs(v: u64) -> [Val; 2] {
    [Val::from_u32(v as u32), Val::from_u32((v >> 32) as u32)]
}
fn vals(v: [u64; 4]) -> [Val; 4] {
    v.map(Val::from_u64)
}
pub(super) fn digest(fields: &[Val]) -> [Val; 4] {
    assert!(matches!(fields.len(), 48 | 96 | 160 | 208));
    let mut state = [Val::ZERO; 12];
    let p = p3_goldilocks::default_goldilocks_poseidon2_12();
    for b in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(b);
        p.permute_mut(&mut state);
    }
    state[..4].try_into().unwrap()
}
pub(super) fn registry_prefix(e: &BootstrapExpected) -> Vec<Val> {
    let mut out = life::stable_prefix(&e.legacy(), false);
    out[..4].copy_from_slice(&source::words(&REGISTRY_DOMAIN).collect::<Vec<_>>());
    out[4] = Val::ONE;
    out[5..13]
        .copy_from_slice(&source::words(&super::registry_profile_digest()).collect::<Vec<_>>());
    out
}
pub(super) fn registry(
    e: &BootstrapExpected,
    plain: &[u8; 2348],
    controllers: &[[u8; 32]; 2],
    state: &State,
    salt: [Val; 4],
) -> Result<Vec<Val>, Error> {
    state.require_canonical()?;
    let table: Zeroizing<[u8; 32]> = Zeroizing::new(plain[124..156].try_into().unwrap());
    let ids: Zeroizing<[[u8; 32]; 4]> = Zeroizing::new(core::array::from_fn(|i| {
        plain[2220 + 32 * i..2252 + 32 * i].try_into().unwrap()
    }));
    let mut out = commitment::registry_fields_opening(
        &e.legacy(),
        &table,
        &ids,
        controllers,
        &state.registry,
        salt,
    );
    out.truncate(194);
    out[..33].copy_from_slice(&registry_prefix(e));
    for p in &state.progress {
        if let Some(p) = p {
            out.push(Val::ONE);
            out.extend(p.root()?);
        } else {
            out.extend([Val::ZERO; 5]);
        }
    }
    out.extend([Val::ZERO; 4]);
    assert_eq!(out.len(), 208);
    Ok(out)
}
pub(super) fn statement(s: &StatementOpening) -> Vec<Val> {
    let mut out = header(&STATEMENT_DOMAIN, super::statement_profile_digest());
    out.extend(source::words(&s.scope));
    out.extend(vals(s.enrollment));
    out.extend(source::words(&s.client));
    out.extend(limbs(s.call));
    out.extend(limbs(s.transaction));
    out.push(Val::from_u8(s.principal));
    out.extend(source::words(&s.controller));
    out.extend(source::words(&s.invocation));
    out.extend(source::words(&s.sql_identity));
    out.extend(source::words(&s.snapshot));
    out.extend(source::words(&s.mask));
    out.extend([s.mode, s.wait, s.offset, s.limit, s.projection].map(Val::from_u8));
    out.extend(vals(s.salt));
    out.push(Val::ZERO);
    assert_eq!(out.len(), 96);
    out
}
pub(super) fn progress(p: &ProgressOpening) -> Result<Vec<Val>, Error> {
    let mut out = header(&PROGRESS_DOMAIN, super::progress_profile_digest());
    out.extend(p.statement.root()?);
    out.extend(limbs(p.statement.transaction));
    out.push(Val::from_u8(p.statement.principal));
    out.extend(limbs(p.statement.call));
    out.extend(limbs(p.microstep));
    out.push(Val::from_u8(p.cursor));
    out.extend(p.visited.map(Val::from_bool));
    out.extend(p.selected.map(Val::from_bool));
    out.push(Val::ONE);
    out.push(Val::from_u8(p.cursor));
    out.extend(limbs(p.holder));
    out.push(Val::from_u8(p.holder_mode));
    out.extend(limbs(p.blocked_revision));
    out.extend(vals(p.salt));
    out.extend([Val::ZERO; 4]);
    assert_eq!(out.len(), 48);
    Ok(out)
}
/// Explicit owner mathematics for Result160. Only the separate genuine
/// transition proof can establish this relation; this hash grants no SQL authority.
pub(super) fn result(
    context: &[Val; 100],
    roots: [[Val; 4]; 3],
    statement: &StatementOpening,
    step: &Step,
    progress_roots: [[Val; 4]; 2],
    salt: [Val; 4],
) -> Vec<Val> {
    let mut out = source::words(&RESULT_DOMAIN)
        .chain([Val::ONE])
        .chain(context.iter().copied())
        .chain(roots.into_iter().flatten())
        .collect::<Vec<_>>();
    out.push(Val::from_bool(step.resumed));
    out.push(Val::from_u8(match step.status {
        Status::Parked => 0,
        Status::Done => 1,
        Status::Error => 2,
    }));
    out.extend(limbs(statement.transaction));
    out.extend([step.old_cursor, step.cursor].map(Val::from_u8));
    out.extend(step.visited.map(Val::from_bool));
    out.extend(step.selected.map(Val::from_bool));
    out.extend(step.block.map(Val::from_bool));
    out.extend(progress_roots.into_iter().flatten());
    out.extend(limbs(step.holder));
    out.push(Val::from_u8(step.holder_mode));
    out.extend(limbs(statement.call));
    out.extend(limbs(step.microstep));
    out.extend(salt);
    out.extend([Val::ZERO; 6]);
    assert_eq!(out.len(), 160);
    out
}
