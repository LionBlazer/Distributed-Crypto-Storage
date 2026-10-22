//! Distinct Word transport contract; no old message/profile/deadline changes.
use super::owner::{PendingSnapshot, Snapshot};
use super::{
    invalid,
    wire::{HEADER, MAX_CONTROL},
};
use sha2::{Digest, Sha256};
use std::{io, time::Duration};
pub(super) const GET_PENDING: u8 = 10;
pub(super) const PENDING_BYTES: usize = 105;
pub const IO_BUDGET: Duration = Duration::from_secs(180);
pub const OPERATION_BUDGET: Duration = Duration::from_secs(1800);
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dcs/Word-finality/TLS-actor/v3/DCSWFN03");
    h.update(registry200_finality::word::profile_digest());
    h.update(b"owner-Body-authorized-inline-Word/one-native-owner/no-blob/no-Predicate-no-SQL");
    h.update(b"pending105-is-availability-only/fetch-exact-body/full-owner-native-recheck-before-local-pending/no-replacement-of-local-intent");
    h.update(b"idle-slot-waits-for-owner-native-admission-or-authenticated-current-context-input/sticky-first-handler-start-counts-verification/resume-durable-actions-or-advanced-round-step/unchanged-active-token-budgets");
    for n in [
        super::MAX_COMMANDS,
        super::MAX_CONNECTIONS,
        super::MAX_PEERS,
        super::MAX_QUEUED_BYTES,
        MAX_CONTROL,
        version_journal::MAX_BODY_BYTES,
        PENDING_BYTES,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.update(IO_BUDGET.as_secs().to_le_bytes());
    h.update(OPERATION_BUDGET.as_secs().to_le_bytes());
    h.finalize().into()
}
pub(super) fn encode(binding: [u8; 32], tag: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > MAX_CONTROL - HEADER {
        return Err(invalid());
    }
    let mut b = Vec::with_capacity(HEADER + data.len());
    b.extend_from_slice(b"DCSWFN03");
    b.extend_from_slice(&profile_digest());
    b.extend_from_slice(&binding);
    b.push(tag);
    b.extend_from_slice(data);
    Ok(b)
}
pub(super) fn decode(binding: [u8; 32], b: &[u8]) -> io::Result<(u8, &[u8])> {
    if !(HEADER..=MAX_CONTROL).contains(&b.len())
        || &b[..8] != b"DCSWFN03"
        || b[8..40] != profile_digest()
        || b[40..72] != binding
    {
        return Err(invalid());
    }
    Ok((b[72], &b[HEADER..]))
}
pub(super) fn encode_pending(p: PendingSnapshot) -> [u8; PENDING_BYTES] {
    let mut out = [0; PENDING_BYTES];
    out[..8].copy_from_slice(&p.current.slot.to_le_bytes());
    out[8..40].copy_from_slice(&p.current.context);
    out[40..72].copy_from_slice(&p.current.parent);
    if let Some(id) = p.candidate {
        out[72] = 1;
        out[73..].copy_from_slice(&id);
    }
    out
}
pub(super) fn decode_pending(b: &[u8]) -> io::Result<PendingSnapshot> {
    if b.len() != PENDING_BYTES || b[72] > 1 || b[72] == 0 && b[73..] != [0; 32] {
        return Err(invalid());
    }
    let slot = u64::from_le_bytes(b[..8].try_into().map_err(|_| invalid())?);
    if slot == 0 {
        return Err(invalid());
    }
    Ok(PendingSnapshot {
        current: Snapshot {
            slot,
            context: b[8..40].try_into().map_err(|_| invalid())?,
            parent: b[40..72].try_into().map_err(|_| invalid())?,
        },
        candidate: (b[72] == 1).then(|| b[73..].try_into().expect("fixed advertised id")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn word_namespace_and_binding_cannot_decode_as_original_joint_or_foreign_control() {
        let binding = [7; 32];
        let tag = super::super::joint_wire::GET_BLOB;
        let bytes = encode(binding, tag, b"public metadata").unwrap();
        assert_eq!(
            decode(binding, &bytes).unwrap(),
            (tag, &b"public metadata"[..])
        );
        assert!(super::super::wire::decode(binding, &bytes).is_err());
        let original = super::super::wire::encode(binding, 0, &[]).unwrap();
        assert!(decode(binding, &original).is_err());
        let joint = super::super::joint_wire::encode(binding, 0, &[]).unwrap();
        assert!(decode(binding, &joint).is_err());
        assert!(super::super::joint_wire::decode(binding, &bytes).is_err());
        let progress = super::super::progress_wire::encode(binding, 0, &[]).unwrap();
        assert!(decode(binding, &progress).is_err());
        assert!(super::super::progress_wire::decode(binding, &bytes).is_err());
        for magic in [b"DCSWFN01", b"DCSWFN02"] {
            let mut retired = bytes.clone();
            retired[..8].copy_from_slice(magic);
            assert!(decode(binding, &retired).is_err());
        }
        assert!(decode([8; 32], &bytes).is_err());
        for at in [0, 7, 8, 39, 40, 71] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(decode(binding, &bad).is_err());
        }
        assert!(decode(binding, &bytes[..HEADER - 1]).is_err());
        assert!(encode(binding, 0, &vec![0; MAX_CONTROL - HEADER + 1]).is_err());
        assert_eq!(super::super::RPC_BUDGET.as_secs(), 180);
        assert_eq!(OPERATION_BUDGET.as_secs(), 1800);
    }
    #[test]
    fn availability_hint_is_canonical_and_cannot_cross_context_or_parent() {
        let current = Snapshot {
            slot: 2,
            context: [3; 32],
            parent: [4; 32],
        };
        for candidate in [None, Some([5; 32])] {
            let bytes = encode_pending(PendingSnapshot { current, candidate });
            let decoded = decode_pending(&bytes).unwrap();
            assert_eq!(decoded.candidate_at(current), candidate);
            for changed in [
                Snapshot { slot: 3, ..current },
                Snapshot {
                    context: [8; 32],
                    ..current
                },
                Snapshot {
                    parent: [9; 32],
                    ..current
                },
            ] {
                assert_eq!(decoded.candidate_at(changed), None);
            }
            assert!(decode_pending(&bytes[..104]).is_err());
            let mut bad = bytes;
            bad[72] = 2;
            assert!(decode_pending(&bad).is_err());
        }
        let mut noncanonical = encode_pending(PendingSnapshot {
            current,
            candidate: Some([5; 32]),
        });
        noncanonical[72] = 0;
        assert!(decode_pending(&noncanonical).is_err());
    }
}
