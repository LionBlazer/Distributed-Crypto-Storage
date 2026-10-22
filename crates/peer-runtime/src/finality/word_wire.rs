//! Distinct Word transport contract; no old message/profile/deadline changes.
use super::{
    invalid,
    wire::{HEADER, MAX_CONTROL},
};
use sha2::{Digest, Sha256};
use std::{io, time::Duration};
pub const IO_BUDGET: Duration = Duration::from_secs(180);
pub const OPERATION_BUDGET: Duration = Duration::from_secs(1800);
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dcs/Word-finality/TLS-actor/v1/DCSWFN01");
    h.update(registry200_finality::word::profile_digest());
    h.update(b"owner-Body-authorized-inline-Word/one-native-owner/no-blob/no-Predicate-no-SQL");
    for n in [
        super::MAX_COMMANDS,
        super::MAX_CONNECTIONS,
        super::MAX_PEERS,
        super::MAX_QUEUED_BYTES,
        MAX_CONTROL,
        version_journal::MAX_BODY_BYTES,
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
    b.extend_from_slice(b"DCSWFN01");
    b.extend_from_slice(&profile_digest());
    b.extend_from_slice(&binding);
    b.push(tag);
    b.extend_from_slice(data);
    Ok(b)
}
pub(super) fn decode(binding: [u8; 32], b: &[u8]) -> io::Result<(u8, &[u8])> {
    if !(HEADER..=MAX_CONTROL).contains(&b.len())
        || &b[..8] != b"DCSWFN01"
        || b[8..40] != profile_digest()
        || b[40..72] != binding
    {
        return Err(invalid());
    }
    Ok((b[72], &b[HEADER..]))
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
}
