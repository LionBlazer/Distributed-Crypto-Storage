use super::{MAX_COMMANDS, MAX_CONNECTIONS, MAX_PEERS, MAX_QUEUED_BYTES, RPC_BUDGET, invalid};
use sha2::{Digest, Sha256};
use std::io;
pub(super) const HEADER: usize = 8 + 32 + 32 + 1;
pub(super) const MAX_CONTROL: usize = HEADER + work_finality::consensus::MAX_INPUT_BYTES;
pub(super) const STATUS: u8 = 0;
pub(super) const INPUT: u8 = 1;
pub(super) const GET_BLOCK: u8 = 2;
pub(super) const PUT_BLOCK: u8 = 3;
pub(super) const GET_CHECKPOINT: u8 = 4;
pub(super) const CHECKPOINT: u8 = 5;
pub(super) const SUBMIT: u8 = 6;
pub(super) const OK: u8 = 16;
pub(super) const BUSY: u8 = 17;
pub(super) const REJECT: u8 = 18;
pub(super) const NEED_BLOCK: u8 = 19;
pub(super) const BLOCK: u8 = 20;
pub(super) const RECORD: u8 = 21;
pub(super) const NONE: u8 = 22;

pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dcs/registry200-finality/TLS-actor/v1");
    h.update(registry200_finality::export_profile_digest());
    h.update(
        b"DCSRFN01/profile32/binding32/tag8/exact-EOF/body-separate-frame/no-remote-timer/no-SQL",
    );
    for n in [
        MAX_COMMANDS,
        MAX_CONNECTIONS,
        MAX_PEERS,
        MAX_QUEUED_BYTES,
        MAX_CONTROL,
        registry200_finality::MAX_BLOCK_BYTES,
        registry200_finality::MAX_CHECKPOINT_BYTES,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.update(RPC_BUDGET.as_secs().to_le_bytes());
    h.finalize().into()
}
pub(super) fn encode(binding: [u8; 32], tag: u8, data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > MAX_CONTROL - HEADER {
        return Err(invalid());
    }
    let mut b = Vec::with_capacity(HEADER + data.len());
    b.extend_from_slice(b"DCSRFN01");
    b.extend_from_slice(&profile_digest());
    b.extend_from_slice(&binding);
    b.push(tag);
    b.extend_from_slice(data);
    Ok(b)
}
pub(super) fn decode(binding: [u8; 32], bytes: &[u8]) -> io::Result<(u8, &[u8])> {
    if !(HEADER..=MAX_CONTROL).contains(&bytes.len())
        || &bytes[..8] != b"DCSRFN01"
        || bytes[8..40] != profile_digest()
        || bytes[40..72] != binding
    {
        return Err(invalid());
    }
    Ok((bytes[72], &bytes[HEADER..]))
}
pub(super) fn word(bytes: &[u8]) -> io::Result<u64> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| invalid())?))
}
pub(super) fn hash(bytes: &[u8]) -> io::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| invalid())
}
