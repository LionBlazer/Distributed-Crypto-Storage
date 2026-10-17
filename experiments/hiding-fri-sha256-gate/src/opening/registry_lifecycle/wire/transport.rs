//! PUBLIC NONSECRET Body transport example, not a Request200 codec or Journal adapter.
use super::{Error, Expected, frame, verify};
use ed25519_dalek::{Signature, SigningKey};
use version_journal::{AuthorizedTransition, Body, HeadPair, ProtocolProfile, ShardUpdate, Target};
pub(super) fn owner() -> SigningKey {
    SigningKey::from_bytes(&[0x67; 32])
}
pub(super) fn profile() -> ProtocolProfile {
    ProtocolProfile {
        initial_target: Target([255; 32]),
        pow_limit: Target([255; 32]),
        block_spacing_secs: 10,
        retarget_interval: 100,
        max_future_secs: 60,
        confirmation_depth: 1,
        max_headers: 128,
        max_shards: 1,
        max_updates: 1,
        max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
        max_request_bytes: frame::MAX_REQUEST_BYTES as u32,
        max_proof_bytes: frame::MAX_BUNDLE_BYTES as u32,
        max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
    }
}
pub(super) fn transition(
    e: &Expected,
    bytes: &[u8],
    request_len: usize,
) -> Result<AuthorizedTransition, Error> {
    frame::body_length(request_len, bytes.len())?;
    // Opaque public transport bytes only: no parser maps this request to Expected.
    let mut request = vec![0x35; request_len];
    if request_len >= 40 {
        request[..8].copy_from_slice(b"DCSLFT01");
        request[8..40].copy_from_slice(&e.source.request);
    }
    let mut transition = AuthorizedTransition {
        parent: e.parent,
        request,
        updates: vec![ShardUpdate {
            id: 7,
            old: HeadPair {
                data: [0x31; 112],
                index: [0x32; 112],
            },
            new: HeadPair {
                data: [0x41; 112],
                index: [0x42; 112],
            },
        }],
        proof: bytes.to_vec(),
        owner_signature: [0; 64],
    };
    transition.sign(e.genesis, &owner());
    Ok(transition)
}
pub(super) fn authorization(e: &Expected, transition: &AuthorizedTransition) -> Result<(), Error> {
    owner()
        .verifying_key()
        .verify_strict(
            &transition.signing_message(e.genesis),
            &Signature::from_bytes(&transition.owner_signature),
        )
        .map_err(|_| Error::Verification)
}
pub(super) fn roundtrip(e: &Expected, frame: &[u8], request: usize) -> Result<usize, Error> {
    let expected = frame::body_length(request, frame.len())?;
    let profile = profile();
    let bytes = {
        let transition = transition(e, frame, request)?;
        authorization(e, &transition)?;
        Body::Transition(transition)
            .encode(&profile)
            .map_err(|_| Error::Encoding)?
    };
    if bytes.len() != expected {
        return Err(Error::Shape);
    }
    let decoded = Body::decode(&bytes, &profile).map_err(|_| Error::Encoding)?;
    if decoded.encode(&profile).map_err(|_| Error::Encoding)? != bytes {
        return Err(Error::Encoding);
    }
    drop(bytes);
    let Body::Transition(decoded) = decoded else {
        return Err(Error::Shape);
    };
    // Body::decode validates structure, not signatures or computation.
    authorization(e, &decoded)?;
    verify(e, &decoded.proof)?;
    Ok(expected)
}
