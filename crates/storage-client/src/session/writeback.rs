//! Freeze public placement/geometry before computation; preflight every ciphertext upload.
//! This module owns transport and durable placement, never SQL proof or authorization policy.
use super::*;
use compact_query::bfv::UpdatePatch;
use peer_runtime::{
    PageAddress, PageImage, RawBundle, StoreDeltaPlan, StoreDeltaRequest, TargetVersion,
};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Full,
    Delta,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UpdateSourceKind {
    Full,
    Static,
}
/// Actual complete images or the genuine core's immutable partial proposal.
/// A partial index is never represented as a Table or EncryptedSnapshot.
pub(super) enum StagedImages {
    Full {
        table: Table,
        replacements: Option<Vec<PageAddress>>,
    },
    Update(UpdatePatch),
}
impl StagedImages {
    pub fn heads(&self) -> HeadPair {
        let (data, index) = match self {
            Self::Full { table, .. } => (table.commitment(), table.index_commitment()),
            Self::Update(patch) => (patch.heads().data(), patch.heads().index()),
        };
        HeadPair {
            data: data.encode(),
            index: index.encode(),
        }
    }
}
struct Recipient {
    peer: Participant,
    transport: Transport,
}
struct FrozenShard {
    shard: u64,
    object: [u8; 32],
    data: Commitment,
    index: Commitment,
    recipients: Vec<Recipient>,
}
impl FrozenShard {
    fn source_kind(&self) -> UpdateSourceKind {
        if !self.recipients.is_empty()
            && self
                .recipients
                .iter()
                .all(|recipient| recipient.transport == Transport::Delta)
        {
            UpdateSourceKind::Static
        } else {
            UpdateSourceKind::Full
        }
    }
}
pub(super) struct Writeback {
    shards: Vec<Option<FrozenShard>>,
    copies: usize,
}
pub(super) struct PreparedWrite {
    slot: usize,
    shard: u64,
    target: TargetVersion,
    full: Option<RawBundle>,
    delta: Option<StoreDeltaRequest>,
    recipients: Vec<Recipient>,
    copies: usize,
}

impl Writeback {
    /// Called before proof jobs: known holders and source class come only from
    /// committed placement and public geometry, never fetch responses or errors.
    pub fn freeze(session: &Session, update: bool) -> Result<Self> {
        validate_recipient_bindings(
            session
                .participants
                .iter()
                .chain(
                    session
                        .data
                        .shards
                        .iter()
                        .flat_map(|shard| shard.peers.iter()),
                )
                .map(|peer| (peer.id, peer.remote.endpoint())),
        )?;
        let shards = session
            .data
            .shards
            .iter()
            .map(|shard| {
                let plan = StoreDeltaPlan::for_heads(&shard.info.data_head, &shard.info.index_head)
                    .map_err(protocol)?;
                let known_transport = if update && plan.padded_request_bytes().is_some() {
                    Transport::Delta
                } else {
                    Transport::Full
                };
                let mut recipients: Vec<_> = shard
                    .peers
                    .iter()
                    .cloned()
                    .map(|peer| Recipient {
                        peer,
                        transport: known_transport,
                    })
                    .collect();
                for peer in &session.participants {
                    if !recipients
                        .iter()
                        .any(|candidate| candidate.peer.id == peer.id)
                    {
                        recipients.push(Recipient {
                            peer: peer.clone(),
                            transport: Transport::Full,
                        });
                    }
                }
                Ok(Some(FrozenShard {
                    shard: shard.info.id,
                    object: shard.info.object,
                    data: shard.info.data_head.clone(),
                    index: shard.info.index_head.clone(),
                    recipients,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            shards,
            copies: 2.min(session.participants.len()),
        })
    }

    pub fn source_kind(&self, slot: usize) -> Result<UpdateSourceKind> {
        self.shards
            .get(slot)
            .and_then(Option::as_ref)
            .map(FrozenShard::source_kind)
            .ok_or_else(|| protocol("Missing frozen UPDATE source class"))
    }

    /// Consumes actual staged ciphertext only after all FHE jobs pass. Every
    /// candidate frame and immutable journal budget passes before any Store.
    pub fn prepare(&mut self, slot: usize, images: StagedImages) -> Result<PreparedWrite> {
        let source = self
            .shards
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or_else(|| protocol("Missing frozen writeback placement"))?;
        let needs_delta = source
            .recipients
            .iter()
            .any(|peer| peer.transport == Transport::Delta);
        let (target, full, pages) = match images {
            StagedImages::Full {
                table,
                replacements,
            } => {
                // Exactly one fresh nonce; all full and delta candidates share it.
                let full = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index())
                    .map_err(protocol)?;
                let target = full.target_version().map_err(protocol)?;
                let pages = if needs_delta {
                    let addresses = replacements
                        .ok_or_else(|| protocol("Missing proved UPDATE page addresses"))?;
                    check_replacement_count(addresses.len())?;
                    Some(
                        addresses
                            .into_iter()
                            .map(|address| {
                                let page = match address.image {
                                    PageImage::Data => table
                                        .snapshot()
                                        .lookup(address.index, Limits::default())
                                        .map_err(protocol)?,
                                    PageImage::Index => table.lookup_index_page(address.index)?,
                                };
                                Ok((address, page))
                            })
                            .collect::<Result<Vec<_>>>()?,
                    )
                } else {
                    None
                };
                (target, Some(full), pages)
            }
            StagedImages::Update(patch) => {
                // No response/error is allowed to upgrade this class to Full.
                if source.source_kind() != UpdateSourceKind::Static {
                    return Err(protocol(
                        "A frozen Full recipient requires complete staged images",
                    ));
                }
                let count = patch
                    .replaced_data_pages()
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| protocol("UPDATE page replacement budget exceeded"))?;
                check_replacement_count(count)?;
                let mut nonce = [0; 32];
                getrandom::getrandom(&mut nonce).map_err(protocol)?;
                let target = TargetVersion::new(
                    nonce,
                    patch.heads().data().clone(),
                    patch.heads().index().clone(),
                )
                .map_err(protocol)?;
                let mut pages = patch
                    .replaced_data_pages()
                    .iter()
                    .map(|&index| {
                        Ok((
                            PageAddress {
                                image: PageImage::Data,
                                index,
                            },
                            patch
                                .data()
                                .lookup(index, Limits::default())
                                .map_err(protocol)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let (index, header) = patch.index_replacement();
                pages.push((
                    PageAddress {
                        image: PageImage::Index,
                        index,
                    },
                    header.clone(),
                ));
                (target, None, Some(pages))
            }
        };
        // This public geometry check also covers INSERT's changed full frame.
        StoreDeltaPlan::for_heads(target.data_head(), target.index_head()).map_err(protocol)?;
        let delta = if needs_delta {
            let pages = pages.ok_or_else(|| protocol("Missing proved UPDATE pages"))?;
            Some(
                StoreDeltaRequest::new(source.object, &source.data, &source.index, &target, &pages)
                    .map_err(protocol)?,
            )
        } else {
            None
        };
        if source
            .recipients
            .iter()
            .any(|peer| peer.transport == Transport::Full)
            && full.is_none()
        {
            return Err(protocol("Missing preflighted full ciphertext"));
        }
        Ok(PreparedWrite {
            slot,
            shard: source.shard,
            target,
            full,
            delta,
            recipients: source.recipients,
            copies: self.copies,
        })
    }
}
impl PreparedWrite {
    pub fn store(self, unavailable: &BTreeSet<u64>) -> Result<StoredMutation> {
        let mut holders = Vec::new();
        for recipient in self.recipients {
            if unavailable.contains(&recipient.peer.id) {
                continue;
            }
            let request = match recipient.transport {
                Transport::Full => Request::Store(
                    self.full
                        .as_ref()
                        .ok_or_else(|| protocol("Missing preflighted full ciphertext"))?
                        .clone(),
                ),
                Transport::Delta => Request::StoreDelta(
                    self.delta
                        .as_ref()
                        .ok_or_else(|| protocol("Missing preflighted UPDATE delta"))?
                        .clone(),
                ),
            };
            // A failed known-holder delta never changes this recipient to Full.
            if matches!(recipient.peer.remote.call(request), Ok(Response::Stored(ref info)) if &info.id == self.target.object())
            {
                holders.push(recipient.peer);
            }
            if holders.len() >= self.copies {
                break;
            }
        }
        if holders.is_empty() {
            return Err(Error::UnavailableShard(self.shard));
        }
        Ok(StoredMutation {
            slot: self.slot,
            object: *self.target.object(),
            heads: HeadPair {
                data: self.target.data_head().encode(),
                index: self.target.index_head().encode(),
            },
            holders,
        })
    }
}

fn check_replacement_count(count: usize) -> Result<()> {
    if count == 0 || count > peer_runtime::MAX_STORE_DELTA_PAGES {
        return Err(protocol("UPDATE page replacement budget exceeded"));
    }
    Ok(())
}

// Participant IDs are routing labels, not authenticated recipient identities.
// Ambiguous aliases fail before proof work, so they cannot become new-Full
// recipients or count the same credential/address as two stored copies.
fn validate_recipient_bindings<'a>(
    recipients: impl IntoIterator<Item = (u64, &'a peer_runtime::Endpoint)>,
) -> Result<()> {
    let mut ids = std::collections::BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for (id, endpoint) in recipients {
        if let Some(previous) = ids.insert(id, endpoint) {
            if previous != endpoint {
                return Err(Error::InvalidInput(
                    "A participant ID has conflicting authenticated endpoints".into(),
                ));
            }
            continue;
        }
        if !identities.insert(endpoint.identity) || !addresses.insert(endpoint.address) {
            return Err(Error::InvalidInput(
                "Distinct participant IDs must use distinct TLS identities and socket addresses"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(address: &str, identity: u8) -> peer_runtime::Endpoint {
        peer_runtime::Endpoint {
            address: address.parse().unwrap(),
            identity: [identity; 32],
        }
    }
    #[test]
    fn aliases_of_one_credential_or_address_cannot_become_distinct_write_recipients() {
        let original = endpoint("127.0.0.1:2001", 1);
        let moved = endpoint("127.0.0.1:2002", 1);
        let repinned = endpoint("127.0.0.1:2001", 2);
        let independent = endpoint("127.0.0.1:2002", 2);
        assert!(validate_recipient_bindings([(1, &original), (2, &independent)]).is_ok());
        // The same committed holder may legitimately occur in several shards.
        assert!(validate_recipient_bindings([(1, &original), (1, &original)]).is_ok());
        for alias in [&original, &moved, &repinned] {
            assert!(validate_recipient_bindings([(1, &original), (3, alias)]).is_err());
        }
        assert!(validate_recipient_bindings([(1, &original), (1, &independent)]).is_err());
    }
}
