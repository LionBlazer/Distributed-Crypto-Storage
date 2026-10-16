//! Freeze public placement/geometry before computation; preflight every ciphertext upload.
//! This module owns transport and durable placement, never SQL proof or authorization policy.
use super::*;
use peer_runtime::{PageAddress, PageImage, StoreDeltaPlan, StoreDeltaRequest};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Full,
    Delta,
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
pub(super) struct Writeback {
    shards: Vec<Option<FrozenShard>>,
    copies: usize,
}
pub(super) struct PreparedWrite {
    slot: usize,
    shard: u64,
    object: [u8; 32],
    heads: HeadPair,
    full: Bundle,
    delta: Option<StoreDeltaRequest>,
    recipients: Vec<Recipient>,
    copies: usize,
}

impl Writeback {
    /// Called before proof jobs: the known-holder class comes only from the
    /// current committed placement, never from fetch responses or write errors.
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

    /// Consumes a staged table only after all FHE jobs have passed. Every bounded
    /// delta, full-bundle frame and immutable journal budget passes before Store.
    pub fn prepare(
        &mut self,
        slot: usize,
        table: Table,
        replacements: Option<Vec<PageAddress>>,
    ) -> Result<PreparedWrite> {
        let source = self
            .shards
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or_else(|| protocol("Missing frozen writeback placement"))?;
        let full = Bundle {
            data_head: table.commitment().encode().to_vec(),
            index_head: table.index_commitment().encode().to_vec(),
            data: table.snapshot().encode(),
            index: table.encrypted_index().encode(),
        };
        // INSERT changes geometry, so preflight the complete new full-store wire.
        StoreDeltaPlan::for_heads(table.commitment(), table.index_commitment())
            .map_err(protocol)?;
        let delta = if source
            .recipients
            .iter()
            .any(|peer| peer.transport == Transport::Delta)
        {
            let addresses =
                replacements.ok_or_else(|| protocol("Missing proved UPDATE page addresses"))?;
            if addresses.is_empty() || addresses.len() > peer_runtime::MAX_STORE_DELTA_PAGES {
                return Err(protocol("UPDATE page replacement budget exceeded"));
            }
            let pages = addresses
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
                .collect::<Result<Vec<_>>>()?;
            Some(
                StoreDeltaRequest::new(source.object, &source.data, &source.index, &full, &pages)
                    .map_err(protocol)?,
            )
        } else {
            None
        };
        let object = delta
            .as_ref()
            .map_or_else(|| full.id(), |request| *request.object());
        Ok(PreparedWrite {
            slot,
            shard: source.shard,
            object,
            heads: HeadPair {
                data: table.commitment().encode(),
                index: table.index_commitment().encode(),
            },
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
                Transport::Full => Request::Store(self.full.clone()),
                Transport::Delta => Request::StoreDelta(
                    self.delta
                        .as_ref()
                        .ok_or_else(|| protocol("Missing preflighted UPDATE delta"))?
                        .clone(),
                ),
            };
            // A failed known-holder delta never changes this recipient to Full.
            // New replicas already have their Full class in the frozen list.
            if matches!(recipient.peer.remote.call(request), Ok(Response::Stored(ref info)) if info.id == self.object)
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
            object: self.object,
            heads: self.heads,
            holders,
        })
    }
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
