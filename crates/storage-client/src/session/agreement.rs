use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl Session {
    pub(super) fn synchronize(&mut self) -> Result<HeadRef> {
        self.synchronize_using(None)
    }
    pub(super) fn synchronize_using(
        &mut self,
        requests: Option<&crate::query_rpc::Requests>,
    ) -> Result<HeadRef> {
        self.persist_pending()?;
        let network = self.journal.genesis_id();
        let mut reached = false;
        for participant in &self.participants {
            if self.unavailable_this_operation.contains(&participant.id) {
                continue;
            }
            for _ in 0..=self.journal.profile().max_headers {
                let mut known = vec![network];
                known.extend(
                    self.journal
                        .validated_blocks()
                        .into_iter()
                        .map(|(h, _)| h.id()),
                );
                let request = || Request::JournalBlocks {
                    network,
                    known: known.clone(),
                };
                let response = match requests {
                    Some(requests) => requests.call(&participant.remote, None, request),
                    None => call_bounded(&participant.remote, request),
                };
                if requests.is_some()
                    && let Err(error) = &response
                    && error.kind() == io::ErrorKind::Interrupted
                {
                    return Err(Error::Transport(response.err().unwrap()));
                }
                let Ok(Response::JournalBlocks(blocks)) = response else {
                    self.unavailable_this_operation.insert(participant.id);
                    break;
                };
                if blocks.is_empty() {
                    reached = true;
                    break;
                }
                if blocks.len() != 1 {
                    break;
                }
                let block = &blocks[0];
                let Ok(header) = Header::decode(&block.header) else {
                    break;
                };
                if self.journal.body(header.id()).is_some() {
                    break;
                }
                if self
                    .journal
                    .import_block(header, &block.body, now(), &self.verifier)
                    .is_err()
                {
                    break;
                }
            }
        }
        if !reached {
            return Err(protocol(
                "No reachable journal synchronizer; freshness unavailable",
            ));
        }
        let head = self
            .journal
            .resolve(Freshness::AtLeast(self.read_floor))
            .map_err(protocol)?;
        let states = self
            .journal
            .shards(head, Freshness::Exact(head))
            .map_err(protocol)?
            .to_vec();
        let mut staged = Vec::new();
        for state in states {
            let slot = self
                .data
                .shards
                .iter()
                .position(|s| s.info.id == state.id)
                .ok_or_else(|| protocol("Unknown agreed shard"))?;
            let shard = &self.data.shards[slot];
            if heads(&shard.info) == state.heads {
                continue;
            }
            let data_head =
                Commitment::decode(&state.heads.data, Limits::default()).map_err(protocol)?;
            let index_head =
                compact_query::decode_index_head(&state.heads.index, data_head.layout().row_count)
                    .map_err(protocol)?;
            let mut fetched = None;
            for peer in &self.participants {
                if self.unavailable_this_operation.contains(&peer.id) {
                    continue;
                }
                let request = || Request::FetchVersion {
                    data_head: state.heads.data.to_vec(),
                    index_head: state.heads.index.to_vec(),
                };
                let response = match requests {
                    Some(requests) => requests.call(&peer.remote, None, request),
                    None => peer.remote.call(request()),
                };
                if requests.is_some()
                    && let Err(error) = &response
                    && error.kind() == io::ErrorKind::Interrupted
                {
                    return Err(Error::Transport(response.err().unwrap()));
                }
                if let Ok(Response::RawBundle(bundle)) = response
                    && let Ok(object) = restore_agreed_object(
                        &self.data.owner,
                        &self.data.table_id,
                        &data_head,
                        &index_head,
                        bundle,
                    )
                {
                    fetched = Some((object, peer.clone()));
                    break;
                }
            }
            let (object, peer) = fetched.ok_or(Error::UnavailableShard(state.id))?;
            staged.push((
                slot,
                Shard {
                    info: ShardInfo {
                        id: state.id,
                        object,
                        holders: vec![peer.id],
                        rows: data_head.layout().row_count as usize,
                        data_head,
                        index_head,
                    },
                    peers: vec![peer],
                },
            ));
        }
        // All ciphertexts authenticate before any snapshot metadata becomes visible.
        for (slot, shard) in staged {
            self.data.shards[slot] = shard;
        }
        self.read_floor = head;
        Ok(head)
    }
    pub(super) fn mine_body(&mut self, body: Body) -> Result<HeadRef> {
        self.persist_pending()?;
        let network = self.journal.genesis_id();
        let parent = self.journal.best_validated().block;
        let mut times = Vec::new();
        let mut cursor = parent;
        for _ in 0..11 {
            if let Some(header) = self.journal.header(cursor) {
                times.push(header.timestamp);
                cursor = header.parent;
            } else {
                times.push(self.journal.genesis().timestamp);
                break;
            }
        }
        times.sort_unstable();
        let timestamp = now().max(times[times.len() / 2].saturating_add(1));
        let bytes = body.encode(self.journal.profile()).map_err(protocol)?;
        let mut mined = None;
        for participant in &self.participants {
            if self.unavailable_this_operation.contains(&participant.id) {
                continue;
            }
            match call_bounded(&participant.remote, || Request::MineBlock {
                network,
                parent,
                body: bytes.clone(),
                timestamp,
                attempts: 1_000_000,
            }) {
                Ok(Response::Mined(block)) => {
                    mined = Some(block);
                    break;
                }
                _ => continue,
            }
        }
        let block = mined.ok_or_else(|| {
            protocol("No peer produced a valid block within the bounded work attempt budget")
        })?;
        let header = Header::decode(&block.header).map_err(protocol)?;
        if header.parent != parent || block.body != bytes {
            return Err(protocol("Miner changed the requested transition"));
        }
        let submitted = HeadRef {
            genesis: self.journal.genesis_id(),
            database: self.journal.genesis().database,
            block: header.id(),
            height: header.height,
            state_root: header.state_root,
        };
        self.journal
            .import_block(header, &bytes, now(), &self.verifier)
            .map_err(protocol)?;
        if let Body::Transition(transition) = &body
            && let Some(pending) = self.pending_mutation.as_mut()
            && pending.transition == *transition
            && pending.submitted.is_none()
        {
            // Capture the exact original block before a lost/failed publication
            // ACK can return control to the caller. Retry must not remine SQL.
            pending.submitted = Some(submitted);
        }
        self.pending_publication = Some(block);
        self.persist_pending()?;
        Ok(submitted)
    }
    fn persist_pending(&mut self) -> Result<()> {
        let Some(block) = self.pending_publication.as_ref() else {
            return Ok(());
        };
        let network = self.journal.genesis_id();
        let id = Header::decode(&block.header).map_err(protocol)?.id();
        let mut persisted = false;
        for participant in &self.participants {
            if self.unavailable_this_operation.contains(&participant.id) {
                continue;
            }
            // Publication is idempotent by the exact block hash. Connectivity is
            // not counted as votes or proof; the client validates all work itself.
            if matches!(call_bounded(&participant.remote, || Request::PublishBlock { network, header: block.header.clone(), body: block.body.clone() }), Ok(Response::JournalAccepted(accepted)) if accepted == id)
            {
                persisted = true;
            }
        }
        if !persisted {
            return Err(protocol(
                "No peer durably acknowledged the mined block; publication remains unconfirmed",
            ));
        }
        self.pending_publication = None;
        Ok(())
    }
    pub(super) fn finish_read(&mut self, expected: HeadRef) -> Result<HeadRef> {
        self.finish_read_using(expected, None)
    }
    pub(super) fn finish_read_using(
        &mut self,
        expected: HeadRef,
        requests: Option<&crate::query_rpc::Requests>,
    ) -> Result<HeadRef> {
        let current = self.synchronize_using(requests)?;
        self.journal
            .resolve(Freshness::Exact(expected))
            .map_err(protocol)?;
        if current.state_root != expected.state_root {
            return Err(protocol(
                "Confirmed state changed during query; retry against the new version",
            ));
        }
        Ok(current)
    }
}

// A malformed envelope is one holder's failure, not permission to stop before
// trying a healthy replica. Return no raw bytes beyond complete owner image validation.
fn restore_agreed_object(
    owner: &backend::Owner,
    table: &compact_query::TableId,
    data: &Commitment,
    index: &Commitment,
    raw: RawBundle,
) -> Result<[u8; 32]> {
    let version = raw.target_version().map_err(protocol)?;
    if version.data_head() != data || version.index_head() != index {
        return Err(protocol("A holder returned different agreed heads"));
    }
    owner.validate_table_images_for_experiment(
        &raw.data,
        &raw.index,
        table,
        data,
        index,
        Limits::default(),
    )?;
    Ok(*version.object())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_version_is_not_a_restored_candidate_even_with_authentic_images() {
        let (owner, _) = backend::Owner::generate([98; 16]).unwrap();
        let table = owner
            .seal(&[PlainRow { age: 18, amount: 7 }], 4, Limits::default())
            .unwrap();
        let raw = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
        let object = *raw.target_version().unwrap().object();
        for mutation in 0..4 {
            let mut bad = raw.clone();
            match mutation {
                0 => bad.version = 1,
                1 => bad.version = 3,
                2 => bad.index_head[56] ^= 1,
                _ => *bad.data.last_mut().unwrap() ^= 1,
            }
            assert!(
                restore_agreed_object(
                    &owner,
                    table.table_id(),
                    table.commitment(),
                    table.index_commitment(),
                    bad,
                )
                .is_err()
            );
        }
        assert_eq!(
            restore_agreed_object(
                &owner,
                table.table_id(),
                table.commitment(),
                table.index_commitment(),
                raw,
            )
            .unwrap(),
            object
        );
    }
}
