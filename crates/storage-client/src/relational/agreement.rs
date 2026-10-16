use super::*;
use peer_runtime::JournalBlock;
use version_journal::{Body, Header};

pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl RelationalSession {
    pub(super) fn initialize_peer(&self, peer: &Participant) -> Result<()> {
        match super::super::session::call_bounded(&peer.remote, || Request::InitJournal {
            genesis: self.journal.genesis().encode().expect("validated genesis"),
            setup: self.setup_id,
        })? {
            Response::JournalReady(id) if id == self.journal.genesis_id() => {}
            _ => return Err(crypto("Wrong typed catalog journal acknowledgement")),
        }
        for (header, body) in self.journal.validated_blocks() {
            match super::super::session::call_bounded(&peer.remote, || Request::PublishBlock {
                network: self.journal.genesis_id(),
                header: header.encode().to_vec(),
                body: body.to_vec(),
            })? {
                Response::JournalAccepted(id) if id == header.id() => {}
                _ => return Err(crypto("Typed catalog block was not acknowledged")),
            }
        }
        Ok(())
    }
    pub(super) fn initialize(&mut self) -> Result<()> {
        for peer in &self.participants {
            self.initialize_peer(peer)?;
        }
        let body = Body::Empty.encode(self.journal.profile()).map_err(crypto)?;
        for height in 0..self.journal.profile().confirmation_depth {
            let parent = self.journal.best_validated().block;
            let timestamp = now().max(self.journal.genesis().timestamp + u64::from(height) + 1);
            let mut mined = None;
            for peer in &self.participants {
                if let Ok(Response::Mined(block)) =
                    super::super::session::call_bounded(&peer.remote, || Request::MineBlock {
                        network: self.journal.genesis_id(),
                        parent,
                        body: body.clone(),
                        timestamp,
                        attempts: 1_000_000,
                    })
                {
                    mined = Some(block);
                    break;
                }
            }
            let JournalBlock {
                header,
                body: received,
            } = mined.ok_or_else(|| crypto("No peer mined the typed catalog confirmation"))?;
            let header = Header::decode(&header).map_err(crypto)?;
            if header.parent != parent || received != body {
                return Err(crypto("Miner changed catalog confirmation"));
            }
            self.journal
                .import_block(header.clone(), &body, now(), &self.verifier)
                .map_err(crypto)?;
            let mut persisted = false;
            for peer in &self.participants {
                if matches!(super::super::session::call_bounded(&peer.remote, || Request::PublishBlock { network: self.journal.genesis_id(), header: header.encode().to_vec(), body: body.clone() }), Ok(Response::JournalAccepted(id)) if id == header.id())
                {
                    persisted = true;
                }
            }
            if !persisted {
                return Err(crypto(
                    "No peer durably acknowledged typed catalog confirmation",
                ));
            }
        }
        self.floor = self.synchronize(&Requests::default())?;
        Ok(())
    }
    pub(super) fn synchronize(&mut self, requests: &Requests) -> Result<HeadRef> {
        let mut reached = false;
        for peer in &self.participants {
            for _ in 0..=self.journal.profile().max_headers {
                let mut known = vec![self.journal.genesis_id()];
                known.extend(
                    self.journal
                        .validated_blocks()
                        .into_iter()
                        .map(|(h, _)| h.id()),
                );
                match requests.call(&peer.remote, None, || Request::JournalBlocks {
                    network: self.journal.genesis_id(),
                    known: known.clone(),
                }) {
                    Ok(Response::JournalBlocks(blocks)) if blocks.is_empty() => {
                        reached = true;
                        break;
                    }
                    Ok(Response::JournalBlocks(blocks)) if blocks.len() == 1 => {
                        let block = &blocks[0];
                        let header = Header::decode(&block.header).map_err(crypto)?;
                        if self.journal.body(header.id()).is_some() {
                            return Err(crypto("Journal synchronizer repeated a known block"));
                        }
                        self.journal
                            .import_block(header, &block.body, now(), &self.verifier)
                            .map_err(crypto)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        return Err(error.into());
                    }
                    _ => break,
                }
            }
        }
        if !reached {
            return Err(crypto(
                "No reachable journal synchronizer; catalog freshness unavailable",
            ));
        }
        let head = self
            .journal
            .resolve(Freshness::AtLeast(self.floor))
            .map_err(crypto)?;
        let states = self
            .journal
            .shards(head, Freshness::Exact(head))
            .map_err(crypto)?;
        let expected: Vec<_> = self
            .relations
            .iter()
            .map(|r| ShardState {
                id: r.shard.id,
                heads: HeadPair {
                    data: r.shard.data_head.encode(),
                    index: r.shard.index_head.encode(),
                },
            })
            .collect();
        if states != expected {
            return Err(crypto(
                "Agreed catalog differs from the imported immutable typed catalog",
            ));
        }
        self.floor = head;
        Ok(head)
    }
}
