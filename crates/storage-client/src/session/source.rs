//! Shared static source retrieval; no predicate-dependent page selection.
use super::*;
use crate::query_rpc::Requests;
use compact_query::{PageSource, ReadHeads};

pub(super) struct IndexPrefix<'a>(pub &'a peer_runtime::ReadImage);
impl PageSource for IndexPrefix<'_> {
    fn commitment(&self) -> &Commitment {
        self.0.index_head()
    }
    fn lookup(
        &self,
        page: u64,
        limits: Limits,
    ) -> compact_query::Result<compact_store::VerifiedPage> {
        self.0
            .index_page(page, limits)
            .map_err(|error| compact_query::Error::Codec(error.to_string()))
    }
}
impl Session {
    pub(super) fn read_heads(&self, slot: usize) -> Result<ReadHeads> {
        let shard = &self.data.shards[slot];
        Ok(ReadHeads::new(
            self.data.table_id,
            &shard.info.data_head,
            &shard.info.index_head,
            Limits::default(),
        )?)
    }
    pub(super) fn fetch_read_image(
        &self,
        slot: usize,
        heads: &ReadHeads,
        requests: &Requests,
    ) -> Result<(RemotePeer, peer_runtime::ReadImage)> {
        let shard = &self.data.shards[slot];
        let required = heads.read_requirements()?;
        let request = peer_runtime::ReadImageRequest::new(
            shard.info.object,
            heads.data(),
            heads.index(),
            required.index_prefix_pages,
        )
        .map_err(protocol)?;
        for peer in &shard.peers {
            if self.unavailable_this_operation.contains(&peer.id) {
                continue;
            }
            let response = requests.call(&peer.remote, Some(shard.info.object), || {
                Request::FetchReadImage(request.clone())
            });
            match response {
                Ok(Response::ReadImage(image)) if image.verify(&request).is_ok() => {
                    return Ok((peer.remote.clone(), image));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    return Err(Error::Transport(error));
                }
                _ => {}
            }
        }
        Err(Error::UnavailableShard(shard.info.id))
    }
}
