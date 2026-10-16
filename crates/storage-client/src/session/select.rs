use super::*;
use crate::query_rpc::{ProofJob, Requests};
use compact_query::{PageSource, ReadHeads, ReadView};
use sql_plan::{Predicate, Projection};

struct CheckedShard {
    slot: usize,
    prepared: backend::PreparedSelect,
    output: Vec<u8>,
    checked: bfv_query_proof::CheckedOperation,
}
struct IndexPrefix<'a>(&'a peer_runtime::ReadImage);
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
    pub(super) fn execute_select(
        &mut self,
        initial: HeadRef,
        predicate: Predicate,
        projection: Projection,
        limit: Option<usize>,
        requests: &Requests,
    ) -> Result<VerifiedResult> {
        // A row beyond a shard's first K matches already has K earlier global
        // matches in that shard. Its omission cannot change the global first K.
        // Every shard still validates its complete source and supplies a real proof.
        let completed = crate::jobs::run(0..self.data.shards.len(), |slot| {
            self.select_shard(slot, predicate, projection, limit, requests)
        })?;
        // Every genuine proof is checked and every worker joined before freshness.
        // No result ciphertext is decrypted until this exact confirmed state gate.
        let version = self.finish_read_using(initial, Some(requests))?;
        let mut selected = Vec::new();
        for completed in completed {
            let current = self.read_heads(completed.slot)?;
            let answer = self.data.owner.complete_checked_select(
                &current,
                completed.prepared,
                &completed.output,
                completed.checked,
            )?;
            for row in answer.into_rows() {
                let values = projection
                    .columns()
                    .into_iter()
                    .map(|column| match column {
                        sql_plan::Column::Age => row.age.map(u32::from),
                        sql_plan::Column::Amount => row.amount.map(u32::from),
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| protocol("Proved projection omitted a requested column"))?;
                selected.push((
                    row.ordinal * self.data.shards.len() as u64 + completed.slot as u64,
                    values,
                ));
            }
        }
        selected.sort_by_key(|(ordinal, _)| *ordinal);
        let mut rows: Vec<_> = selected.into_iter().map(|(_, row)| row).collect();
        if let Some(limit) = limit {
            rows.truncate(limit);
        }
        Ok(VerifiedResult::Selected {
            columns: projection.columns(),
            rows,
            version,
        })
    }
    fn read_heads(&self, slot: usize) -> Result<ReadHeads> {
        let shard = &self.data.shards[slot];
        Ok(ReadHeads::new(
            self.data.table_id,
            &shard.info.data_head,
            &shard.info.index_head,
            Limits::default(),
        )?)
    }
    fn fetch_read_image(
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
    fn select_shard(
        &self,
        slot: usize,
        predicate: Predicate,
        projection: Projection,
        limit: Option<usize>,
        requests: &Requests,
    ) -> Result<CheckedShard> {
        let shard = &self.data.shards[slot];
        let heads = self.read_heads(slot)?;
        let (remote, image) = self.fetch_read_image(slot, &heads, requests)?;
        let kind = match projection {
            Projection::Age => backend::RowProjection::Age,
            Projection::Amount => backend::RowProjection::Amount,
            _ => backend::RowProjection::AgeAmount,
        };
        let prepared = {
            let index = IndexPrefix(&image);
            let source = ReadView::new(heads.clone(), image.data(), &index)?;
            let predicate = predicate.age_range().map(|range| AgeRange {
                lower: range.lower,
                upper: range.upper,
            });
            match limit {
                Some(limit) => self
                    .data
                    .owner
                    .prepare_provable_select_limited_from_source(
                        &source,
                        predicate,
                        kind,
                        limit,
                        256,
                        Limits::default(),
                    )?,
                None => self.data.owner.prepare_provable_select_from_source(
                    &source,
                    predicate,
                    kind,
                    256,
                    Limits::default(),
                )?,
            }
        };
        // Only exact pending ciphertext/head/ordinal state survives the RPC wait.
        drop(image);
        let (reply, checked) = requests.request(
            &remote,
            &shard.peers,
            ProofJob {
                object: shard.info.object,
                setup: self.data.setup_id,
                operation: Operation::Select,
                ciphertext: prepared.request(),
            },
            |reply| {
                self.data
                    .owner
                    .check_select_proof(&heads, &prepared, &reply.output, &reply.proof)
                    .map_err(Error::from)
            },
        )?;
        Ok(CheckedShard {
            slot,
            prepared,
            output: reply.output,
            checked,
        })
    }
}
