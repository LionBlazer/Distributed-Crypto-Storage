use super::source::IndexPrefix;
use super::*;
use crate::query_rpc::{ProofJob, Requests};
use compact_query::ReadView;
use sql_plan::{Predicate, Projection, RowWindow};

struct CheckedShard {
    slot: usize,
    prepared: backend::PreparedSelect,
    output: Vec<u8>,
    checked: bfv_query_proof::CheckedOperation,
}
impl Session {
    pub(super) fn execute_select(
        &mut self,
        initial: HeadRef,
        predicate: Predicate,
        projection: Projection,
        window: RowWindow,
        requests: &Requests,
    ) -> Result<VerifiedResult> {
        let prefix_limit = window.prefix_limit()?;
        // K = OFFSET + LIMIT: a row beyond a shard's first K matches has K earlier global
        // matches in that shard. Its omission cannot change the global first K.
        // Every shard still validates its complete source and supplies a real proof.
        let completed = crate::jobs::run(0..self.data.shards.len(), |slot| {
            self.select_shard(slot, predicate, projection, prefix_limit, requests)
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
        let rows = selected
            .into_iter()
            .skip(window.offset)
            .take(window.limit.unwrap_or(usize::MAX))
            .map(|(_, row)| row)
            .collect();
        Ok(VerifiedResult::Selected {
            columns: projection.columns(),
            rows,
            version,
        })
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
            let predicate = compact_query::AgeSet256::from_bytes(predicate.age_mask());
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
