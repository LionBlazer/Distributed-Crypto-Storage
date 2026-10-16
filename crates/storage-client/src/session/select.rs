use super::*;
use crate::proof::{ProofJob, ProofRequests};
use sql_plan::{Predicate, Projection};

type ShardRows = Vec<(u64, Vec<u32>)>;

impl Session {
    pub(super) fn execute_select(
        &mut self,
        initial: HeadRef,
        predicate: Predicate,
        projection: Projection,
        limit: Option<usize>,
    ) -> Result<VerifiedResult> {
        let completed = self.read_shards(|slot, requests| {
            self.select_shard(slot, predicate, projection, requests)
        })?;
        let mut selected: Vec<_> = completed.into_iter().flatten().collect();
        let version = self.finish_read(initial)?;
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

    fn select_shard(
        &self,
        slot: usize,
        predicate: Predicate,
        projection: Projection,
        requests: &ProofRequests,
    ) -> Result<ShardRows> {
        let shard = &self.data.shards[slot];
        let (remote, table) = self.fetch_online(shard)?;
        let kind = match projection {
            Projection::Age => backend::RowProjection::Age,
            Projection::Amount => backend::RowProjection::Amount,
            _ => backend::RowProjection::AgeAmount,
        };
        let prepared = self.data.owner.prepare_provable_select(
            &table,
            predicate.age_range().map(|r| AgeRange {
                lower: r.lower,
                upper: r.upper,
            }),
            kind,
            256,
            Limits::default(),
        )?;
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
                    .check_select_proof(&table, &prepared, &reply.output, &reply.proof)
                    .map_err(Error::from)
            },
        )?;
        let answer =
            self.data
                .owner
                .complete_checked_select(&table, prepared, &reply.output, checked)?;
        answer
            .into_rows()
            .into_iter()
            .map(|row| {
                let values = projection
                    .columns()
                    .into_iter()
                    .map(|column| match column {
                        sql_plan::Column::Age => row.age.map(u32::from),
                        sql_plan::Column::Amount => row.amount.map(u32::from),
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| protocol("Proved projection omitted a requested column"))?;
                Ok((
                    row.ordinal * self.data.shards.len() as u64 + slot as u64,
                    values,
                ))
            })
            .collect()
    }
}
