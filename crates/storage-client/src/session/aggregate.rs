//! Genuine encrypted partial aggregates followed by checked client-side completion.
use super::*;
use crate::query_rpc::{ProofJob, Requests};

impl Session {
    pub(super) fn execute_aggregate(
        &mut self,
        initial: HeadRef,
        predicate: sql_plan::Predicate,
        projection: AggregateProjection,
    ) -> Result<VerifiedResult> {
        let mut count = 0u64;
        let mut sum = 0u64;
        let requests = Requests::default();
        let answers = crate::jobs::run(0..self.data.shards.len(), |slot| {
            let shard = &self.data.shards[slot];
            let (remote, table) = self.fetch_online(shard)?;
            let prepared = self.data.owner.prepare_provable_aggregate(
                &table,
                predicate.age_range().map(|range| AgeRange {
                    lower: range.lower,
                    upper: range.upper,
                }),
                backend::POLYNOMIAL_AGGREGATE_CAPACITY,
                Limits::default(),
            )?;
            let (reply, checked) = requests.request(
                &remote,
                &shard.peers,
                ProofJob {
                    object: shard.info.object,
                    setup: self.data.setup_id,
                    operation: Operation::Aggregate,
                    ciphertext: prepared.request(),
                },
                |reply| {
                    self.data
                        .owner
                        .check_aggregate_proof(&table, &prepared, &reply.output, &reply.proof)
                        .map_err(Error::from)
                },
            )?;
            self.data
                .owner
                .complete_checked_aggregate(&table, prepared, &reply.output, checked)
                .map_err(Error::from)
        })?;
        for answer in answers {
            count = count
                .checked_add(u64::from(answer.count()))
                .ok_or_else(|| protocol("Aggregate count overflow"))?;
            sum = sum
                .checked_add(u64::from(answer.sum().unwrap_or(0)))
                .ok_or_else(|| protocol("Aggregate sum overflow"))?;
        }
        let version = self.finish_read(initial)?;
        Ok(VerifiedResult::Aggregated {
            projection,
            count,
            sum: (count != 0).then_some(sum),
            version,
        })
    }
}
