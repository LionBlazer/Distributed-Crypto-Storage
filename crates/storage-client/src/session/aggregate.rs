//! Genuine encrypted partial aggregates followed by checked client-side completion.
use super::source::IndexPrefix;
use super::*;
use crate::query_rpc::{ProofJob, Requests};
use compact_query::ReadView;

struct CheckedShard {
    slot: usize,
    prepared: backend::PreparedProvableAggregate,
    output: Vec<u8>,
    checked: bfv_query_proof::CheckedOperation,
}

impl Session {
    pub(super) fn execute_aggregate(
        &mut self,
        initial: HeadRef,
        predicate: sql_plan::Predicate,
        projection: AggregateProjection,
        requests: &Requests,
    ) -> Result<VerifiedResult> {
        let completed = crate::jobs::run(0..self.data.shards.len(), |slot| {
            let shard = &self.data.shards[slot];
            let heads = self.read_heads(slot)?;
            let (remote, image) = self.fetch_read_image(slot, &heads, requests)?;
            let prepared = {
                let index = IndexPrefix(&image);
                let source = ReadView::new(heads.clone(), image.data(), &index)?;
                self.data.owner.prepare_provable_aggregate_from_source(
                    &source,
                    predicate.age_range().map(|range| AgeRange {
                        lower: range.lower,
                        upper: range.upper,
                    }),
                    backend::POLYNOMIAL_AGGREGATE_CAPACITY,
                    Limits::default(),
                )?
            };
            // Only the exact encrypted pending statement survives the proof wait.
            drop(image);
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
                        .check_aggregate_proof_for_heads(
                            &heads,
                            &prepared,
                            &reply.output,
                            &reply.proof,
                        )
                        .map_err(Error::from)
                },
            )?;
            Ok(CheckedShard {
                slot,
                prepared,
                output: reply.output,
                checked,
            })
        })?;
        // Every worker joins and every proof passes before the fresh agreed-state
        // gate. No partial count or sum is decrypted before this check succeeds.
        let version = self.finish_read_using(initial, Some(requests))?;
        let mut count = 0u64;
        let mut sum = 0u64;
        for completed in completed {
            let answer = self.data.owner.complete_checked_aggregate_for_heads(
                &self.read_heads(completed.slot)?,
                completed.prepared,
                &completed.output,
                completed.checked,
            )?;
            count = count
                .checked_add(u64::from(answer.count()))
                .ok_or_else(|| protocol("Aggregate count overflow"))?;
            sum = sum
                .checked_add(u64::from(answer.sum().unwrap_or(0)))
                .ok_or_else(|| protocol("Aggregate sum overflow"))?;
        }
        Ok(VerifiedResult::Aggregated {
            projection,
            count,
            sum: (count != 0).then_some(sum),
            version,
        })
    }
}
